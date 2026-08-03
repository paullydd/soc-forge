from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable

from soc_forge.investigations.evidence_models import EvidenceCandidate
from soc_forge.investigations.models import (
    EVIDENCE_CLASSIFICATIONS,
    EvidenceReference,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


class InvestigationEvidenceError(Exception):
    pass


class InvalidEvidenceCandidateError(InvestigationEvidenceError):
    pass


class EvidenceOutsideScopeError(InvestigationEvidenceError):
    pass


class EvidenceProvenanceMismatchError(InvestigationEvidenceError):
    pass


class DuplicateEvidenceSelectionError(InvestigationEvidenceError):
    pass


class EvidenceSelectionNotFoundError(InvestigationEvidenceError):
    pass


class InvalidEvidenceClassificationError(InvestigationEvidenceError):
    pass


class InvalidEvidenceRationaleError(InvestigationEvidenceError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationEvidenceService:
    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
    ):
        self.workspace_service = workspace_service
        self.clock = clock

    def select_evidence(
        self,
        investigation_id: str,
        candidate: EvidenceCandidate,
        *,
        classification: str,
        rationale: str,
        author: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self.workspace_service.get_investigation(investigation_id)
        self._require_revision(current, expected_revision)
        self._validate_candidate(current, candidate)
        if any(
            item.reference_id == candidate.evidence_id
            and item.origin == "analyst_selection"
            for item in current.investigation.evidence_references
        ):
            raise DuplicateEvidenceSelectionError(
                f"Evidence {candidate.evidence_id!r} is already selected in "
                f"{investigation_id!r}"
            )

        timestamp = self._required_text(self.clock(), "selection timestamp")
        reference = EvidenceReference(
            reference_id=candidate.evidence_id,
            source_type=self._source_type(candidate.evidence_type),
            source_id=candidate.source_id,
            artifact_key=self._artifact_key(candidate.evidence_type),
            case_id=candidate.case_ids[0] if len(candidate.case_ids) == 1 else None,
            timestamp=candidate.timestamp,
            label=candidate.title,
            origin="analyst_selection",
            classification=self._classification(classification),
            rationale=self._rationale(rationale),
            selected_by=self._required_text(author, "author"),
            selected_at=timestamp,
            selection_updated_at=timestamp,
            source_analysis_id=candidate.source_analysis_id,
            evidence_type=candidate.evidence_type,
            scope_case_ids=candidate.case_ids,
            provenance_fields=tuple(
                sorted({item.field_name for item in candidate.field_provenance})
            ),
        )
        references = self._ordered(
            current.investigation.evidence_references + (reference,)
        )
        return self.workspace_service.replace_evidence_references(
            investigation_id,
            references,
            expected_revision=expected_revision,
        )

    def update_evidence_rationale(
        self,
        investigation_id: str,
        evidence_id: str,
        *,
        classification: str | None = None,
        rationale: str | None = None,
        author: str | None = None,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self.workspace_service.get_investigation(investigation_id)
        self._require_revision(current, expected_revision)
        index = self._selection_index(current.investigation.evidence_references, evidence_id)
        existing = current.investigation.evidence_references[index]
        if classification is None and rationale is None and author is None:
            raise InvalidEvidenceRationaleError(
                "At least one evidence selection field must be updated"
            )
        timestamp = self._required_text(self.clock(), "selection update timestamp")
        updated_classification = (
            self._classification(classification)
            if classification is not None
            else existing.classification
        )
        self._validate_hypothesis_classification(
            current, evidence_id, updated_classification)
        updated_reference = replace(
            existing,
            classification=updated_classification,
            rationale=(
                self._rationale(rationale)
                if rationale is not None
                else existing.rationale
            ),
            selected_by=(
                self._required_text(author, "author")
                if author is not None
                else existing.selected_by
            ),
            selection_updated_at=timestamp,
        )
        references = list(current.investigation.evidence_references)
        references[index] = updated_reference
        return self.workspace_service.replace_evidence_references(
            investigation_id,
            self._ordered(tuple(references)),
            expected_revision=expected_revision,
        )

    def remove_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self.workspace_service.get_investigation(investigation_id)
        self._require_revision(current, expected_revision)
        index = self._selection_index(current.investigation.evidence_references, evidence_id)
        references = list(current.investigation.evidence_references)
        del references[index]
        return self.workspace_service.replace_evidence_references(
            investigation_id,
            self._ordered(tuple(references)),
            expected_revision=expected_revision,
        )

    def _validate_candidate(self, current: WorkspaceResult, candidate: EvidenceCandidate) -> None:
        if not isinstance(candidate, EvidenceCandidate):
            raise InvalidEvidenceCandidateError(
                "Evidence selection requires one validated EvidenceCandidate"
            )
        if not candidate.selectable:
            raise InvalidEvidenceCandidateError(
                f"Evidence candidate {candidate.evidence_id!r} is not selectable"
            )
        investigation = current.investigation
        if candidate.source_analysis_id != investigation.analysis_id:
            raise EvidenceProvenanceMismatchError(
                f"Evidence {candidate.evidence_id!r} belongs to analysis "
                f"{candidate.source_analysis_id!r}, not {investigation.analysis_id!r}"
            )
        scope_case_ids = {
            item.source_id
            for item in investigation.evidence_references
            if item.origin == "scope" and item.source_type == "case"
        }
        if not scope_case_ids.intersection(candidate.case_ids):
            raise EvidenceOutsideScopeError(
                f"Evidence {candidate.evidence_id!r} is outside investigation "
                f"{investigation.investigation_id!r} case scope"
            )

    @staticmethod
    def _require_revision(current: WorkspaceResult, expected_revision: int) -> None:
        if current.revision != expected_revision:
            from soc_forge.investigations.repository import InvestigationConflictError

            raise InvestigationConflictError(
                f"Investigation {current.investigation.investigation_id!r} is at "
                f"revision {current.revision}, not expected revision {expected_revision}"
            )

    @staticmethod
    def _selection_index(
        references: tuple[EvidenceReference, ...],
        evidence_id: str,
    ) -> int:
        for index, reference in enumerate(references):
            if (
                reference.reference_id == evidence_id
                and reference.origin == "analyst_selection"
            ):
                return index
        raise EvidenceSelectionNotFoundError(
            f"Selected evidence {evidence_id!r} was not found"
        )

    @staticmethod
    def _ordered(
        references: tuple[EvidenceReference, ...],
    ) -> tuple[EvidenceReference, ...]:
        return tuple(
            sorted(
                references,
                key=lambda item: (
                    item.origin != "scope",
                    item.reference_id,
                ),
            )
        )


    @staticmethod
    def _validate_hypothesis_classification(
        current: WorkspaceResult,
        evidence_id: str,
        classification: str,
    ) -> None:
        for hypothesis in current.investigation.hypotheses:
            if (
                evidence_id in hypothesis.supporting_evidence_reference_ids
                and classification != "supporting"
            ):
                raise InvalidEvidenceClassificationError(
                    f"Evidence {evidence_id!r} supports hypothesis "
                    f"{hypothesis.hypothesis_id!r} and must remain supporting"
                )
            if (
                evidence_id in hypothesis.contradicting_evidence_reference_ids
                and classification != "contradicting"
            ):
                raise InvalidEvidenceClassificationError(
                    f"Evidence {evidence_id!r} contradicts hypothesis "
                    f"{hypothesis.hypothesis_id!r} and must remain contradicting"
                )
    @staticmethod
    def _classification(value: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in EVIDENCE_CLASSIFICATIONS:
            raise InvalidEvidenceClassificationError(
                "Evidence classification must be one of: "
                + ", ".join(sorted(EVIDENCE_CLASSIFICATIONS))
            )
        return normalized

    @classmethod
    def _rationale(cls, value: str) -> str:
        try:
            return cls._required_text(value, "rationale")
        except InvalidEvidenceCandidateError as exc:
            raise InvalidEvidenceRationaleError(str(exc)) from exc

    @staticmethod
    def _required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidEvidenceCandidateError(
                f"{field_name} must be a non-empty string"
            )
        return value.strip()

    @staticmethod
    def _source_type(evidence_type: str) -> str:
        return (
            "reconstruction"
            if evidence_type == "reconstruction_step"
            else evidence_type
        )

    @staticmethod
    def _artifact_key(evidence_type: str) -> str:
        return {
            "event": "events",
            "alert": "alerts",
            "case": "cases",
            "reconstruction_step": "reconstructions",
        }[evidence_type]
