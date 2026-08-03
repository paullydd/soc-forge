from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Iterable, List

from soc_forge.investigations.models import (
    AnalysisProvenance,
    Annotation,
    Decision,
    EvidenceReference,
    Hypothesis,
    INTERNAL_ANNOTATION_TARGET_TYPES,
    Investigation,
    WorkspaceMetadata,
)
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepository,
    InvestigationSummary,
)


WORKSPACE_STATUSES = frozenset({"open", "in_progress", "escalated", "closed"})
STATUS_TRANSITIONS = {
    "open": frozenset({"in_progress", "closed"}),
    "in_progress": frozenset({"escalated", "closed"}),
    "escalated": frozenset({"in_progress", "closed"}),
    "closed": frozenset(),
}


class InvestigationWorkspaceError(Exception):
    """Base error for investigation workflow operations."""


class InvalidWorkspaceOperationError(InvestigationWorkspaceError):
    pass


class InvalidStatusTransitionError(InvalidWorkspaceOperationError):
    pass


class InvalidOwnerError(InvalidWorkspaceOperationError):
    pass


class DuplicateAnnotationError(InvalidWorkspaceOperationError):
    pass


class AnnotationNotFoundError(InvalidWorkspaceOperationError):
    pass


class DuplicateDecisionError(InvalidWorkspaceOperationError):
    pass


class InvalidWorkspaceReferenceError(InvalidWorkspaceOperationError):
    pass


@dataclass(frozen=True)
class WorkspaceResult:
    investigation: Investigation
    revision: int


@dataclass(frozen=True)
class WorkspaceDeletionResult:
    investigation_id: str
    deleted_revision: int


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationWorkspaceService:
    def __init__(
        self,
        repository: InvestigationRepository,
        *,
        clock: Callable[[], str] = _utc_now,
    ):
        self.repository = repository
        self.clock = clock

    def create_investigation(
        self,
        *,
        investigation_id: str,
        title: str,
        analysis_id: str,
        provenance: AnalysisProvenance | None = None,
        case_ids: Iterable[str] = (),
        artifact_keys: Iterable[str] = (),
        owner: str | None = None,
        initial_status: str = "open",
        created_at: str | None = None,
    ) -> WorkspaceResult:
        timestamp = (
            self._required_text(created_at, "created_at")
            if created_at is not None
            else self._now()
        )
        normalized_title = self._required_text(title, "title")
        normalized_status = self._validate_status(initial_status)
        normalized_owner = self._normalize_owner(owner)
        normalized_case_ids = self._unique_ids(case_ids, "case_ids")
        normalized_artifact_keys = self._unique_ids(artifact_keys, "artifact_keys")
        evidence_references = tuple(
            EvidenceReference(
                reference_id=f"case:{case_id}",
                source_type="case",
                source_id=case_id,
                artifact_key="cases",
                case_id=case_id,
                label=f"Referenced case {case_id}",
            )
            for case_id in normalized_case_ids
        )
        investigation = Investigation(
            investigation_id=investigation_id,
            analysis_id=analysis_id,
            metadata=WorkspaceMetadata(
                title=normalized_title,
                created_at=timestamp,
                updated_at=timestamp,
                owner=normalized_owner,
                status=normalized_status,
            ),
            analysis_artifact_keys=normalized_artifact_keys,
            evidence_references=evidence_references,
            provenance=provenance,
        )
        revision = self.repository.save(investigation)
        return WorkspaceResult(investigation=investigation, revision=revision)

    def get_investigation(self, investigation_id: str) -> WorkspaceResult:
        stored = self.repository.load_record(investigation_id)
        return WorkspaceResult(
            investigation=stored.investigation,
            revision=stored.revision,
        )

    def list_investigations(self) -> List[InvestigationSummary]:
        return self.repository.list_investigations()

    def replace_evidence_references(
        self,
        investigation_id: str,
        evidence_references: Iterable[EvidenceReference],
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        normalized = tuple(evidence_references)
        if any(not isinstance(item, EvidenceReference) for item in normalized):
            raise InvalidWorkspaceOperationError(
                "evidence_references must contain EvidenceReference objects"
            )
        if normalized == current.investigation.evidence_references:
            return current
        timestamp = self._now()
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=timestamp,
            ),
            evidence_references=normalized,
        )
        return self._save(updated, expected_revision)

    def replace_reasoning(
        self,
        investigation_id: str,
        hypotheses: Iterable[Hypothesis],
        decisions: Iterable[Decision],
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        normalized_hypotheses = tuple(hypotheses)
        normalized_decisions = tuple(decisions)
        if any(not isinstance(item, Hypothesis) for item in normalized_hypotheses):
            raise InvalidWorkspaceOperationError(
                "hypotheses must contain Hypothesis objects"
            )
        if any(not isinstance(item, Decision) for item in normalized_decisions):
            raise InvalidWorkspaceOperationError(
                "decisions must contain Decision objects"
            )
        if (
            normalized_hypotheses == current.investigation.hypotheses
            and normalized_decisions == current.investigation.decisions
        ):
            return current
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=self._now(),
            ),
            hypotheses=normalized_hypotheses,
            decisions=normalized_decisions,
        )
        return self._save(updated, expected_revision)

    def available_status_transitions(self, status: str) -> tuple[str, ...]:
        normalized_status = self._validate_status(status)
        return tuple(sorted(STATUS_TRANSITIONS[normalized_status]))

    def assign_owner(
        self,
        investigation_id: str,
        owner: str | None,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        normalized_owner = self._normalize_owner(owner)
        if current.investigation.metadata.owner == normalized_owner:
            return current
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                owner=normalized_owner,
                updated_at=self._now(),
            ),
        )
        return self._save(updated, expected_revision)

    def change_status(
        self,
        investigation_id: str,
        status: str,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        normalized_status = self._validate_status(status)
        current_status = self._validate_status(current.investigation.metadata.status)
        if normalized_status == current_status:
            return current
        if normalized_status not in STATUS_TRANSITIONS[current_status]:
            raise InvalidStatusTransitionError(
                f"Investigation {investigation_id!r} cannot transition "
                f"from {current_status!r} to {normalized_status!r}"
            )
        return self._replace_status(current, normalized_status)

    def reopen_investigation(
        self,
        investigation_id: str,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        if current.investigation.metadata.status != "closed":
            raise InvalidStatusTransitionError(
                f"Investigation {investigation_id!r} must be closed before reopening"
            )
        return self._replace_status(current, "in_progress")

    def add_annotation(
        self,
        investigation_id: str,
        *,
        annotation_id: str,
        body: str,
        author: str,
        expected_revision: int,
        target_type: str = "investigation",
        target_id: str | None = None,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        if any(
            annotation.annotation_id == annotation_id
            for annotation in current.investigation.annotations
        ):
            raise DuplicateAnnotationError(
                f"Annotation {annotation_id!r} already exists in {investigation_id!r}"
            )
        timestamp = self._now()
        annotation = Annotation(
            annotation_id=annotation_id,
            target_type=target_type,
            target_id=target_id or investigation_id,
            body=self._required_text(body, "annotation body"),
            created_at=timestamp,
            updated_at=timestamp,
            created_by=self._required_text(author, "annotation author"),
        )
        self._validate_annotation_target(
            current.investigation,
            annotation.target_type,
            annotation.target_id,
            annotation.annotation_id,
        )
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=timestamp,
            ),
            annotations=current.investigation.annotations + (annotation,),
        )
        return self._save(updated, expected_revision)

    def update_annotation(
        self,
        investigation_id: str,
        annotation_id: str,
        body: str,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        index = self._annotation_index(current.investigation, annotation_id)
        timestamp = self._now()
        annotations = list(current.investigation.annotations)
        annotations[index] = replace(
            annotations[index],
            body=self._required_text(body, "annotation body"),
            updated_at=timestamp,
        )
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=timestamp,
            ),
            annotations=tuple(annotations),
        )
        return self._save(updated, expected_revision)

    def remove_annotation(
        self,
        investigation_id: str,
        annotation_id: str,
        *,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        index = self._annotation_index(current.investigation, annotation_id)
        timestamp = self._now()
        annotations = list(current.investigation.annotations)
        del annotations[index]
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=timestamp,
            ),
            annotations=tuple(annotations),
        )
        return self._save(updated, expected_revision)

    def record_decision(
        self,
        investigation_id: str,
        *,
        decision_id: str,
        decision_type: str,
        outcome: str,
        rationale: str,
        author: str,
        expected_revision: int,
        evidence_reference_ids: Iterable[str] = (),
        hypothesis_ids: Iterable[str] = (),
    ) -> WorkspaceResult:
        current = self._load_for_update(investigation_id, expected_revision)
        if any(
            decision.decision_id == decision_id
            for decision in current.investigation.decisions
        ):
            raise DuplicateDecisionError(
                f"Decision {decision_id!r} already exists in {investigation_id!r}"
            )
        timestamp = self._now()
        decision = Decision(
            decision_id=decision_id,
            decision_type=self._required_text(decision_type, "decision type"),
            outcome=self._required_text(outcome, "decision outcome"),
            rationale=self._required_text(rationale, "decision rationale"),
            evidence_reference_ids=self._unique_ids(
                evidence_reference_ids,
                "evidence_reference_ids",
            ),
            hypothesis_ids=self._unique_ids(hypothesis_ids, "hypothesis_ids"),
            decided_at=timestamp,
            decided_by=self._required_text(author, "decision author"),
        )
        self._require_known_ids(
            current.investigation,
            "decision", decision.decision_id, "evidence",
            decision.evidence_reference_ids,
            {item.reference_id for item in current.investigation.evidence_references},
        )
        self._require_known_ids(
            current.investigation,
            "decision", decision.decision_id, "hypothesis",
            decision.hypothesis_ids,
            {item.hypothesis_id for item in current.investigation.hypotheses},
        )
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                updated_at=timestamp,
            ),
            decisions=current.investigation.decisions + (decision,),
        )
        return self._save(updated, expected_revision)

    def delete_investigation(
        self,
        investigation_id: str,
        *,
        expected_revision: int,
    ) -> WorkspaceDeletionResult:
        current = self._load_for_update(investigation_id, expected_revision)
        self.repository.delete(
            investigation_id,
            expected_revision=current.revision,
        )
        return WorkspaceDeletionResult(
            investigation_id=investigation_id,
            deleted_revision=current.revision,
        )

    def _replace_status(
        self,
        current: WorkspaceResult,
        status: str,
    ) -> WorkspaceResult:
        updated = replace(
            current.investigation,
            metadata=replace(
                current.investigation.metadata,
                status=status,
                updated_at=self._now(),
            ),
        )
        return self._save(updated, current.revision)

    def _load_for_update(
        self,
        investigation_id: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise InvalidWorkspaceOperationError(
                "expected_revision must be a positive integer"
            )
        current = self.get_investigation(investigation_id)
        if expected_revision < 1 or current.revision != expected_revision:
            raise InvestigationConflictError(
                f"Investigation {investigation_id!r} is at revision "
                f"{current.revision}, not expected revision {expected_revision}"
            )
        return current

    def _save(
        self,
        investigation: Investigation,
        expected_revision: int,
    ) -> WorkspaceResult:
        revision = self.repository.save(
            investigation,
            expected_revision=expected_revision,
        )
        return WorkspaceResult(investigation=investigation, revision=revision)


    @classmethod
    def _validate_annotation_target(
        cls,
        investigation: Investigation,
        target_type: str,
        target_id: str,
        annotation_id: str,
    ) -> None:
        if target_type not in INTERNAL_ANNOTATION_TARGET_TYPES:
            return
        known_by_type = {
            "investigation": {investigation.investigation_id},
            "evidence": {item.reference_id for item in investigation.evidence_references},
            "hypothesis": {item.hypothesis_id for item in investigation.hypotheses},
            "decision": {item.decision_id for item in investigation.decisions},
            "timeline_selection": {
                item.selection_id for item in investigation.timeline_selections
            },
        }
        if target_id not in known_by_type[target_type]:
            raise InvalidWorkspaceReferenceError(
                f"Investigation {investigation.investigation_id!r} annotation "
                f"{annotation_id!r} targets missing {target_type} {target_id!r}"
            )

    @staticmethod
    def _require_known_ids(
        investigation: Investigation,
        child_type: str,
        child_id: str,
        relationship: str,
        references: tuple[str, ...],
        known_ids: set[str],
    ) -> None:
        missing = sorted(set(references).difference(known_ids))
        if missing:
            raise InvalidWorkspaceReferenceError(
                f"Investigation {investigation.investigation_id!r} {child_type} "
                f"{child_id!r} references missing {relationship} ID {missing[0]!r}"
            )

    @staticmethod
    def _annotation_index(investigation: Investigation, annotation_id: str) -> int:
        for index, annotation in enumerate(investigation.annotations):
            if annotation.annotation_id == annotation_id:
                return index
        raise AnnotationNotFoundError(
            f"Annotation {annotation_id!r} was not found in "
            f"{investigation.investigation_id!r}"
        )

    @staticmethod
    def _validate_status(status: str) -> str:
        normalized = status.strip().lower() if isinstance(status, str) else ""
        if normalized not in WORKSPACE_STATUSES:
            raise InvalidStatusTransitionError(
                f"Status must be one of: {', '.join(sorted(WORKSPACE_STATUSES))}"
            )
        return normalized

    @staticmethod
    def _normalize_owner(owner: str | None) -> str | None:
        if owner is None:
            return None
        if not isinstance(owner, str) or not owner.strip():
            raise InvalidOwnerError(
                "Owner must be a non-empty local analyst label or None"
            )
        return owner.strip()

    @staticmethod
    def _required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidWorkspaceOperationError(
                f"{field_name} must be a non-empty string"
            )
        return value.strip()

    @classmethod
    def _unique_ids(cls, values: Iterable[str], field_name: str) -> tuple[str, ...]:
        if isinstance(values, (str, bytes)):
            raise InvalidWorkspaceOperationError(
                f"{field_name} must be an iterable of identifiers, not a string"
            )
        normalized = []
        seen = set()
        for value in values:
            item = cls._required_text(value, f"{field_name} item")
            if item not in seen:
                seen.add(item)
                normalized.append(item)
        return tuple(normalized)

    def _now(self) -> str:
        return self._required_text(self.clock(), "clock timestamp")
