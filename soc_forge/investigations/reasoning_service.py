from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Iterable

from soc_forge.investigations.models import (
    Decision,
    EvidenceReference,
    HYPOTHESIS_STATES,
    Hypothesis,
)
from soc_forge.investigations.repository import InvestigationConflictError
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


TERMINAL_HYPOTHESIS_STATES = frozenset({"supported", "rejected", "inconclusive"})
DECISION_TYPES = frozenset(
    {
        "hypothesis_assessment",
        "escalation",
        "containment_recommendation",
        "closure_rationale",
        "investigative_conclusion",
    }
)
EVIDENCE_RELATIONSHIPS = frozenset({"supporting", "contradicting"})


class InvestigationReasoningError(Exception):
    """Base error for analyst reasoning workflow operations."""


class DuplicateHypothesisError(InvestigationReasoningError):
    pass


class HypothesisNotFoundError(InvestigationReasoningError):
    pass


class InvalidHypothesisStateError(InvestigationReasoningError):
    pass


class InvalidHypothesisTransitionError(InvestigationReasoningError):
    pass


class InvalidHypothesisStatementError(InvestigationReasoningError):
    pass


class InvalidReasoningAuthorError(InvestigationReasoningError):
    pass


class InvalidAssessmentRationaleError(InvestigationReasoningError):
    pass


class InvalidEvidenceClassificationError(InvestigationReasoningError):
    pass


class HypothesisEvidenceNotFoundError(InvestigationReasoningError):
    pass


class DuplicateHypothesisEvidenceError(InvestigationReasoningError):
    pass


class HypothesisEvidenceRelationshipNotFoundError(InvestigationReasoningError):
    pass


class InvalidDecisionTypeError(InvestigationReasoningError):
    pass


class InvalidDecisionRationaleError(InvestigationReasoningError):
    pass


class DuplicateReasoningDecisionError(InvestigationReasoningError):
    pass


class ReasoningReferenceError(InvestigationReasoningError):
    pass


@dataclass(frozen=True)
class HypothesisSummary:
    hypothesis_id: str
    statement: str
    state: str
    supporting_evidence_count: int
    contradicting_evidence_count: int
    created_at: str | None
    updated_at: str | None


@dataclass(frozen=True)
class ReasoningSummary:
    total_hypotheses: int
    open: int
    supported: int
    rejected: int
    inconclusive: int
    decision_count: int
    hypotheses_lacking_evidence: tuple[str, ...]
    mixed_evidence_hypotheses: tuple[str, ...]
    last_reasoning_update: str | None
    hypotheses: tuple[HypothesisSummary, ...]
    decision_ids: tuple[str, ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationReasoningService:
    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
    ):
        self.workspace_service = workspace_service
        self.clock = clock

    def create_hypothesis(
        self,
        investigation_id: str,
        *,
        hypothesis_id: str,
        statement: str,
        author: str,
        expected_revision: int,
        supporting_evidence_ids: Iterable[str] = (),
        contradicting_evidence_ids: Iterable[str] = (),
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        normalized_id = self._text(hypothesis_id, "hypothesis ID")
        if any(
            item.hypothesis_id == normalized_id
            for item in current.investigation.hypotheses
        ):
            raise DuplicateHypothesisError(
                f"Hypothesis {normalized_id!r} already exists in {investigation_id!r}"
            )
        supporting = self._ids(supporting_evidence_ids)
        contradicting = self._ids(contradicting_evidence_ids)
        self._validate_relationship_sets(supporting, contradicting)
        self._validate_evidence(
            current,
            supporting,
            relationship="supporting",
        )
        self._validate_evidence(
            current,
            contradicting,
            relationship="contradicting",
        )
        timestamp = self._now()
        hypothesis = Hypothesis(
            hypothesis_id=normalized_id,
            statement=self._statement(statement),
            state="open",
            supporting_evidence_reference_ids=supporting,
            contradicting_evidence_reference_ids=contradicting,
            created_at=timestamp,
            updated_at=timestamp,
            author=self._author(author),
        )
        return self.workspace_service.replace_reasoning(
            investigation_id,
            self._ordered_hypotheses(current.investigation.hypotheses + (hypothesis,)),
            current.investigation.decisions,
            expected_revision=expected_revision,
        )

    def edit_hypothesis_statement(
        self,
        investigation_id: str,
        hypothesis_id: str,
        *,
        statement: str,
        author: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        index = self._hypothesis_index(current, hypothesis_id)
        existing = current.investigation.hypotheses[index]
        normalized_statement = self._statement(statement)
        normalized_author = self._author(author)
        if existing.statement == normalized_statement and existing.author == normalized_author:
            return current
        updated = replace(
            existing,
            statement=normalized_statement,
            author=normalized_author,
            updated_at=self._now(),
        )
        return self._replace_hypothesis(current, index, updated)

    def add_hypothesis_evidence(
        self,
        investigation_id: str,
        hypothesis_id: str,
        evidence_id: str,
        *,
        relationship: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        index = self._hypothesis_index(current, hypothesis_id)
        normalized_relationship = self._relationship(relationship)
        normalized_id = self._text(evidence_id, "evidence ID")
        self._validate_evidence(
            current,
            (normalized_id,),
            relationship=normalized_relationship,
        )
        existing = current.investigation.hypotheses[index]
        supporting = set(existing.supporting_evidence_reference_ids)
        contradicting = set(existing.contradicting_evidence_reference_ids)
        target = supporting if normalized_relationship == "supporting" else contradicting
        other = contradicting if normalized_relationship == "supporting" else supporting
        if normalized_id in target:
            raise DuplicateHypothesisEvidenceError(
                f"Evidence {normalized_id!r} already has {normalized_relationship!r} "
                f"relationship to hypothesis {hypothesis_id!r}"
            )
        if normalized_id in other:
            raise InvalidEvidenceClassificationError(
                f"Evidence {normalized_id!r} already has the opposite relationship "
                f"to hypothesis {hypothesis_id!r}"
            )
        target.add(normalized_id)
        updated = replace(
            existing,
            supporting_evidence_reference_ids=tuple(sorted(supporting)),
            contradicting_evidence_reference_ids=tuple(sorted(contradicting)),
            updated_at=self._now(),
        )
        return self._replace_hypothesis(current, index, updated)

    def remove_hypothesis_evidence(
        self,
        investigation_id: str,
        hypothesis_id: str,
        evidence_id: str,
        *,
        relationship: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        index = self._hypothesis_index(current, hypothesis_id)
        normalized_relationship = self._relationship(relationship)
        normalized_id = self._text(evidence_id, "evidence ID")
        existing = current.investigation.hypotheses[index]
        supporting = set(existing.supporting_evidence_reference_ids)
        contradicting = set(existing.contradicting_evidence_reference_ids)
        target = supporting if normalized_relationship == "supporting" else contradicting
        if normalized_id not in target:
            raise HypothesisEvidenceRelationshipNotFoundError(
                f"Evidence {normalized_id!r} has no {normalized_relationship!r} "
                f"relationship to hypothesis {hypothesis_id!r}"
            )
        target.remove(normalized_id)
        updated = replace(
            existing,
            supporting_evidence_reference_ids=tuple(sorted(supporting)),
            contradicting_evidence_reference_ids=tuple(sorted(contradicting)),
            updated_at=self._now(),
        )
        return self._replace_hypothesis(current, index, updated)

    def assess_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        *,
        state: str,
        rationale: str,
        author: str,
        decision_id: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        index = self._hypothesis_index(current, hypothesis_id)
        existing = current.investigation.hypotheses[index]
        normalized_state = self._state(state)
        if normalized_state == existing.state:
            return current
        if normalized_state not in TERMINAL_HYPOTHESIS_STATES:
            raise InvalidHypothesisTransitionError(
                f"Hypothesis {hypothesis_id!r} must use reopen_hypothesis to return to open"
            )
        if existing.state != "open":
            raise InvalidHypothesisTransitionError(
                f"Hypothesis {hypothesis_id!r} must be reopened before reassessment"
            )
        timestamp = self._now()
        updated = replace(existing, state=normalized_state, updated_at=timestamp)
        evidence_ids = tuple(
            sorted(
                set(existing.supporting_evidence_reference_ids).union(
                    existing.contradicting_evidence_reference_ids
                )
            )
        )
        decision = self._decision(
            current,
            decision_id=decision_id,
            decision_type="hypothesis_assessment",
            outcome=normalized_state,
            rationale=self._assessment_rationale(rationale),
            author=author,
            timestamp=timestamp,
            evidence_reference_ids=evidence_ids,
            hypothesis_ids=(existing.hypothesis_id,),
        )
        return self._replace_hypothesis(
            current,
            index,
            updated,
            appended_decision=decision,
        )

    def reopen_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        *,
        rationale: str,
        author: str,
        decision_id: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        index = self._hypothesis_index(current, hypothesis_id)
        existing = current.investigation.hypotheses[index]
        if existing.state == "open":
            return current
        timestamp = self._now()
        updated = replace(existing, state="open", updated_at=timestamp)
        decision = self._decision(
            current,
            decision_id=decision_id,
            decision_type="hypothesis_assessment",
            outcome="reopened",
            rationale=self._assessment_rationale(rationale),
            author=author,
            timestamp=timestamp,
            evidence_reference_ids=tuple(
                sorted(
                    set(existing.supporting_evidence_reference_ids).union(
                        existing.contradicting_evidence_reference_ids
                    )
                )
            ),
            hypothesis_ids=(existing.hypothesis_id,),
        )
        return self._replace_hypothesis(
            current,
            index,
            updated,
            appended_decision=decision,
        )

    def record_investigation_decision(
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
        current = self._current(investigation_id, expected_revision)
        decision = self._decision(
            current,
            decision_id=decision_id,
            decision_type=decision_type,
            outcome=outcome,
            rationale=rationale,
            author=author,
            timestamp=self._now(),
            evidence_reference_ids=self._ids(evidence_reference_ids),
            hypothesis_ids=self._ids(hypothesis_ids),
        )
        return self.workspace_service.replace_reasoning(
            investigation_id,
            current.investigation.hypotheses,
            current.investigation.decisions + (decision,),
            expected_revision=expected_revision,
        )

    def reasoning_summary(self, investigation_id: str) -> ReasoningSummary:
        current = self.workspace_service.get_investigation(investigation_id)
        hypotheses = tuple(
            sorted(current.investigation.hypotheses, key=lambda item: item.hypothesis_id)
        )
        decisions = tuple(
            sorted(current.investigation.decisions, key=lambda item: item.decision_id)
        )
        counts = {state: 0 for state in HYPOTHESIS_STATES}
        for hypothesis in hypotheses:
            counts[hypothesis.state] += 1
        updates = [
            value
            for value in (
                *(item.updated_at for item in hypotheses),
                *(item.decided_at for item in decisions),
            )
            if value
        ]
        return ReasoningSummary(
            total_hypotheses=len(hypotheses),
            open=counts["open"],
            supported=counts["supported"],
            rejected=counts["rejected"],
            inconclusive=counts["inconclusive"],
            decision_count=len(decisions),
            hypotheses_lacking_evidence=tuple(
                item.hypothesis_id
                for item in hypotheses
                if not item.supporting_evidence_reference_ids
                and not item.contradicting_evidence_reference_ids
            ),
            mixed_evidence_hypotheses=tuple(
                item.hypothesis_id
                for item in hypotheses
                if item.supporting_evidence_reference_ids
                and item.contradicting_evidence_reference_ids
            ),
            last_reasoning_update=max(updates) if updates else None,
            hypotheses=tuple(
                HypothesisSummary(
                    hypothesis_id=item.hypothesis_id,
                    statement=item.statement,
                    state=item.state,
                    supporting_evidence_count=len(
                        item.supporting_evidence_reference_ids
                    ),
                    contradicting_evidence_count=len(
                        item.contradicting_evidence_reference_ids
                    ),
                    created_at=item.created_at,
                    updated_at=item.updated_at,
                )
                for item in hypotheses
            ),
            decision_ids=tuple(item.decision_id for item in decisions),
        )

    def _replace_hypothesis(
        self,
        current: WorkspaceResult,
        index: int,
        hypothesis: Hypothesis,
        *,
        appended_decision: Decision | None = None,
    ) -> WorkspaceResult:
        hypotheses = list(current.investigation.hypotheses)
        hypotheses[index] = hypothesis
        decisions = current.investigation.decisions
        if appended_decision is not None:
            decisions = decisions + (appended_decision,)
        return self.workspace_service.replace_reasoning(
            current.investigation.investigation_id,
            self._ordered_hypotheses(tuple(hypotheses)),
            decisions,
            expected_revision=current.revision,
        )

    def _decision(
        self,
        current: WorkspaceResult,
        *,
        decision_id: str,
        decision_type: str,
        outcome: str,
        rationale: str,
        author: str,
        timestamp: str,
        evidence_reference_ids: tuple[str, ...],
        hypothesis_ids: tuple[str, ...],
    ) -> Decision:
        normalized_id = self._text(decision_id, "decision ID")
        if any(
            item.decision_id == normalized_id
            for item in current.investigation.decisions
        ):
            raise DuplicateReasoningDecisionError(
                f"Decision {normalized_id!r} already exists in "
                f"{current.investigation.investigation_id!r}"
            )
        normalized_type = self._text(decision_type, "decision type")
        if normalized_type not in DECISION_TYPES:
            raise InvalidDecisionTypeError(
                "Decision type must be one of: " + ", ".join(sorted(DECISION_TYPES))
            )
        known_evidence = {
            item.reference_id for item in current.investigation.evidence_references
        }
        known_hypotheses = {
            item.hypothesis_id for item in current.investigation.hypotheses
        }
        self._known_ids(evidence_reference_ids, known_evidence, "evidence")
        self._known_ids(hypothesis_ids, known_hypotheses, "hypothesis")
        return Decision(
            decision_id=normalized_id,
            decision_type=normalized_type,
            outcome=self._text(outcome, "decision outcome"),
            rationale=self._decision_rationale(rationale),
            evidence_reference_ids=evidence_reference_ids,
            hypothesis_ids=hypothesis_ids,
            decided_at=timestamp,
            decided_by=self._author(author),
        )

    def _current(
        self,
        investigation_id: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        current = self.workspace_service.get_investigation(investigation_id)
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or current.revision != expected_revision
        ):
            raise InvestigationConflictError(
                f"Investigation {investigation_id!r} is at revision "
                f"{current.revision}, not expected revision {expected_revision}"
            )
        return current

    @staticmethod
    def _hypothesis_index(current: WorkspaceResult, hypothesis_id: str) -> int:
        for index, hypothesis in enumerate(current.investigation.hypotheses):
            if hypothesis.hypothesis_id == hypothesis_id:
                return index
        raise HypothesisNotFoundError(
            f"Hypothesis {hypothesis_id!r} was not found in "
            f"{current.investigation.investigation_id!r}"
        )

    @staticmethod
    def _selected_evidence(current: WorkspaceResult) -> dict[str, EvidenceReference]:
        return {
            item.reference_id: item
            for item in current.investigation.evidence_references
            if item.origin == "analyst_selection"
        }

    def _validate_evidence(
        self,
        current: WorkspaceResult,
        evidence_ids: tuple[str, ...],
        *,
        relationship: str,
    ) -> None:
        selected = self._selected_evidence(current)
        for evidence_id in evidence_ids:
            evidence = selected.get(evidence_id)
            if evidence is None:
                raise HypothesisEvidenceNotFoundError(
                    f"Analyst-selected evidence {evidence_id!r} was not found"
                )
            if evidence.classification != relationship:
                raise InvalidEvidenceClassificationError(
                    f"Evidence {evidence_id!r} classification "
                    f"{evidence.classification!r} cannot be used as {relationship!r}"
                )

    @staticmethod
    def _validate_relationship_sets(
        supporting: tuple[str, ...],
        contradicting: tuple[str, ...],
    ) -> None:
        overlap = sorted(set(supporting).intersection(contradicting))
        if overlap:
            raise InvalidEvidenceClassificationError(
                f"Evidence {overlap[0]!r} cannot be both supporting and contradicting"
            )

    @staticmethod
    def _relationship(value: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in EVIDENCE_RELATIONSHIPS:
            raise InvalidEvidenceClassificationError(
                "Relationship must be supporting or contradicting"
            )
        return normalized

    @staticmethod
    def _state(value: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in HYPOTHESIS_STATES:
            raise InvalidHypothesisStateError(
                "Hypothesis state must be one of: "
                + ", ".join(sorted(HYPOTHESIS_STATES))
            )
        return normalized

    @staticmethod
    def _text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvestigationReasoningError(f"{field_name} must not be blank")
        return value.strip()


    @staticmethod
    def _statement(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidHypothesisStatementError(
                "Hypothesis statement must not be blank"
            )
        return value.strip()

    @staticmethod
    def _author(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidReasoningAuthorError("Analyst author must not be blank")
        return value.strip()

    @staticmethod
    def _assessment_rationale(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidAssessmentRationaleError(
                "Assessment or decision rationale must not be blank"
            )
        return value.strip()

    @staticmethod
    def _decision_rationale(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidDecisionRationaleError("Decision rationale must not be blank")
        return value.strip()

    def _now(self) -> str:
        value = self.clock()
        if not isinstance(value, str) or not value.strip():
            raise InvestigationReasoningError("Reasoning clock returned no timestamp")
        return value.strip()

    @staticmethod
    def _ids(values: Iterable[str]) -> tuple[str, ...]:
        if isinstance(values, (str, bytes)):
            values = (str(values),)
        return tuple(
            sorted({str(value).strip() for value in values if str(value).strip()})
        )

    @staticmethod
    def _known_ids(
        references: tuple[str, ...],
        known: set[str],
        relationship: str,
    ) -> None:
        missing = sorted(set(references).difference(known))
        if missing:
            raise ReasoningReferenceError(
                f"Decision references missing {relationship} ID {missing[0]!r}"
            )

    @staticmethod
    def _ordered_hypotheses(
        hypotheses: tuple[Hypothesis, ...],
    ) -> tuple[Hypothesis, ...]:
        return tuple(sorted(hypotheses, key=lambda item: item.hypothesis_id))
