from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Iterable

from soc_forge.investigations.models import (
    FINDING_CONFIDENCES,
    FINDING_STATUSES,
    InvestigationFinding,
)
from soc_forge.investigations.repository import InvestigationConflictError
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


class InvestigationFindingError(Exception):
    """Base error for durable analyst finding operations."""


class DuplicateFindingError(InvestigationFindingError):
    pass


class FindingNotFoundError(InvestigationFindingError):
    pass


class InvalidFindingReferenceError(InvestigationFindingError):
    pass


class FindingLifecycleError(InvestigationFindingError):
    pass


class SupersededFindingReadOnlyError(FindingLifecycleError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationFindingService:
    """Own finding lifecycle and relationship validation."""

    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        self.workspace_service = workspace_service
        self.clock = clock

    def create_finding(
        self,
        investigation_id: str,
        *,
        finding_id: str,
        title: str,
        conclusion: str,
        status: str,
        confidence: str,
        author: str,
        expected_revision: int,
        evidence_ids: Iterable[str] = (),
        hypothesis_ids: Iterable[str] = (),
        decision_ids: Iterable[str] = (),
        attack_tactics: Iterable[str] = (),
        attack_techniques: Iterable[str] = (),
        limitations: Iterable[str] = (),
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        if any(item.finding_id == finding_id for item in current.investigation.findings):
            raise DuplicateFindingError(
                f"Finding {finding_id!r} already exists in {investigation_id!r}"
            )
        timestamp = self.clock()
        finding = InvestigationFinding(
            finding_id=finding_id,
            investigation_id=investigation_id,
            title=title,
            conclusion=conclusion,
            status=self._controlled(status, FINDING_STATUSES, "status"),
            confidence=self._controlled(
                confidence, FINDING_CONFIDENCES, "confidence"
            ),
            author=author,
            created_at=timestamp,
            updated_at=timestamp,
            evidence_ids=tuple(evidence_ids),
            hypothesis_ids=tuple(hypothesis_ids),
            decision_ids=tuple(decision_ids),
            attack_tactics=tuple(attack_tactics),
            attack_techniques=tuple(attack_techniques),
            limitations=tuple(limitations),
        )
        self._validate_references(current, finding)
        return self.workspace_service.replace_findings(
            investigation_id,
            current.investigation.findings + (finding,),
            expected_revision=expected_revision,
        )

    def get_finding(
        self, investigation_id: str, finding_id: str
    ) -> InvestigationFinding:
        current = self.workspace_service.get_investigation(investigation_id)
        return self._find(current, finding_id)

    def list_findings(
        self, investigation_id: str
    ) -> tuple[InvestigationFinding, ...]:
        current = self.workspace_service.get_investigation(investigation_id)
        return tuple(sorted(
            current.investigation.findings,
            key=lambda item: item.finding_id,
        ))

    def list_active_findings(self, investigation_id: str) -> tuple[InvestigationFinding, ...]:
        return tuple(item for item in self.list_findings(investigation_id) if item.lifecycle_state == "active")

    def list_historical_findings(self, investigation_id: str) -> tuple[InvestigationFinding, ...]:
        return tuple(item for item in self.list_findings(investigation_id) if item.lifecycle_state == "superseded")

    def resolve_current_finding(self, investigation_id: str, finding_id: str) -> InvestigationFinding:
        findings = {item.finding_id: item for item in self.list_findings(investigation_id)}
        current = findings.get(finding_id)
        if current is None:
            raise FindingNotFoundError(f"Finding {finding_id!r} was not found")
        seen = set()
        while current.superseded_by_finding_id is not None:
            if current.finding_id in seen:
                raise FindingLifecycleError("Finding supersession cycle detected")
            seen.add(current.finding_id)
            current = findings[current.superseded_by_finding_id]
        return current

    def supersede_finding(
        self, investigation_id: str, finding_id: str, replacement_finding_id: str,
        *, reason: str, author: str, expected_revision: int,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        original = self._find(current, finding_id)
        replacement = self._find(current, replacement_finding_id)
        if original.finding_id == replacement.finding_id:
            raise FindingLifecycleError("A finding cannot supersede itself")
        if original.lifecycle_state != "active":
            raise FindingLifecycleError("The original finding is already superseded")
        if replacement.lifecycle_state != "active":
            raise FindingLifecycleError("The replacement finding is superseded")
        if replacement.supersedes_finding_id is not None:
            raise FindingLifecycleError("The replacement already supersedes a finding")
        timestamp = self.clock()
        historical = replace(
            original, lifecycle_state="superseded",
            superseded_by_finding_id=replacement.finding_id,
            supersession_reason=reason, supersession_author=author,
            superseded_at=timestamp,
        )
        authoritative = replace(replacement, supersedes_finding_id=original.finding_id)
        findings = tuple(
            historical if item.finding_id == original.finding_id
            else authoritative if item.finding_id == replacement.finding_id
            else item for item in current.investigation.findings
        )
        return self.workspace_service.replace_findings(
            investigation_id, findings, expected_revision=expected_revision
        )

    def update_finding(
        self,
        investigation_id: str,
        finding_id: str,
        *,
        expected_revision: int,
        title: str | None = None,
        conclusion: str | None = None,
        status: str | None = None,
        confidence: str | None = None,
        author: str | None = None,
        evidence_ids: Iterable[str] | None = None,
        hypothesis_ids: Iterable[str] | None = None,
        decision_ids: Iterable[str] | None = None,
        attack_tactics: Iterable[str] | None = None,
        attack_techniques: Iterable[str] | None = None,
        limitations: Iterable[str] | None = None,
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        existing = self._find(current, finding_id)
        if existing.lifecycle_state == "superseded":
            raise SupersededFindingReadOnlyError(
                "Superseded findings are read-only historical records"
            )
        changes = {
            "title": existing.title if title is None else title,
            "conclusion": existing.conclusion if conclusion is None else conclusion,
            "status": existing.status if status is None else self._controlled(
                status, FINDING_STATUSES, "status"
            ),
            "confidence": (
                existing.confidence if confidence is None
                else self._controlled(confidence, FINDING_CONFIDENCES, "confidence")
            ),
            "author": existing.author if author is None else author,
            "evidence_ids": (
                existing.evidence_ids if evidence_ids is None else tuple(evidence_ids)
            ),
            "hypothesis_ids": (
                existing.hypothesis_ids
                if hypothesis_ids is None else tuple(hypothesis_ids)
            ),
            "decision_ids": (
                existing.decision_ids if decision_ids is None else tuple(decision_ids)
            ),
            "attack_tactics": (
                existing.attack_tactics
                if attack_tactics is None else tuple(attack_tactics)
            ),
            "attack_techniques": (
                existing.attack_techniques
                if attack_techniques is None else tuple(attack_techniques)
            ),
            "limitations": (
                existing.limitations if limitations is None else tuple(limitations)
            ),
        }
        candidate = replace(existing, **changes)
        if candidate == existing:
            return current
        updated = replace(candidate, updated_at=self.clock())
        self._validate_references(current, updated)
        findings = tuple(
            updated if item.finding_id == finding_id else item
            for item in current.investigation.findings
        )
        return self.workspace_service.replace_findings(
            investigation_id,
            findings,
            expected_revision=expected_revision,
        )

    @staticmethod
    def _controlled(value: str, allowed: frozenset[str], name: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in allowed:
            raise ValueError(
                f"Finding {name} must be one of: {', '.join(sorted(allowed))}"
            )
        return normalized

    @staticmethod
    def _find(current: WorkspaceResult, finding_id: str) -> InvestigationFinding:
        for finding in current.investigation.findings:
            if finding.finding_id == finding_id:
                return finding
        raise FindingNotFoundError(
            f"Finding {finding_id!r} was not found in "
            f"{current.investigation.investigation_id!r}"
        )

    @staticmethod
    def _validate_references(
        current: WorkspaceResult, finding: InvestigationFinding
    ) -> None:
        investigation = current.investigation
        known = {
            "evidence": {
                item.reference_id for item in investigation.evidence_references
                if item.origin == "analyst_selection"
            },
            "hypothesis": {
                item.hypothesis_id for item in investigation.hypotheses
            },
            "decision": {
                item.decision_id for item in investigation.decisions
            },
        }
        for relationship, values in (
            ("evidence", finding.evidence_ids),
            ("hypothesis", finding.hypothesis_ids),
            ("decision", finding.decision_ids),
        ):
            missing = sorted(set(values).difference(known[relationship]))
            if missing:
                raise InvalidFindingReferenceError(
                    f"Finding {finding.finding_id!r} references unknown "
                    f"{relationship} ID {missing[0]!r} in "
                    f"{investigation.investigation_id!r}"
                )

    def _current(
        self, investigation_id: str, expected_revision: int
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
