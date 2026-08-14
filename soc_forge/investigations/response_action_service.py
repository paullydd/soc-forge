from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import re
from typing import Callable, Iterable
from uuid import uuid4

from soc_forge.investigations.models import (
    RESPONSE_ACTION_PRIORITIES,
    RESPONSE_ACTION_STATUSES,
    RESPONSE_ACTION_TYPES,
    ResponseAction,
    ResponseActionTransition,
)
from soc_forge.investigations.repository import InvestigationConflictError
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


RESPONSE_ACTION_TRANSITIONS = {
    "proposed": frozenset({"approved", "dismissed"}),
    "approved": frozenset({"in_progress", "dismissed"}),
    "in_progress": frozenset({"completed", "dismissed"}),
    "completed": frozenset(),
    "dismissed": frozenset(),
}


class ResponseActionError(Exception):
    """Base error for durable analyst-controlled response actions."""


class ResponseActionNotFoundError(ResponseActionError):
    pass


class DuplicateResponseActionError(ResponseActionError):
    pass


class InvalidResponseActionFindingError(ResponseActionError):
    pass


class InvalidResponseActionTransitionError(ResponseActionError):
    pass


class TerminalResponseActionError(InvalidResponseActionTransitionError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _action_id() -> str:
    return f"ACT-{uuid4().hex.upper()}"


def _transition_id() -> str:
    return f"TRANS-{uuid4().hex.upper()}"


class InvestigationResponseActionService:
    """Owns durable response-action creation and lifecycle validation."""

    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
        id_factory: Callable[[], str] = _action_id,
        transition_id_factory: Callable[[], str] = _transition_id,
    ) -> None:
        self.workspace_service = workspace_service
        self.clock = clock
        self.id_factory = id_factory
        self.transition_id_factory = transition_id_factory

    def create_action(
        self,
        investigation_id: str,
        *,
        finding_ids: Iterable[str],
        title: str,
        description: str,
        action_type: str,
        priority: str,
        rationale: str,
        owner: str,
        created_by: str,
        expected_revision: int,
        action_id: str | None = None,
        status: str = "proposed",
    ) -> WorkspaceResult:
        current = self._current(investigation_id, expected_revision)
        resolved_id = action_id if action_id is not None else self.id_factory()
        if any(
            item.action_id == resolved_id
            for item in current.investigation.response_actions
        ):
            raise DuplicateResponseActionError(
                f"Response action {resolved_id!r} already exists"
            )
        normalized_findings = tuple(finding_ids)
        known = {
            item.finding_id: item for item in current.investigation.findings
        }
        for finding_id in normalized_findings:
            finding = known.get(finding_id)
            if finding is None:
                raise InvalidResponseActionFindingError(
                    f"Response action references unknown Finding {finding_id!r}"
                )
            if finding.lifecycle_state != "active":
                raise InvalidResponseActionFindingError(
                    "Response action cannot reference superseded Finding "
                    f"{finding_id!r}"
                )
        normalized_status = self._controlled(
            status, RESPONSE_ACTION_STATUSES, "status"
        )
        if normalized_status != "proposed":
            raise InvalidResponseActionTransitionError(
                "New response actions must begin in proposed status"
            )
        timestamp = self.clock()
        action = ResponseAction(
            action_id=resolved_id,
            investigation_id=investigation_id,
            finding_ids=normalized_findings,
            title=title,
            description=description,
            action_type=self._controlled(
                action_type, RESPONSE_ACTION_TYPES, "type"
            ),
            priority=self._controlled(
                priority, RESPONSE_ACTION_PRIORITIES, "priority"
            ),
            status=normalized_status,
            rationale=rationale,
            owner=owner,
            created_by=created_by,
            created_at=timestamp,
            updated_at=timestamp,
        )
        return self.workspace_service.replace_response_actions(
            investigation_id,
            current.investigation.response_actions + (action,),
            expected_revision=expected_revision,
        )

    def transition_action(
        self,
        investigation_id: str,
        action_id: str,
        *,
        target_status: str,
        author: str,
        rationale: str,
        expected_revision: int,
    ) -> WorkspaceResult:
        self._validate_action_id(action_id)
        current = self._current(investigation_id, expected_revision)
        action = self._find(current, action_id)
        normalized_target = self._controlled(
            target_status, RESPONSE_ACTION_STATUSES, "status"
        )
        allowed = RESPONSE_ACTION_TRANSITIONS[action.status]
        if not allowed:
            raise TerminalResponseActionError(
                f"Response action {action_id!r} is terminal in {action.status!r} status"
            )
        if normalized_target == action.status:
            raise InvalidResponseActionTransitionError(
                "Response action transition must change status"
            )
        if normalized_target not in allowed:
            raise InvalidResponseActionTransitionError(
                f"Response action cannot transition from {action.status!r} "
                f"to {normalized_target!r}"
            )
        timestamp = self.clock()
        transition = ResponseActionTransition(
            transition_id=self.transition_id_factory(),
            from_status=action.status,
            to_status=normalized_target,
            author=author,
            rationale=rationale,
            timestamp=timestamp,
        )
        updated = replace(
            action,
            status=normalized_target,
            updated_at=timestamp,
            transition_history=action.transition_history + (transition,),
        )
        actions = tuple(
            updated if item.action_id == action_id else item
            for item in current.investigation.response_actions
        )
        return self.workspace_service.replace_response_actions(
            investigation_id,
            actions,
            expected_revision=expected_revision,
        )

    def get_action(self, investigation_id: str, action_id: str) -> ResponseAction:
        self._validate_action_id(action_id)
        current = self.workspace_service.get_investigation(investigation_id)
        return self._find(current, action_id)

    def list_actions(self, investigation_id: str) -> tuple[ResponseAction, ...]:
        current = self.workspace_service.get_investigation(investigation_id)
        return tuple(
            sorted(
                current.investigation.response_actions,
                key=lambda item: item.action_id,
            )
        )

    @staticmethod
    def _find(current: WorkspaceResult, action_id: str) -> ResponseAction:
        for action in current.investigation.response_actions:
            if action.action_id == action_id:
                return action
        raise ResponseActionNotFoundError(
            f"Response action {action_id!r} was not found"
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

    @staticmethod
    def _validate_action_id(action_id: str) -> None:
        if not isinstance(action_id, str) or not re.fullmatch(
            r"ACT-[A-Za-z0-9._-]+", action_id
        ):
            raise ValueError("Response action ID must use a valid ACT- identifier")

    @staticmethod
    def _controlled(value: str, allowed: frozenset[str], name: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in allowed:
            raise ValueError(
                f"Response action {name} must be one of: "
                + ", ".join(sorted(allowed))
            )
        return normalized