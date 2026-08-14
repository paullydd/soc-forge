from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable
from uuid import uuid4

from soc_forge.investigations.models import (
    RESPONSE_ACTION_PRIORITIES,
    RESPONSE_ACTION_STATUSES,
    RESPONSE_ACTION_TYPES,
    ResponseAction,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


class ResponseActionError(Exception):
    """Base error for durable analyst-controlled response actions."""


class ResponseActionNotFoundError(ResponseActionError):
    pass


class DuplicateResponseActionError(ResponseActionError):
    pass


class InvalidResponseActionFindingError(ResponseActionError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _action_id() -> str:
    return f"ACT-{uuid4().hex.upper()}"


class InvestigationResponseActionService:
    """Owns durable response-action creation and Finding validation."""

    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
        id_factory: Callable[[], str] = _action_id,
    ) -> None:
        self.workspace_service = workspace_service
        self.clock = clock
        self.id_factory = id_factory

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
        current = self.workspace_service.get_investigation(investigation_id)
        if current.revision != expected_revision:
            from soc_forge.investigations.repository import InvestigationConflictError
            raise InvestigationConflictError(
                f"Investigation {investigation_id!r} is at revision {current.revision}, "
                f"not expected revision {expected_revision}"
            )
        resolved_id = action_id if action_id is not None else self.id_factory()
        if any(item.action_id == resolved_id for item in current.investigation.response_actions):
            raise DuplicateResponseActionError(f"Response action {resolved_id!r} already exists")
        normalized_findings = tuple(finding_ids)
        known = {item.finding_id: item for item in current.investigation.findings}
        for finding_id in normalized_findings:
            finding = known.get(finding_id)
            if finding is None:
                raise InvalidResponseActionFindingError(
                    f"Response action references unknown Finding {finding_id!r}"
                )
            if finding.lifecycle_state != "active":
                raise InvalidResponseActionFindingError(
                    f"Response action cannot reference superseded Finding {finding_id!r}"
                )
        timestamp = self.clock()
        action = ResponseAction(
            action_id=resolved_id,
            investigation_id=investigation_id,
            finding_ids=normalized_findings,
            title=title,
            description=description,
            action_type=self._controlled(action_type, RESPONSE_ACTION_TYPES, "type"),
            priority=self._controlled(priority, RESPONSE_ACTION_PRIORITIES, "priority"),
            status=self._controlled(status, RESPONSE_ACTION_STATUSES, "status"),
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

    def get_action(self, investigation_id: str, action_id: str) -> ResponseAction:
        for action in self.list_actions(investigation_id):
            if action.action_id == action_id:
                return action
        raise ResponseActionNotFoundError(f"Response action {action_id!r} was not found")

    def list_actions(self, investigation_id: str) -> tuple[ResponseAction, ...]:
        current = self.workspace_service.get_investigation(investigation_id)
        return tuple(sorted(current.investigation.response_actions, key=lambda item: item.action_id))

    @staticmethod
    def _controlled(value: str, allowed: frozenset[str], name: str) -> str:
        normalized = value.strip().lower() if isinstance(value, str) else ""
        if normalized not in allowed:
            raise ValueError(f"Response action {name} must be one of: {', '.join(sorted(allowed))}")
        return normalized