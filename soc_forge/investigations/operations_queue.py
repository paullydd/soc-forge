from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from soc_forge.investigations.models import Investigation, InvestigationFinding, ResponseAction
from soc_forge.investigations.repository import InvestigationRepository


OPERATIONS_QUEUE_ITEM_TYPES = frozenset({"response_action", "uncovered_finding"})
OPERATIONS_QUEUE_PRIORITIES = ("critical", "high", "medium", "low")
OPEN_RESPONSE_ACTION_STATUSES = frozenset({"proposed", "approved", "in_progress"})
UNCOVERED_FINDING_PRIORITY = "medium"

_PRIORITY_ORDER = {value: index for index, value in enumerate(OPERATIONS_QUEUE_PRIORITIES)}
_SOURCE_ORDER = {
    ("response_action", "proposed"): 0,
    ("response_action", "approved"): 1,
    ("response_action", "in_progress"): 2,
    ("uncovered_finding", "active"): 3,
}
_ACTION_REASONS = {
    "proposed": "Response Action {source_id} is proposed and awaiting analyst review.",
    "approved": "Response Action {source_id} is approved and ready for work.",
    "in_progress": "Response Action {source_id} is currently in progress.",
}


@dataclass(frozen=True)
class OperationsQueueItem:
    queue_item_id: str
    investigation_id: str
    investigation_title: str
    item_type: str
    priority: str
    reason: str
    source_id: str
    source_type: str
    source_status: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        if self.item_type not in OPERATIONS_QUEUE_ITEM_TYPES:
            raise ValueError("Unsupported Operations Queue item type")
        if self.source_type != self.item_type:
            raise ValueError("Operations Queue source_type must match item_type")
        if self.priority not in OPERATIONS_QUEUE_PRIORITIES:
            raise ValueError("Unsupported Operations Queue priority")


@dataclass(frozen=True)
class OperationsQueueSummary:
    total_items: int
    critical: int
    high: int
    medium: int
    low: int
    response_actions: int
    uncovered_findings: int
    proposed: int
    approved: int
    in_progress: int


class OperationsQueueService:
    """Build a deterministic read-only projection of durable analyst work."""

    def __init__(self, repository: InvestigationRepository):
        self.repository = repository

    def list_queue(self, investigation_id: str | None = None) -> tuple[OperationsQueueItem, ...]:
        if investigation_id is not None:
            investigations = (self.repository.load(investigation_id),)
        else:
            investigations = tuple(
                self.repository.load(summary.investigation_id)
                for summary in self.repository.list_investigations()
            )
        return self._sorted(
            item
            for investigation in investigations
            for item in self._project_investigation(investigation)
        )

    def get_queue_item(self, queue_item_id: str) -> OperationsQueueItem:
        for item in self.list_queue():
            if item.queue_item_id == queue_item_id:
                return item
        raise KeyError(f"Operations Queue item {queue_item_id!r} was not found")

    def summarize(self, items: Iterable[OperationsQueueItem] | None = None) -> OperationsQueueSummary:
        projected = tuple(self.list_queue() if items is None else items)
        return OperationsQueueSummary(
            total_items=len(projected),
            critical=sum(item.priority == "critical" for item in projected),
            high=sum(item.priority == "high" for item in projected),
            medium=sum(item.priority == "medium" for item in projected),
            low=sum(item.priority == "low" for item in projected),
            response_actions=sum(item.item_type == "response_action" for item in projected),
            uncovered_findings=sum(item.item_type == "uncovered_finding" for item in projected),
            proposed=sum(item.source_status == "proposed" for item in projected),
            approved=sum(item.source_status == "approved" for item in projected),
            in_progress=sum(item.source_status == "in_progress" for item in projected),
        )

    @staticmethod
    def _project_investigation(investigation: Investigation) -> tuple[OperationsQueueItem, ...]:
        open_actions = tuple(
            action
            for action in investigation.response_actions
            if action.status in OPEN_RESPONSE_ACTION_STATUSES
        )
        covered_finding_ids = {
            finding_id for action in open_actions for finding_id in action.finding_ids
        }
        action_items = tuple(
            OperationsQueueService._action_item(investigation, action)
            for action in open_actions
        )
        finding_items = tuple(
            OperationsQueueService._finding_item(investigation, finding)
            for finding in investigation.findings
            if finding.lifecycle_state == "active"
            and finding.finding_id not in covered_finding_ids
        )
        return action_items + finding_items

    @staticmethod
    def _action_item(investigation: Investigation, action: ResponseAction) -> OperationsQueueItem:
        return OperationsQueueItem(
            queue_item_id=OperationsQueueService._queue_item_id(
                investigation.investigation_id, "response_action", action.action_id
            ),
            investigation_id=investigation.investigation_id,
            investigation_title=investigation.metadata.title,
            item_type="response_action",
            priority=action.priority,
            reason=_ACTION_REASONS[action.status].format(source_id=action.action_id),
            source_id=action.action_id,
            source_type="response_action",
            source_status=action.status,
            created_at=action.created_at,
            updated_at=action.updated_at,
        )

    @staticmethod
    def _finding_item(
        investigation: Investigation, finding: InvestigationFinding
    ) -> OperationsQueueItem:
        return OperationsQueueItem(
            queue_item_id=OperationsQueueService._queue_item_id(
                investigation.investigation_id, "uncovered_finding", finding.finding_id
            ),
            investigation_id=investigation.investigation_id,
            investigation_title=investigation.metadata.title,
            item_type="uncovered_finding",
            priority=UNCOVERED_FINDING_PRIORITY,
            reason=f"Finding {finding.finding_id} is active and has no open Response Action.",
            source_id=finding.finding_id,
            source_type="uncovered_finding",
            source_status=finding.lifecycle_state,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
        )

    @staticmethod
    def _queue_item_id(investigation_id: str, source_type: str, source_id: str) -> str:
        return f"OPQ:{investigation_id}:{source_type}:{source_id}"

    @staticmethod
    def _sorted(items: Iterable[OperationsQueueItem]) -> tuple[OperationsQueueItem, ...]:
        return tuple(
            sorted(
                items,
                key=lambda item: (
                    _PRIORITY_ORDER[item.priority],
                    _SOURCE_ORDER[(item.item_type, item.source_status)],
                    item.updated_at,
                    item.investigation_id,
                    item.source_id,
                ),
            )
        )
