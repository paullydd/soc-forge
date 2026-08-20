from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from soc_forge.investigations.operations_queue import (
    OPERATIONS_QUEUE_PRIORITIES,
    OperationsQueueItem,
    OperationsQueueService,
)


_PRIORITY_ORDER = {
    value: index for index, value in enumerate(OPERATIONS_QUEUE_PRIORITIES)
}
_OPERATIONAL_STATE_ORDER = {
    "in_progress": 0,
    "approved": 1,
    "proposed": 2,
    "uncovered_finding": 3,
}
_ACTION_STATE_BASIS = {
    "in_progress": "Action is currently in progress",
    "approved": "Action is approved and ready to begin",
    "proposed": "Action is awaiting analyst approval",
}
_UNCOVERED_FINDING_BASIS = (
    "Finding is ACTIVE",
    "No open Response Action addresses this Finding",
    "Uncovered Findings use neutral MEDIUM operational priority",
)


@dataclass(frozen=True)
class PrioritizedOperationsItem:
    """Explainable priority metadata layered over one queue item."""

    queue_item: OperationsQueueItem
    priority_tier: str
    priority_basis: tuple[str, ...]
    operational_state: str


@dataclass(frozen=True)
class OperationsPrioritizationSummary:
    top_item: PrioritizedOperationsItem | None
    top_priority: str | None
    top_reason: str | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class OperationsPrioritizationService:
    """Rank queue items deterministically without changing queue semantics."""

    def __init__(self, queue_service: OperationsQueueService):
        self.queue_service = queue_service

    def prioritize(
        self,
        items: Iterable[OperationsQueueItem] | None = None,
        *,
        investigation_id: str | None = None,
    ) -> tuple[PrioritizedOperationsItem, ...]:
        if items is not None and investigation_id is not None:
            raise ValueError("Provide queue items or an investigation_id, not both")
        if items is None:
            projected = (
                self.queue_service.list_queue()
                if investigation_id is None
                else self.queue_service.list_queue(investigation_id)
            )
        else:
            projected = tuple(items)
        prioritized = tuple(self.prioritize_item(item) for item in projected)
        return tuple(sorted(prioritized, key=self._rank_key))

    def get_prioritized_item(self, queue_item_id: str) -> PrioritizedOperationsItem:
        item = self.queue_service.get_queue_item(queue_item_id)
        return self.prioritize_item(item)

    def summarize(
        self,
        items: Iterable[PrioritizedOperationsItem] | None = None,
    ) -> OperationsPrioritizationSummary:
        prioritized = tuple(self.prioritize() if items is None else items)
        top_item = prioritized[0] if prioritized else None
        return OperationsPrioritizationSummary(
            top_item=top_item,
            top_priority=None if top_item is None else top_item.priority_tier,
            top_reason=(
                None if top_item is None else top_item.priority_basis[-1]
            ),
            critical_count=sum(item.priority_tier == "critical" for item in prioritized),
            high_count=sum(item.priority_tier == "high" for item in prioritized),
            medium_count=sum(item.priority_tier == "medium" for item in prioritized),
            low_count=sum(item.priority_tier == "low" for item in prioritized),
        )

    @staticmethod
    def prioritize_item(item: OperationsQueueItem) -> PrioritizedOperationsItem:
        if item.item_type == "response_action":
            operational_state = item.source_status
            basis = (
                f"Response Action priority is {item.priority.upper()}",
                _ACTION_STATE_BASIS[operational_state],
            )
        else:
            operational_state = "uncovered_finding"
            basis = _UNCOVERED_FINDING_BASIS
        return PrioritizedOperationsItem(
            queue_item=item,
            priority_tier=item.priority,
            priority_basis=basis,
            operational_state=operational_state,
        )

    @staticmethod
    def _rank_key(item: PrioritizedOperationsItem) -> tuple[int, int, str, str, str]:
        source = item.queue_item
        return (
            _PRIORITY_ORDER[item.priority_tier],
            _OPERATIONAL_STATE_ORDER[item.operational_state],
            source.updated_at,
            source.investigation_id,
            source.source_id,
        )

