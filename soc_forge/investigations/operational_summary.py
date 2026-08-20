from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from soc_forge.investigations.operations_prioritization import (
    OperationsPrioritizationService,
    PrioritizedOperationsItem,
)


TOP_ITEMS_LIMIT = 3


@dataclass(frozen=True)
class OperationalSummary:
    total_attention_items: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    response_action_count: int
    uncovered_finding_count: int
    proposed_count: int
    approved_count: int
    in_progress_count: int
    investigations_represented: int
    top_item: PrioritizedOperationsItem | None
    top_priority: str | None
    top_reason: str | None
    top_investigation_id: str | None
    top_source_id: str | None
    top_source_type: str | None
    top_items: tuple[PrioritizedOperationsItem, ...]


class OperationalSummaryService:
    """Summarize the authoritative prioritized queue without creating state."""

    def __init__(self, prioritization_service: OperationsPrioritizationService):
        self.prioritization_service = prioritization_service

    def summarize(
        self,
        items: Iterable[PrioritizedOperationsItem] | None = None,
    ) -> OperationalSummary:
        prioritized = tuple(
            self.prioritization_service.prioritize() if items is None else items
        )
        top_item = prioritized[0] if prioritized else None
        top_source = None if top_item is None else top_item.queue_item
        return OperationalSummary(
            total_attention_items=len(prioritized),
            critical_count=sum(item.priority_tier == "critical" for item in prioritized),
            high_count=sum(item.priority_tier == "high" for item in prioritized),
            medium_count=sum(item.priority_tier == "medium" for item in prioritized),
            low_count=sum(item.priority_tier == "low" for item in prioritized),
            response_action_count=sum(
                item.queue_item.item_type == "response_action" for item in prioritized
            ),
            uncovered_finding_count=sum(
                item.queue_item.item_type == "uncovered_finding" for item in prioritized
            ),
            proposed_count=sum(item.operational_state == "proposed" for item in prioritized),
            approved_count=sum(item.operational_state == "approved" for item in prioritized),
            in_progress_count=sum(
                item.operational_state == "in_progress" for item in prioritized
            ),
            investigations_represented=len(
                {item.queue_item.investigation_id for item in prioritized}
            ),
            top_item=top_item,
            top_priority=None if top_item is None else top_item.priority_tier,
            top_reason=None if top_source is None else top_source.reason,
            top_investigation_id=(
                None if top_source is None else top_source.investigation_id
            ),
            top_source_id=None if top_source is None else top_source.source_id,
            top_source_type=None if top_source is None else top_source.source_type,
            top_items=prioritized[:TOP_ITEMS_LIMIT],
        )
