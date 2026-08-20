from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.investigations.operations_prioritization import (
    OperationsPrioritizationService,
    PrioritizedOperationsItem,
)
from soc_forge.investigations.operations_queue import (
    OperationsQueueItem,
    OperationsQueueService,
    OperationsQueueSummary,
)
from soc_forge.ui.terminal import (
    render_application_header,
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_grouped_menu,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


QUEUE_MENU = (
    (
        "QUEUE VIEWS",
        (
            ("1", "All Attention Items"),
            ("2", "Response Actions"),
            ("3", "Uncovered Findings"),
            ("4", "High / Critical"),
        ),
    ),
)


def render_queue_state(
    summary: OperationsQueueSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = (
        ("Total", summary.total_items),
        ("Critical", summary.critical),
        ("High", summary.high),
        ("Medium", summary.medium),
        ("Low", summary.low),
        ("Response Actions", summary.response_actions),
        ("Uncovered Findings", summary.uncovered_findings),
        ("Proposed", summary.proposed),
        ("Approved", summary.approved),
        ("In Progress", summary.in_progress),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="QUEUE STATE",
        width=resolved,
        ansi=ansi,
    )


def render_queue_item(
    item: PrioritizedOperationsItem | OperationsQueueItem,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    if isinstance(item, OperationsQueueItem):
        item = OperationsPrioritizationService.prioritize_item(item)
    source = item.queue_item
    rows = (
        ("Queue ID", source.queue_item_id),
        ("Priority", render_badge("priority", item.priority_tier, ansi=ansi)),
        ("Item Type", source.item_type),
        ("Investigation", source.investigation_id),
        ("Title", source.investigation_title),
        ("Source ID", source.source_id),
        ("Source Status", render_badge("status", source.source_status, ansi=ansi)),
        ("Created", source.created_at),
        ("Updated", source.updated_at),
        ("Reason", source.reason),
        ("Why Prioritized", "\n".join(f"- {basis}" for basis in item.priority_basis)),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi, wrap_values=True),
        title="ATTENTION ITEM",
        width=resolved,
        ansi=ansi,
    )


def render_queue_items(
    items: Iterable[PrioritizedOperationsItem | OperationsQueueItem],
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    projected = tuple(items)
    resolved = resolve_terminal_width(width)
    if not projected:
        return render_empty_state(
            "No analyst attention items.", width=resolved, ansi=ansi
        )
    return "\n\n".join(
        f"[{index}]\n{render_queue_item(item, width=resolved, ansi=ansi)}"
        for index, item in enumerate(projected, start=1)
    )


def render_operations_queue(
    summary: OperationsQueueSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    return "\n\n".join(
        (
            render_application_header(width=resolved, ansi=ansi),
            render_breadcrumb(
                ("SOC-FORGE", "OPERATIONS QUEUE"),
                width=resolved,
                ansi=ansi,
            ),
            render_queue_state(summary, width=resolved, ansi=ansi),
            render_grouped_menu(
                QUEUE_MENU,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


class OperationsQueueConsoleController:
    def __init__(
        self,
        *,
        queue_service: OperationsQueueService,
        prioritization_service: OperationsPrioritizationService | None = None,
        workspace_service: object,
        response_action_controller: object,
        finding_controller: object,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] | None = None,
    ):
        self.queue_service = queue_service
        self.prioritization_service = (
            prioritization_service or OperationsPrioritizationService(queue_service)
        )
        self.workspace_service = workspace_service
        self.response_action_controller = response_action_controller
        self.finding_controller = finding_controller
        self.input = input_func
        self.output = output_func
        self.screen = screen_func or (lambda _title: None)

    def run(self) -> None:
        while True:
            items = self.prioritization_service.prioritize()
            self.screen("OPERATIONS QUEUE")
            queue_items = tuple(item.queue_item for item in items)
            self.output(render_operations_queue(self.queue_service.summarize(queue_items)))
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return
            filters = {
                "1": lambda item: True,
                "2": lambda item: item.queue_item.item_type == "response_action",
                "3": lambda item: item.queue_item.item_type == "uncovered_finding",
                "4": lambda item: item.priority_tier in {"critical", "high"},
            }
            if choice not in filters:
                self.output("\nInvalid option.")
                continue
            self._browse(tuple(item for item in items if filters[choice](item)))

    def _browse(self, items: tuple[PrioritizedOperationsItem, ...]) -> None:
        self.screen("OPERATIONS QUEUE")
        self.output(render_queue_items(items))
        if not items:
            self.input("\nPress Enter to return...")
            return
        choice = self.input("\nItem number (blank to return): ").strip()
        if not choice:
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(items):
            self.output("\nInvalid item number.")
            return
        self._open(items[int(choice) - 1])

    def _open(self, item: PrioritizedOperationsItem) -> None:
        self.screen("OPERATIONS QUEUE ITEM")
        self.output(render_queue_item(item))
        source = item.queue_item
        label = (
            "Response Action"
            if source.item_type == "response_action"
            else "Finding"
        )
        self.output(f"\n[1] Open {label}\n[0] Back")
        if self.input("\nSelect option: ").strip() != "1":
            return
        current = self.workspace_service.get_investigation(source.investigation_id)
        if source.item_type == "response_action":
            self.response_action_controller.open_action(current, source.source_id)
        else:
            self.finding_controller.open_finding(current, source.source_id)
