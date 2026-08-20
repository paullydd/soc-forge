from dataclasses import replace

from soc_forge.investigations.operations_queue import (
    OperationsQueueItem,
    OperationsQueueSummary,
)
from soc_forge.investigations.operations_queue_console import (
    OperationsQueueConsoleController,
    render_operations_queue,
    render_queue_items,
)


def _item(**changes):
    item = OperationsQueueItem(
        queue_item_id="OPQ:INV-001:response_action:ACT-001",
        investigation_id="INV-001",
        investigation_title="Credential review",
        item_type="response_action",
        priority="high",
        reason="Response Action ACT-001 is approved and ready for work.",
        source_id="ACT-001",
        source_type="response_action",
        source_status="approved",
        created_at="2026-08-14T10:00:00Z",
        updated_at="2026-08-14T11:00:00Z",
    )
    return replace(item, **changes)


def test_workspace_renders_v32_structure_and_filters():
    summary = OperationsQueueSummary(2, 0, 1, 1, 0, 1, 1, 0, 1, 0)
    output = render_operations_queue(summary, width=72, ansi=False)
    assert "SOC-FORGE" in output
    assert "OPERATIONS QUEUE" in output
    assert "QUEUE STATE" in output
    assert "[1] All Attention Items" in output
    assert "[2] Response Actions" in output
    assert "[3] Uncovered Findings" in output
    assert "[4] High / Critical" in output
    assert "[0] Back" in output
    assert all(len(line) <= 72 for line in output.splitlines())


def test_item_cards_keep_projection_fields_and_empty_state():
    item = _item()
    output = render_queue_items((item,), width=90, ansi=False)
    for value in (
        item.queue_item_id,
        item.investigation_id,
        item.investigation_title,
        item.source_id,
        item.source_status,
        item.created_at,
        item.updated_at,
        item.reason,
    ):
        assert value in output
    assert "Why Prioritized" in output
    assert "Response Action priority is HIGH" in output
    assert "Action is approved and ready to" in output
    assert "begin" in output
    assert "No analyst attention items." in render_queue_items((), ansi=False)


class _Queue:
    def __init__(self, items):
        self.items = items
        self.calls = 0

    def list_queue(self):
        self.calls += 1
        return tuple(self.items)

    def summarize(self, items):
        return OperationsQueueSummary(
            len(items),
            sum(item.priority == "critical" for item in items),
            sum(item.priority == "high" for item in items),
            sum(item.priority == "medium" for item in items),
            sum(item.priority == "low" for item in items),
            sum(item.item_type == "response_action" for item in items),
            sum(item.item_type == "uncovered_finding" for item in items),
            sum(item.source_status == "proposed" for item in items),
            sum(item.source_status == "approved" for item in items),
            sum(item.source_status == "in_progress" for item in items),
        )


class _Workspace:
    def get_investigation(self, investigation_id):
        return f"workspace:{investigation_id}"


class _SourceController:
    def __init__(self):
        self.calls = []

    def open_action(self, current, source_id):
        self.calls.append((current, source_id))

    def open_finding(self, current, source_id):
        self.calls.append((current, source_id))


def test_controller_routes_to_authoritative_response_action_and_refreshes():
    queue = _Queue([_item()])
    response = _SourceController()
    finding = _SourceController()
    inputs = iter(("1", "1", "1", "0"))
    controller = OperationsQueueConsoleController(
        queue_service=queue,
        workspace_service=_Workspace(),
        response_action_controller=response,
        finding_controller=finding,
        input_func=lambda _prompt="": next(inputs),
        output_func=lambda _value: None,
    )
    controller.run()
    assert response.calls == [("workspace:INV-001", "ACT-001")]
    assert finding.calls == []
    assert queue.calls == 2


def test_controller_routes_uncovered_finding_and_preserves_source_id():
    finding_item = _item(
        queue_item_id="OPQ:INV-001:uncovered_finding:FIND-001",
        item_type="uncovered_finding",
        source_type="uncovered_finding",
        source_id="FIND-001",
        source_status="active",
        priority="medium",
        reason="Finding FIND-001 is active and has no open Response Action.",
    )
    queue = _Queue([finding_item])
    response = _SourceController()
    finding = _SourceController()
    inputs = iter(("3", "1", "1", "0"))
    controller = OperationsQueueConsoleController(
        queue_service=queue,
        workspace_service=_Workspace(),
        response_action_controller=response,
        finding_controller=finding,
        input_func=lambda _prompt="": next(inputs),
        output_func=lambda _value: None,
    )
    controller.run()
    assert finding.calls == [("workspace:INV-001", "FIND-001")]
    assert response.calls == []
