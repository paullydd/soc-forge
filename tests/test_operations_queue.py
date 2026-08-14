from dataclasses import FrozenInstanceError, replace

import pytest

from soc_forge.investigations.models import (
    InvestigationFinding,
    ResponseAction,
    ResponseActionTransition,
)
from soc_forge.investigations.operations_queue import (
    OperationsQueueService,
    UNCOVERED_FINDING_PRIORITY,
)
from soc_forge.investigations.repository import InvestigationRepository
from test_investigation_repository import build_investigation


NOW = "2026-08-14T12:00:00Z"
LATER = "2026-08-14T13:00:00Z"


def _finding(investigation_id="INV-A", finding_id="FIND-001", **changes):
    values = dict(
        finding_id=finding_id,
        investigation_id=investigation_id,
        title="Credential attack",
        conclusion="Password spraying was observed.",
        status="substantiated",
        confidence="high",
        author="alice",
        created_at=NOW,
        updated_at=NOW,
        decision_ids=("DECISION-001",),
    )
    values.update(changes)
    return InvestigationFinding(**values)


def _action(
    investigation_id="INV-A",
    action_id="ACT-001",
    finding_ids=("FIND-001",),
    status="proposed",
    priority="high",
    **changes,
):
    history = ()
    if status != "proposed":
        path = ["proposed"]
        if status in {"approved", "in_progress", "completed"}:
            path.append("approved")
        if status in {"in_progress", "completed"}:
            path.append("in_progress")
        if status == "completed":
            path.append("completed")
        if status == "dismissed":
            path.append("dismissed")
        history = tuple(
            ResponseActionTransition(
                transition_id=f"TRANS-{index}",
                from_status=source,
                to_status=target,
                author="alice",
                rationale=f"Move to {target}.",
                timestamp=LATER,
            )
            for index, (source, target) in enumerate(zip(path, path[1:]), 1)
        )
    values = dict(
        action_id=action_id,
        investigation_id=investigation_id,
        finding_ids=finding_ids,
        title="Review affected credentials",
        description="Review affected credential use.",
        action_type="credential_action",
        priority=priority,
        status=status,
        rationale="The Finding requires response work.",
        owner="identity-team",
        created_by="alice",
        created_at=NOW,
        updated_at=LATER if history else NOW,
        transition_history=history,
    )
    values.update(changes)
    return ResponseAction(**values)


def _save(repository, investigation_id="INV-A", *, findings=None, actions=()):
    findings = (_finding(investigation_id),) if findings is None else findings
    investigation = replace(
        build_investigation(investigation_id),
        findings=tuple(findings),
        response_actions=tuple(actions),
        handoff_manifest=None,
    )
    assert repository.save(investigation) == 1
    return investigation


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("proposed", "Response Action ACT-001 is proposed and awaiting analyst review."),
        ("approved", "Response Action ACT-001 is approved and ready for work."),
        ("in_progress", "Response Action ACT-001 is currently in progress."),
    ],
)
def test_open_response_actions_are_queued_with_lifecycle_reason(tmp_path, status, reason):
    repository = InvestigationRepository(tmp_path / "workspace")
    action = _action(status=status)
    _save(repository, actions=(action,))

    item = OperationsQueueService(repository).list_queue()[0]

    assert item.item_type == "response_action"
    assert item.source_status == status
    assert item.reason == reason
    assert item.priority == action.priority
    assert item.queue_item_id == "OPQ:INV-A:response_action:ACT-001"


@pytest.mark.parametrize("status", ["completed", "dismissed"])
def test_terminal_action_is_excluded_and_active_finding_becomes_uncovered(tmp_path, status):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status=status),))

    items = OperationsQueueService(repository).list_queue()

    assert [(item.item_type, item.source_id) for item in items] == [
        ("uncovered_finding", "FIND-001")
    ]


def test_multi_finding_action_produces_one_item_and_covers_all_findings(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    findings = (_finding(), _finding(finding_id="FIND-002"))
    _save(repository, findings=findings, actions=(_action(finding_ids=("FIND-001", "FIND-002")),))

    items = OperationsQueueService(repository).list_queue()

    assert len(items) == 1
    assert items[0].source_id == "ACT-001"


def test_superseded_finding_is_not_uncovered_but_linked_open_action_remains(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    historical = _finding(
        lifecycle_state="superseded",
        superseded_by_finding_id="FIND-002",
        supersession_reason="Refined conclusion.",
        supersession_author="alice",
        superseded_at=LATER,
    )
    replacement = _finding(finding_id="FIND-002", supersedes_finding_id="FIND-001")
    _save(repository, findings=(historical, replacement), actions=(_action(),))

    items = OperationsQueueService(repository).list_queue()

    assert [(item.item_type, item.source_id) for item in items] == [
        ("response_action", "ACT-001"),
        ("uncovered_finding", "FIND-002"),
    ]


@pytest.mark.parametrize("status", ["proposed", "approved", "in_progress"])
def test_open_action_prevents_separate_uncovered_finding_item(tmp_path, status):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status=status),))
    assert [item.item_type for item in OperationsQueueService(repository).list_queue()] == [
        "response_action"
    ]


def test_one_open_and_one_terminal_action_still_covers_finding(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    actions = (_action(action_id="ACT-OPEN"), _action(action_id="ACT-DONE", status="completed"))
    _save(repository, actions=actions)
    assert [item.source_id for item in OperationsQueueService(repository).list_queue()] == ["ACT-OPEN"]


def test_uncovered_finding_uses_neutral_priority_and_deterministic_identity(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    finding = _finding(confidence="low")
    _save(repository, findings=(finding,))

    first = OperationsQueueService(repository).list_queue()[0]
    second = OperationsQueueService(repository).list_queue()[0]

    assert first == second
    assert first.priority == UNCOVERED_FINDING_PRIORITY == "medium"
    assert first.queue_item_id == "OPQ:INV-A:uncovered_finding:FIND-001"
    assert first.reason == "Finding FIND-001 is active and has no open Response Action."


def test_transition_history_does_not_affect_action_queue_identity(tmp_path):
    first_repository = InvestigationRepository(tmp_path / "first")
    second_repository = InvestigationRepository(tmp_path / "second")
    _save(first_repository, actions=(_action(),))
    _save(second_repository, actions=(_action(status="approved"),))

    proposed = OperationsQueueService(first_repository).list_queue()[0]
    approved = OperationsQueueService(second_repository).list_queue()[0]

    assert proposed.queue_item_id == approved.queue_item_id
    assert proposed.source_status != approved.source_status


def test_cross_investigation_queue_is_ordered_scoped_and_collision_safe(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, "INV-B", actions=(_action("INV-B", priority="critical"),))
    _save(repository, "INV-A", actions=(_action("INV-A", priority="high"),))
    service = OperationsQueueService(repository)

    items = service.list_queue()

    assert [item.investigation_id for item in items] == ["INV-B", "INV-A"]
    assert len({item.queue_item_id for item in items}) == 2
    assert service.list_queue("INV-A") == (items[1],)


def test_deterministic_order_uses_priority_source_timestamp_and_ids(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    findings = (_finding(finding_id="FIND-002"), _finding(finding_id="FIND-001"))
    actions = (
        _action(action_id="ACT-LOW", finding_ids=("FIND-002",), priority="low"),
        _action(action_id="ACT-HIGH", finding_ids=("FIND-001",), priority="high"),
    )
    _save(repository, findings=findings, actions=actions)
    assert [item.source_id for item in OperationsQueueService(repository).list_queue()] == [
        "ACT-HIGH", "ACT-LOW"
    ]


def test_summary_counts_are_derived_from_items_and_empty_queue_is_zero(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    findings = (_finding(), _finding(finding_id="FIND-002"))
    actions = (_action(finding_ids=("FIND-001",), status="approved", priority="critical"),)
    _save(repository, findings=findings, actions=actions)
    service = OperationsQueueService(repository)

    summary = service.summarize()

    assert summary.total_items == 2
    assert (summary.critical, summary.high, summary.medium, summary.low) == (1, 0, 1, 0)
    assert (summary.response_actions, summary.uncovered_findings) == (1, 1)
    assert (summary.proposed, summary.approved, summary.in_progress) == (0, 1, 0)

    empty_repository = InvestigationRepository(tmp_path / "empty")
    assert OperationsQueueService(empty_repository).summarize().total_items == 0


def test_projection_retrieval_filtering_sorting_and_summary_are_byte_read_only(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    investigation = _save(repository, actions=(_action(),))
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    service = OperationsQueueService(repository)

    items = service.list_queue()
    assert service.get_queue_item(items[0].queue_item_id) == items[0]
    assert service.list_queue("INV-A") == items
    assert service.summarize(items).total_items == len(items)
    assert service.list_queue() == items

    assert path.read_bytes() == before
    stored = repository.load_record("INV-A")
    assert stored.revision == 1
    assert stored.investigation == investigation
    with pytest.raises(FrozenInstanceError):
        items[0].priority = "critical"


def test_queue_requires_no_analysis_snapshot_or_artifact_access(tmp_path, monkeypatch):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status="in_progress"),))
    monkeypatch.setattr(repository, "save", lambda *args, **kwargs: pytest.fail("queue wrote repository"))

    items = OperationsQueueService(repository).list_queue()

    assert len(items) == 1
    assert items[0].source_status == "in_progress"


def test_missing_queue_item_is_bounded_and_read_only(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(KeyError, match="was not found"):
        OperationsQueueService(repository).get_queue_item("OPQ:missing")
    assert path.read_bytes() == before
