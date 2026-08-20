from dataclasses import FrozenInstanceError

import pytest

from soc_forge.investigations.operations_prioritization import OperationsPrioritizationService
from soc_forge.investigations.operations_queue import OperationsQueueService
from soc_forge.investigations.repository import InvestigationRepository
from test_operations_queue import _action, _finding, _save


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("in_progress", "Action is currently in progress"),
        ("approved", "Action is approved and ready to begin"),
        ("proposed", "Action is awaiting analyst approval"),
    ],
)
def test_response_action_priority_and_basis_are_explicit(tmp_path, status, expected):
    repository = InvestigationRepository(tmp_path / status)
    _save(repository, actions=(_action(status=status, priority="high"),))
    item = OperationsPrioritizationService(OperationsQueueService(repository)).prioritize()[0]
    assert item.priority_tier == "high"
    assert item.operational_state == status
    assert item.priority_basis == ("Response Action priority is HIGH", expected)


@pytest.mark.parametrize("confidence", ["low", "medium", "high"])
def test_uncovered_finding_uses_neutral_medium_not_confidence(tmp_path, confidence):
    repository = InvestigationRepository(tmp_path / confidence)
    _save(repository, findings=(_finding(confidence=confidence),))
    item = OperationsPrioritizationService(OperationsQueueService(repository)).prioritize()[0]
    assert item.priority_tier == "medium"
    assert item.operational_state == "uncovered_finding"
    assert item.priority_basis == (
        "Finding is ACTIVE",
        "No open Response Action addresses this Finding",
        "Uncovered Findings use neutral MEDIUM operational priority",
    )


def test_priority_and_operational_state_order_are_deterministic(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    cases = (
        ("INV-LOW", _action("INV-LOW", priority="low", status="in_progress")),
        ("INV-MED", _action("INV-MED", priority="medium", status="proposed")),
        ("INV-PROP", _action("INV-PROP", priority="high", status="proposed")),
        ("INV-APP", _action("INV-APP", priority="high", status="approved")),
        ("INV-PROG", _action("INV-PROG", priority="high", status="in_progress")),
        ("INV-CRIT", _action("INV-CRIT", priority="critical", status="proposed")),
    )
    for investigation_id, action in reversed(cases):
        _save(repository, investigation_id, actions=(action,))
    service = OperationsPrioritizationService(OperationsQueueService(repository))
    first = service.prioritize()
    assert [item.queue_item.investigation_id for item in first] == [
        "INV-CRIT", "INV-PROG", "INV-APP", "INV-PROP", "INV-MED", "INV-LOW",
    ]
    assert first == service.prioritize()
    assert service.summarize(first).top_item == first[0]
    assert service.summarize(first).top_priority == "critical"


def test_uncovered_finding_follows_proposed_at_same_medium_tier(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, "INV-FIND", findings=(_finding("INV-FIND"),))
    _save(repository, "INV-ACTION", actions=(_action("INV-ACTION", priority="medium"),))
    items = OperationsPrioritizationService(OperationsQueueService(repository)).prioritize()
    assert [item.operational_state for item in items] == ["proposed", "uncovered_finding"]


def test_timestamp_then_investigation_and_source_ids_are_stable_tiebreaks(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    common = "2026-08-19T12:00:00Z"
    _save(repository, "INV-Z", actions=(_action("INV-Z", action_id="ACT-LATE", updated_at="2026-08-20T12:00:00Z"),))
    _save(repository, "INV-B", actions=(_action("INV-B", action_id="ACT-002", updated_at=common),))
    _save(
        repository,
        "INV-A",
        actions=(
            _action("INV-A", action_id="ACT-002", updated_at=common),
            _action("INV-A", action_id="ACT-001", updated_at=common),
        ),
    )
    service = OperationsPrioritizationService(OperationsQueueService(repository))
    items = service.prioritize()
    assert [(item.queue_item.investigation_id, item.queue_item.source_id) for item in items] == [
        ("INV-A", "ACT-001"), ("INV-A", "ACT-002"),
        ("INV-B", "ACT-002"), ("INV-Z", "ACT-LATE"),
    ]
    assert service.prioritize(reversed(tuple(item.queue_item for item in items))) == items


def test_prioritization_is_immutable_read_only_and_has_no_score(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    investigation = _save(repository, actions=(_action(status="in_progress"),))
    record_path = next(repository.investigations_root.glob("*.json"))
    before = record_path.read_bytes()
    service = OperationsPrioritizationService(OperationsQueueService(repository))
    item = service.prioritize()[0]
    assert record_path.read_bytes() == before
    assert repository.load_record("INV-A").investigation == investigation
    assert not hasattr(item, "score")
    assert all("AI" not in basis and "generated" not in basis for basis in item.priority_basis)
    with pytest.raises(FrozenInstanceError):
        item.priority_tier = "critical"
