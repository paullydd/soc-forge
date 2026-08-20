from dataclasses import FrozenInstanceError

import pytest

from soc_forge.investigations.operational_summary import OperationalSummaryService
from soc_forge.investigations.operations_prioritization import OperationsPrioritizationService
from soc_forge.investigations.operations_queue import OperationsQueueService
from soc_forge.investigations.repository import InvestigationRepository
from test_operations_queue import _action, _finding, _save


def _service(repository):
    return OperationalSummaryService(
        OperationsPrioritizationService(OperationsQueueService(repository))
    )


def test_empty_operational_summary_is_deterministic(tmp_path):
    service = _service(InvestigationRepository(tmp_path / "workspace"))
    first = service.summarize()
    assert first == service.summarize()
    assert first.total_attention_items == 0
    assert first.investigations_represented == 0
    assert first.top_item is None
    assert first.top_items == ()
    assert first.top_priority is first.top_reason is None


@pytest.mark.parametrize("status", ["proposed", "approved", "in_progress"])
def test_one_action_summary_counts_only_its_nonterminal_state(tmp_path, status):
    repository = InvestigationRepository(tmp_path / status)
    _save(repository, actions=(_action(status=status, priority="high"),))
    summary = _service(repository).summarize()
    assert summary.total_attention_items == 1
    assert summary.response_action_count == 1
    assert summary.uncovered_finding_count == 0
    assert (summary.proposed_count, summary.approved_count, summary.in_progress_count) == (
        int(status == "proposed"), int(status == "approved"), int(status == "in_progress")
    )
    assert summary.investigations_represented == 1


def test_uncovered_finding_summary_uses_queue_membership(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, findings=(_finding(confidence="high"),))
    summary = _service(repository).summarize()
    assert summary.uncovered_finding_count == 1
    assert summary.response_action_count == 0
    assert summary.medium_count == 1
    assert summary.top_source_type == "uncovered_finding"


def test_mixed_summary_counts_investigations_and_preserves_top_three(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    cases = (
        ("INV-CRIT", "proposed", "critical"),
        ("INV-PROG", "in_progress", "high"),
        ("INV-APP", "approved", "high"),
        ("INV-LOW", "proposed", "low"),
    )
    for investigation_id, status, priority in reversed(cases):
        _save(repository, investigation_id, actions=(
            _action(investigation_id, status=status, priority=priority),
        ))
    _save(repository, "INV-FIND", findings=(_finding("INV-FIND"),))
    service = _service(repository)

    summary = service.summarize()

    assert summary.total_attention_items == 5
    assert summary.investigations_represented == 5
    assert (summary.critical_count, summary.high_count, summary.medium_count, summary.low_count) == (1, 2, 1, 1)
    assert (summary.response_action_count, summary.uncovered_finding_count) == (4, 1)
    assert (summary.proposed_count, summary.approved_count, summary.in_progress_count) == (2, 1, 1)
    assert summary.top_investigation_id == "INV-CRIT"
    assert summary.top_source_id == "ACT-001"
    assert summary.top_priority == "critical"
    assert summary.top_reason == summary.top_item.queue_item.reason
    assert [item.queue_item.investigation_id for item in summary.top_items] == [
        "INV-CRIT", "INV-PROG", "INV-APP",
    ]
    assert summary == service.summarize()


def test_summary_consumes_supplied_prioritization_without_rebuilding(tmp_path, monkeypatch):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status="approved"),))
    prioritization = OperationsPrioritizationService(OperationsQueueService(repository))
    items = prioritization.prioritize()
    monkeypatch.setattr(
        prioritization, "prioritize", lambda: pytest.fail("summary rebuilt queue")
    )
    summary = OperationalSummaryService(prioritization).summarize(items)
    assert summary.top_item == items[0]
    assert summary.total_attention_items == 1


def test_summary_is_frozen_and_repository_byte_read_only(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status="in_progress"),))
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    summary = _service(repository).summarize()
    assert path.read_bytes() == before
    assert repository.load_record("INV-A").revision == 1
    with pytest.raises(FrozenInstanceError):
        summary.total_attention_items = 99
