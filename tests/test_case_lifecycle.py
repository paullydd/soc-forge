import json

from soc_forge.cases.lifecycle import (
    add_case_note,
    assign_case_owner,
    change_case_status,
    ensure_case_lifecycle,
)
from soc_forge.export.cases_export import export_cases_json
from soc_forge.models import normalize_case


def test_ensure_case_lifecycle_adds_defaults():
    case = {"case_id": "CASE-001", "title": "Suspicious activity"}

    ensure_case_lifecycle(case, now="2026-07-16T12:00:00Z")

    assert case["status"] == "New"
    assert case["owner"] == "Unassigned"
    assert case["created_at"] == "2026-07-16T12:00:00Z"
    assert case["updated_at"] == "2026-07-16T12:00:00Z"
    assert case["status_history"][0]["status"] == "New"
    assert case["status_history"][0]["reason"] == "Case created"


def test_change_status_appends_history_and_updates_header():
    case = {"status": "New", "header": {"status": "New"}}
    ensure_case_lifecycle(case, now="2026-07-16T12:00:00Z")

    change_case_status(
        case,
        "Investigating",
        changed_by="pauly",
        reason="Triage started",
        changed_at="2026-07-16T12:05:00Z",
    )

    assert case["status"] == "Investigating"
    assert case["updated_at"] == "2026-07-16T12:05:00Z"
    assert case["header"]["status"] == "Investigating"
    assert case["status_history"][-1] == {
        "status": "Investigating",
        "changed_at": "2026-07-16T12:05:00Z",
        "changed_by": "pauly",
        "reason": "Triage started",
    }


def test_assign_owner_and_add_note_are_structured():
    case = {"status": "New"}

    assign_case_owner(case, "Alice", changed_at="2026-07-16T12:10:00Z")
    add_case_note(case, "Blocked source IP", author="Alice", created_at="2026-07-16T12:11:00Z")

    assert case["owner"] == "Alice"
    assert case["notes"] == [
        {
            "text": "Blocked source IP",
            "author": "Alice",
            "created_at": "2026-07-16T12:11:00Z",
        }
    ]
    assert case["updated_at"] == "2026-07-16T12:11:00Z"


def test_normalize_case_preserves_evidence_and_lifecycle():
    case = normalize_case(
        {
            "correlation_id": "abc123",
            "header": {"title": "Case", "timestamp": "2026-07-16T12:00:00Z", "details": {}},
            "evidence": [{"timestamp": "2026-07-16T12:00:00Z", "rule_id": "SOCF-001", "title": "Alert"}],
        }
    )

    assert case["owner"] == "Unassigned"
    assert case["status_history"][0]["status"] == "New"
    assert case["evidence"] == [{"timestamp": "2026-07-16T12:00:00Z", "rule_id": "SOCF-001", "title": "Alert"}]


def test_export_cases_json_writes_lifecycle_fields(tmp_path):
    export_cases_json([{"case_id": "CASE-001", "title": "Case"}], tmp_path)

    data = json.loads((tmp_path / "cases.json").read_text(encoding="utf-8"))

    assert data[0]["case_id"] == "CASE-001"
    assert data[0]["owner"] == "Unassigned"
    assert data[0]["status_history"][0]["status"] == "New"
