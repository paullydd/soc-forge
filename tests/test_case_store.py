import json

from soc_forge.cases.store import filter_cases, load_cases_file, replace_case, save_cases_file, sort_cases


def test_save_and_load_cases_file_normalizes_lifecycle(tmp_path):
    path = tmp_path / "cases.json"

    save_cases_file([{"case_id": "CASE-001", "title": "Case", "risk_score": 250}], path)
    cases = load_cases_file(path)

    assert cases[0]["case_id"] == "CASE-001"
    assert cases[0]["owner"] == "Unassigned"
    assert cases[0]["status_history"][0]["status"] == "New"

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw[0]["updated_at"]


def test_filter_cases_by_status_risk_owner_and_notes():
    cases = [
        {"case_id": "CASE-001", "status": "New", "risk_score": 250, "owner": "pauly", "notes": ["note"]},
        {"case_id": "CASE-002", "status": "Closed", "risk_score": 80, "owner": "alice", "notes": []},
        {"case_id": "CASE-003", "status": "Investigating", "risk_score": 120, "owner": "pauly", "notes": []},
    ]

    assert [case["case_id"] for case in filter_cases(cases, "high_risk")] == ["CASE-001"]
    assert [case["case_id"] for case in filter_cases(cases, "assigned_to_me", current_owner="pauly")] == ["CASE-001", "CASE-003"]
    assert [case["case_id"] for case in filter_cases(cases, "has_notes")] == ["CASE-001"]
    assert [case["case_id"] for case in filter_cases(cases, "closed")] == ["CASE-002"]
    assert [case["case_id"] for case in filter_cases(cases, "open")] == ["CASE-001", "CASE-003"]


def test_replace_case_updates_by_case_id():
    cases = [{"case_id": "CASE-001", "status": "New"}]

    replace_case(cases, {"case_id": "CASE-001", "status": "Closed"})

    assert cases == [{"case_id": "CASE-001", "status": "Closed"}]

def test_sort_cases_by_risk_updated_status_owner_and_title():
    cases = [
        {"case_id": "CASE-002", "title": "Beta", "status": "Closed", "risk_score": 80, "owner": "zara", "updated_at": "2026-07-16T12:00:00Z"},
        {"case_id": "CASE-001", "title": "Alpha", "status": "New", "risk_score": 300, "owner": "alice", "updated_at": "2026-07-16T13:00:00Z"},
    ]

    assert [case["case_id"] for case in sort_cases(cases, "risk_desc")] == ["CASE-001", "CASE-002"]
    assert [case["case_id"] for case in sort_cases(cases, "updated_desc")] == ["CASE-001", "CASE-002"]
    assert [case["case_id"] for case in sort_cases(cases, "status")] == ["CASE-001", "CASE-002"]
    assert [case["case_id"] for case in sort_cases(cases, "owner")] == ["CASE-001", "CASE-002"]
    assert [case["case_id"] for case in sort_cases(cases, "title")] == ["CASE-001", "CASE-002"]

