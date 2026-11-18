from soc_forge.cases.builder import build_case_iocs, build_cases


def test_case_iocs_include_actor_and_target_user():
    alerts = [
        {"rule_id": "SOCF-007", "correlation_id": "c1", "timestamp": "2026-09-01T11:38:54Z",
         "details": {"actor": "alice", "target_user": "svc-backup-admin", "host": "WS-ENG-01"}},
        {"rule_id": "SOCF-008", "correlation_id": "c1", "timestamp": "2026-09-01T11:39:54Z",
         "details": {"target_user": "svc-backup-admin", "host": "WS-ENG-01"}},
    ]
    iocs = build_case_iocs(alerts)
    assert iocs["users"] == ["alice", "svc-backup-admin"]
    assert iocs["hosts"] == ["WS-ENG-01"]


def test_case_iocs_ignore_placeholder_users():
    iocs = build_case_iocs([{"details": {"actor": "unknown", "target_user": "", "username": "N/A"}}])
    assert iocs["users"] == []


def test_built_case_lists_users_named_in_its_alerts():
    alerts = [{"rule_id": "SOCF-CORR-004", "correlation_id": "c2", "timestamp": "2026-09-01T11:39:54Z",
               "severity": "critical", "title": "New account followed by privileged group assignment",
               "details": {"target_user": "svc-backup-admin", "host": "WS-ENG-01"}}]
    cases = build_cases(alerts, "test")
    case = next(c for c in cases if "svc-backup-admin" in str(c))
    found = []
    def walk(o):
        if isinstance(o, dict):
            if "iocs" in o and isinstance(o["iocs"], dict):
                found.append(o["iocs"])
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    walk(case)
    assert found and all("svc-backup-admin" in i.get("users", []) for i in found)
