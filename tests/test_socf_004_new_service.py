from pathlib import Path
from soc_forge.rules.engine import load_rules, run_rules


def test_socf_004_new_service_base_no_boost():
    rules = load_rules([str(Path("soc_forge/rules/SOCF-004.yml"))])

    events = [{
        "timestamp": "2026-02-27T22:20:00Z",
        "event_id": 7045,
        "host": "WIN10",
        "service_name": "UpdaterSvc",
        "image_path": r"C:\Windows\System32\svchost.exe",  # not suspicious
        "service_account": "LocalSystem",
        "message": "service installed",
    }]

    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-004"
    assert a["severity"] == "high"
    assert a["score"] == 80
    assert a["details"]["suspicious"] is False
    assert a["details"]["service_name"] == "UpdaterSvc"


def test_socf_004_new_service_suspicious_boost_and_bump():
    rules = load_rules([str(Path("soc_forge/rules/SOCF-004.yml"))])

    events = [{
        "timestamp": "2026-02-27T22:20:00Z",
        "event_id": 7045,
        "host": "WIN10",
        "service_name": "UpdaterSvc",
        "image_path": r"C:\Users\bob\AppData\Roaming\updater.exe",  # suspicious
        "service_account": "LocalSystem",
        "message": "service installed",
    }]

    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-004"
    assert a["severity"] == "critical"   # high -> critical
    assert a["score"] == 100             # 80 + 20
    assert a["details"]["suspicious"] is True