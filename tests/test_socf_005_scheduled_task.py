from pathlib import Path
from soc_forge.rules.engine import load_rules, run_rules


def test_socf_005_scheduled_task_base_no_boost():
    rules = load_rules([str(Path("soc_forge/rules/SOCF-005.yml"))])

    events = [{
        "timestamp": "2026-02-27T22:25:00Z",
        "event_id": 4698,
        "host": "WIN10",
        "actor": "alice",
        "task_name": r"\Microsoft\Windows\Update\Updater",
        "task_command": r"C:\Windows\System32\schtasks.exe /Create /TN Updater",
        "message": "task created",
    }]

    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-005"
    assert a["severity"] == "high"
    assert a["score"] == 75
    assert a["details"]["suspicious"] is False
    assert a["details"]["task_name"] == r"\Microsoft\Windows\Update\Updater"


def test_socf_005_scheduled_task_suspicious_boost_and_bump():
    rules = load_rules([str(Path("soc_forge/rules/SOCF-005.yml"))])

    events = [{
        "timestamp": "2026-02-27T22:25:00Z",
        "event_id": 4698,
        "host": "WIN10",
        "actor": "alice",
        "task_name": r"\Updater",
        "task_command": "powershell.exe -enc AAAA",
        "message": "task created",
    }]

    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-005"
    assert a["severity"] == "critical"  # high -> critical
    assert a["score"] == 95             # 75 + 20
    assert a["details"]["suspicious"] is True