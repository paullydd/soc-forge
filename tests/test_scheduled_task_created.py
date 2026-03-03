from soc_forge.cli import detect_scheduled_task_created

def test_scheduled_task_created_4698_triggers():
    events = [{
        "timestamp": "2026-02-27T22:25:00Z",
        "event_id": 4698,
        "host": "WIN10",
        "actor": "alice",
        "task_name": "\\Microsoft\\Windows\\Update\\Updater",
        "task_command": "powershell.exe -enc AAAA",
        "message": "task created",
    }]

    alerts = detect_scheduled_task_created(events, severity="high", score=75)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SOCF-005"
    assert alerts[0].severity == "high"
    assert alerts[0].score == 75
    assert alerts[0].details["task_name"] == "\\Microsoft\\Windows\\Update\\Updater"
