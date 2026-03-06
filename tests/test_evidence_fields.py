from soc_forge.report.html_report import build_evidence_fields


def test_build_evidence_fields_extracts_key_values():
    alert = {
        "event_id": 4698,
        "host": "WIN10",
        "username": "bob",
        "details": {
            "src_ip": "203.0.113.50",
            "task_name": "Updater",
            "command": "cmd.exe /c whoami",
        },
    }

    fields = build_evidence_fields(alert)

    assert ("event_id", "4698") in fields
    assert ("host", "WIN10") in fields
    assert ("username", "bob") in fields
    assert ("ip", "203.0.113.50") in fields
    assert ("task_name", "Updater") in fields
    assert ("command", "cmd.exe /c whoami") in fields
