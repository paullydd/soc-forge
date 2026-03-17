from soc_forge.hunts.engine import run_hunts


def test_hunt_suspicious_command_detects_powershell_encoded():
    events = [
        {
            "timestamp": "2026-03-12T10:00:00",
            "host": "WIN10",
            "username": "bob",
            "command_line": "powershell -enc aGVsbG8=",
            "event_id": 4688,
        }
    ]

    findings = run_hunts(events)

    assert any(f.hunt_id == "HUNT-001" for f in findings)
    match = next(f for f in findings if f.hunt_id == "HUNT-001")
    assert match.entities["username"] == "bob"
    assert match.entities["host"] == "WIN10"
    assert "powershell -enc" in match.entities["command_line"].lower()