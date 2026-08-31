from soc_forge.hunts.engine import run_hunts


def test_hunt_discovery_detects_systeminfo():
    events = [
        {
            "timestamp": "2026-03-12T10:00:00",
            "host": "WIN10",
            "username": "bob",
            "command_line": "systeminfo",
            "event_id": 4688,
        }
    ]

    findings = run_hunts(events)

    assert any(f.hunt_id == "HUNT-004" for f in findings)
    match = next(f for f in findings if f.hunt_id == "HUNT-004")
    assert match.entities["username"] == "bob"
    assert match.entities["host"] == "WIN10"
    assert match.category == "discovery"
    assert "T1082" in match.mitre


def test_hunt_discovery_covers_commands_outside_socf_024():
    # SOCF-024 only matches whoami / net user / net group / net localgroup.
    # This hunt should catch adjacent recon commands that rule misses.
    events = [
        {"host": "H1", "username": "u1", "command_line": "tasklist /v", "timestamp": "2026-03-12T10:00:00"},
        {"host": "H1", "username": "u1", "command_line": "nltest /domain_trusts", "timestamp": "2026-03-12T10:00:01"},
        {"host": "H1", "username": "u1", "command_line": "netstat -ano", "timestamp": "2026-03-12T10:00:02"},
        {"host": "H1", "username": "u1", "command_line": "ipconfig /all", "timestamp": "2026-03-12T10:00:03"},
        {"host": "H1", "username": "u1", "command_line": "net view \\\\FILESERVER", "timestamp": "2026-03-12T10:00:04"},
    ]

    findings = [f for f in run_hunts(events) if f.hunt_id == "HUNT-004"]

    assert len(findings) == 5
    all_techniques = {t for f in findings for t in f.mitre}
    assert {"T1057", "T1482", "T1049", "T1016", "T1135"}.issubset(all_techniques)


def test_hunt_discovery_does_not_match_unrelated_commands():
    events = [
        {"host": "H1", "username": "u1", "command_line": "notepad.exe report.txt"},
        {"host": "H1", "username": "u1", "command_line": "whoami"},
        {"host": "H1", "username": "u1", "command_line": "net localgroup administrators"},
    ]

    findings = [f for f in run_hunts(events) if f.hunt_id == "HUNT-004"]

    assert findings == []
