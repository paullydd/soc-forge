from soc_forge.cli import detect_suspicious_rdp_logon

def test_rdp_logon_type_10_triggers():
    events = [{
        "timestamp": "2026-02-27T22:15:00Z",
        "event_id": 4624,
        "username": "bob",
        "ip": "203.0.113.50",
        "host": "WIN10",
        "logon_type": 10,
        "message": "successful logon (RDP)"
    }]
    alerts = detect_suspicious_rdp_logon(events, logon_type=10, severity="medium", score=55)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SOCF-006"

def test_non_rdp_logon_type_does_not_trigger():
    events = [{
        "timestamp": "2026-02-27T22:15:00Z",
        "event_id": 4624,
        "username": "bob",
        "ip": "203.0.113.50",
        "host": "WIN10",
        "logon_type": 2,
        "message": "successful console logon"
    }]
    alerts = detect_suspicious_rdp_logon(events, logon_type=10, severity="medium", score=55)
    assert len(alerts) == 0
