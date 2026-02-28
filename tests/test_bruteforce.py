from soc_forge.cli import detect_bruteforce


def test_bruteforce_triggers_at_threshold():
    events = []
    # 8 failed logons from same IP within 10 minutes should trigger exactly once at threshold
    for i in range(8):
        events.append({
            "timestamp": f"2026-02-27T21:0{i}:00Z",
            "event_id": 4625,
            "username": "bob",
            "ip": "10.0.0.5",
            "host": "WIN10",
            "message": "failed logon",
        })

    alerts = detect_bruteforce(events, threshold=8, window_minutes=10)

    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "SOCF-001"
    assert a.severity.lower() in ("high", "critical")  # depending on later changes
    assert a.details["ip"] == "10.0.0.5"


def test_bruteforce_not_triggered_below_threshold():
    events = []
    for i in range(7):
        events.append({
            "timestamp": f"2026-02-27T21:0{i}:00Z",
            "event_id": 4625,
            "username": "bob",
            "ip": "10.0.0.5",
            "host": "WIN10",
        })

    alerts = detect_bruteforce(events, threshold=8, window_minutes=10)
    assert len(alerts) == 0
