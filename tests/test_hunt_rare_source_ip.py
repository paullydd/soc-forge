from soc_forge.hunts.engine import run_hunts


def test_hunt_rare_source_ip_detects_new_ip_for_user():
    events = [
        {
            "timestamp": "2026-03-12T09:00:00",
            "host": "WIN10",
            "username": "bob",
            "src_ip": "10.0.0.5",
            "event_id": 4624,
        },
        {
            "timestamp": "2026-03-12T09:05:00",
            "host": "DC01",
            "username": "bob",
            "src_ip": "203.0.113.50",
            "event_id": 4624,
        },
    ]

    findings = run_hunts(events)

    assert any(f.hunt_id == "HUNT-002" for f in findings)
    match = next(f for f in findings if f.hunt_id == "HUNT-002")
    assert match.entities["username"] == "bob"
    assert match.entities["src_ip"] == "203.0.113.50"
    assert match.entities["baseline_ip"] == "10.0.0.5"