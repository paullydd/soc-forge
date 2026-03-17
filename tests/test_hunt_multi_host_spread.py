from soc_forge.hunts.engine import run_hunts


def test_hunt_multi_host_spread_detects_user_touching_many_hosts():
    events = [
        {
            "timestamp": "2026-03-12T08:00:00",
            "host": "WIN10",
            "username": "alice",
            "src_ip": "10.0.0.20",
            "event_id": 4624,
        },
        {
            "timestamp": "2026-03-12T08:05:00",
            "host": "DC01",
            "username": "alice",
            "src_ip": "10.0.0.20",
            "event_id": 4624,
        },
        {
            "timestamp": "2026-03-12T08:10:00",
            "host": "FILE01",
            "username": "alice",
            "src_ip": "10.0.0.20",
            "event_id": 4624,
        },
    ]

    findings = run_hunts(events)

    assert any(f.hunt_id == "HUNT-003" for f in findings)
    match = next(f for f in findings if f.hunt_id == "HUNT-003")
    assert match.entities["username"] == "alice"
    assert match.entities["host_count"] == 3
    assert set(match.entities["hosts"]) == {"WIN10", "DC01", "FILE01"}