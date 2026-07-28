from datetime import datetime, timedelta, timezone

from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.simulator.attack_simulator import generate_scenario


def _event(offset_minutes: int, username: str, ip: str = "203.0.113.55") -> dict:
    timestamp = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=offset_minutes)
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "event_id": 4625,
        "host": "DC1",
        "username": username,
        "ip": ip,
        "message": "An account failed to log on.",
    }


def _run(events: list[dict]) -> list[dict]:
    rules = load_rules(["soc_forge/rules/SOCF-010.yml"])
    return run_rules(events, rules)


def test_socf_010_password_spray_fires():
    alerts = _run(generate_scenario("password_spray"))

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-010"


def test_socf_010_requires_five_distinct_usernames():
    assert _run([_event(i, f"user-{i}") for i in range(4)]) == []
    assert _run([_event(i, "alice") for i in range(5)]) == []


def test_socf_010_groups_failures_by_source_ip():
    events = [
        _event(0, "alice", "203.0.113.10"),
        _event(1, "bob", "203.0.113.10"),
        _event(2, "carol", "203.0.113.10"),
        _event(3, "dave", "203.0.113.20"),
        _event(4, "erin", "203.0.113.20"),
    ]

    assert _run(events) == []


def test_socf_010_enforces_sliding_window():
    events = [_event(i * 3, username) for i, username in enumerate(("alice", "bob", "carol", "dave", "erin"))]

    assert _run(events) == []


def test_socf_010_emits_once_at_threshold():
    events = [_event(i, username) for i, username in enumerate(("alice", "bob", "carol", "dave", "erin", "frank"))]

    alerts = _run(events)

    assert len(alerts) == 1
    assert alerts[0]["timestamp"] == events[4]["timestamp"]
    assert alerts[0]["details"]["ip"] == "203.0.113.55"
    assert alerts[0]["details"]["distinct_username_count"] == 5
    assert alerts[0]["details"]["window_minutes"] == 10
