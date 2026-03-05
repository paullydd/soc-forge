from pathlib import Path

from soc_forge.rules.engine import load_rules, run_rules

def test_socf_003_new_admin():
    # Load YAML rules
    rules_path = str(Path("soc_forge/rules/SOCF-003.yml"))
    rules = load_rules([rules_path])

    # Build
    events = [
        {
            "timestamp": "2026-02-27T22:20:00Z",
            "event_id": 4728,
            "username": "bob",
            "group": "Administrators",
            "actor": "alice",
            "host": "WIN10",
            "message": "added to group",
        }
    ]

    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-003"
    assert a["severity"] == "high"
    assert a["score"] == 90

    assert a["details"]["host"] == "WIN10"
    assert a["details"]["username"] == "bob"
    assert a["details"]["group"] == "Administrators"
    assert a["details"]["actor"] == "alice"

def test_yaml_rule_socf_003_no_match():
    rules_path = str(Path("soc_forge/rules/SOCF-003.yml"))
    rules = load_rules([rules_path])

    events = [
        {
            "timestamp": "2026-02-27T22:20:00Z",
            "event_id": 4728,
            "username": "bob",
            "group": "Users",
            "actor": "alice",
            "host": "WIN10",
            "message": "added to group",
        }
    ]

    alerts = run_rules(events, rules)
    assert alerts == []