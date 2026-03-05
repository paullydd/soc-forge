from pathlib import Path

from soc_forge.rules.engine import load_rules, run_rules

def test_yaml_rule_socf_002_account_lockout_matches():
    # Load the YAML rule(s)
    rules_path = str(Path("soc_forge/rules/SOCF-002.yml"))
    rules = load_rules([rules_path])

    # Build a sample event that should match (event_id 4740)

    events = [
        {
            "timestamp": "2026-02-27T21:10:00Z",
            "event_id": 4740,
            "host": "DC01",
            "username": "bob",
            "ip": "10.0.0.5",
            "message": "Account locked out",
        }
    ]

    # Run it
    alerts = run_rules(events, rules)

    # Assert: exactly one alert, correct metadata
    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_id"] == "SOCF-002"
    assert a["severity"] == "medium"
    assert a["score"] == 40

    # Assert: details emitted correctly (at least two)
    assert a["details"]["host"] == "DC01"
    assert a["details"]["username"] == "bob"

def test_yaml_rule_socf_002_account_lockout_does_not_match_other_event_id():
    # Load rules
    rules_path = str(Path("soc_forge/rules/SOCF-002.yml"))
    rules = load_rules([rules_path])

    # Event that should NOT match
    events = [
        {
            "timestamp": "2026-02-27T21:10:00Z",
            "event_id": 4624,
            "host": "DC01",
            "username": "bob",
            "ip": "10.0.0.5",
            "message": "Logon success",
        }
    ]

    alerts = run_rules(events, rules)
    assert alerts == []
