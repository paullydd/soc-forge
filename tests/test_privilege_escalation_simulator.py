# tests/test_privilege_escalation_simulator.py

from soc_forge.simulator.attack_simulator import generate_scenario
from soc_forge.rules.engine import load_rules, run_rules

def test_generate_privilege_escalation_returns_events():
    events = generate_scenario("privilege_escalation")
    assert len(events) == 2


def test_generate_privilege_escalation_contains_group_change():
    events = generate_scenario("privilege_escalation")
    assert any(e.get("event_id") == 4732 for e in events)


def test_generate_privilege_escalation_contains_success_logon():
    events = generate_scenario("privilege_escalation")
    assert any(e.get("event_id") == 4624 for e in events)


def test_generate_privilege_escalation_targets_administrators():
    events = generate_scenario("privilege_escalation")
    group_events = [e for e in events if e.get("event_id") == 4732]
    assert len(group_events) == 1
    assert group_events[0].get("group_name") == "Administrators"

def test_privilege_escalation_triggers_socf_008():
    events = generate_scenario("privilege_escalation")
    rules = load_rules(["soc_forge/rules"])
    alerts = run_rules(events, rules)

    matching = [a for a in alerts if a.get("rule_id") == "SOCF-008"]

    assert len(matching) >= 1
    alert = matching[0]
    assert alert.get("details", {}).get("host") == "WS-01"
