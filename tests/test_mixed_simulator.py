from soc_forge.simulator.attack_simulator import generate_scenario
from soc_forge.rules.engine import load_rules, run_rules


def test_generate_mixed_scenario_returns_events():
    events = generate_scenario("mixed")
    assert len(events) > 10


def test_generate_mixed_scenario_contains_success_and_failures():
    events = generate_scenario("mixed")
    event_ids = {e.get("event_id") for e in events}
    assert 4624 in event_ids
    assert 4625 in event_ids


def test_mixed_scenario_triggers_socf_010():
    events = generate_scenario("mixed")
    rules = load_rules(["soc_forge/rules"])
    alerts = run_rules(events, rules)

    assert any(a.get("rule_id") == "SOCF-010" for a in alerts)
