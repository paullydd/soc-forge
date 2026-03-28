from soc_forge.simulator.attack_simulator import generate_scenario
from soc_forge.rules.engine import load_rules, run_rules


def test_socf_010_password_spray_fires():
    events = generate_scenario("password_spray")
    rules = load_rules(["soc_forge/rules"])
    alerts = run_rules(events, rules)

    assert any(a.get("rule_id") == "SOCF-010" for a in alerts)
