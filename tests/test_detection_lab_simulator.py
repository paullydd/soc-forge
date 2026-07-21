from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.simulator.attack_simulator import generate_scenario


def test_detection_lab_scenario_triggers_process_detections_only_for_suspicious_events():
    events = generate_scenario("detection_lab")
    rules = load_rules(["soc_forge/rules"])
    alerts = run_rules(events, rules)
    rule_ids = [alert.get("rule_id") for alert in alerts]

    assert rule_ids.count("SOCF-011") == 1
    assert rule_ids.count("SOCF-012") == 1
    assert rule_ids.count("SOCF-013") == 1
    assert rule_ids.count("SOCF-014") == 1
    assert rule_ids.count("SOCF-015") == 1
    assert len(events) == 6
