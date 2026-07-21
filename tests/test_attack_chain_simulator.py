from soc_forge.correlate.rules import correlate_alerts
from soc_forge.core.investigation_graph import build_investigation_graph, summarize_graph
from soc_forge.report.html_report import build_cases
from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.simulator.attack_simulator import generate_scenario


def test_generate_attack_chain_contains_multistage_events():
    events = generate_scenario("attack_chain")
    event_ids = [event.get("event_id") for event in events]

    assert event_ids == [4624, 4698, 4720, 4732, 1102]
    assert {event.get("host") for event in events} == {"WS-ENG-01"}
    assert {event.get("src_ip") for event in events} == {"198.51.100.77"}


def test_attack_chain_triggers_rules_and_correlations():
    events = generate_scenario("attack_chain")
    rules = load_rules(["soc_forge/rules"])
    alerts = run_rules(events, rules)
    correlated = correlate_alerts(alerts)
    rule_ids = {alert.get("rule_id") for alert in correlated}

    assert {"SOCF-005", "SOCF-006", "SOCF-007", "SOCF-008", "SOCF-009"}.issubset(rule_ids)
    assert {"SOCF-CORR-002", "SOCF-CORR-003", "SOCF-CORR-004", "SOCF-CORR-005"}.issubset(rule_ids)


def test_attack_chain_builds_rich_case_graph():
    events = generate_scenario("attack_chain")
    rules = load_rules(["soc_forge/rules"])
    alerts = correlate_alerts(run_rules(events, rules))
    cases = build_cases(alerts, "attack_chain_events.jsonl")

    case = max(cases, key=lambda item: len(item.get("alerts", [])))
    graph = build_investigation_graph(case)
    summary = summarize_graph(graph)

    assert summary["total_nodes"] >= 4
    assert summary["total_edges"] >= 3
    assert "198.51.100.77" in graph["nodes"]
    assert "WS-ENG-01" in graph["nodes"]
    assert "svc-backup-admin" in graph["nodes"]
