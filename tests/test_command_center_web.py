from pathlib import Path


ROOT = Path(__file__).parents[1]
STATIC = ROOT / "soc_forge" / "web" / "static"


def sources():
    return {
        name: (STATIC / name).read_text()
        for name in ("index.html", "app.js", "command_center.js", "styles.css")
    }


def test_command_center_has_required_information_hierarchy_and_secondary_demo():
    source = sources()
    index = source["index.html"]
    for heading in (
        "Operational status", "Current analyst workload", "Top Attention",
        "Recent Activity", "Security Activity", "Demo / Lab controls",
    ):
        assert heading in index
    assert index.index("Top Attention") < index.index("Recent Activity")
    assert index.index("Recent Activity") < index.index("Security Activity")
    assert '<details class="demo-lab panel">' in index
    assert "Generate Scenario" in index
    assert "Start Guided Demo" in index
    topbar = index[index.index('<header class="topbar">'):index.index('</header>')]
    assert "scenarioSelect" not in topbar
    assert "runScenarioButton" not in topbar
    assert "startDemoButton" not in topbar


def test_operational_metrics_use_existing_authoritative_payloads_and_destinations():
    command = sources()["command_center.js"]
    for label in (
        "Investigations", "High / Critical Attention", "Open Response Actions",
        "Alerts", "Hunts",
    ):
        assert label in command
    assert "state.investigations.length" in command
    assert "operations.critical_count" in command
    assert "operations.high_count" in command
    assert "operations.response_action_count" in command
    assert "summary.alert_count" in command
    assert "summary.hunt_count" in command
    assert "Avg Quality" not in command
    assert "commandMetric(label, value, destination)" in command


def test_top_attention_reuses_operations_queue_order_and_is_bounded():
    source = sources()
    command = source["command_center.js"]
    app = source["app.js"]
    assert "state.operationsQueue?.operational_summary?.top_items" in command
    assert ".top_items.slice(0, 4)" in command
    assert "openOperationsSource(item)" in command
    assert "priority_basis[0]" in command
    assert "caseRisk(" not in command
    assert "risk_score" not in command
    assert "top_case_id" not in command
    assert "fetch('/api/operations-queue', { cache: 'no-store' })" in app


def test_recent_activity_is_bounded_reverse_chronological_and_attributed():
    command = sources()["command_center.js"]
    assert "state.workspace?.alerts" in command
    assert "state.investigations" in command
    assert "kind: 'Machine alert'" in command
    assert "kind: 'Investigation'" in command
    assert ".sort((left, right) => String(right.timestamp).localeCompare(String(left.timestamp))" in command
    assert ".slice(0, 7)" in command
    assert "openInvestigation(item.investigationId)" in command
    assert "No current timestamped activity is available." in command


def test_supporting_activity_keeps_attack_observation_distinct_from_coverage():
    command = sources()["command_center.js"]
    assert "Top observed ATT&CK tactics" in command
    assert "Observed ATT&CK activity is not Detection Coverage." in command
    assert "summary.tactic_counts.slice(0, 5)" in command
    assert "enabled_rule_count" in command
    assert "percentage" not in command.lower()
    assert "completeness" not in command.lower()


def test_empty_machine_context_does_not_invent_offline_or_zero_semantics():
    command = sources()["command_center.js"]
    assert "No current generated machine-analysis artifacts are available." in command
    assert "Durable Investigation and Operations state remains separate." in command
    assert "OFFLINE" not in command
    assert "Machine analysis context is unavailable in OFFLINE mode." not in command


def test_command_center_uses_safe_dom_and_no_browser_authoritative_state():
    command = sources()["command_center.js"]
    assert "createElement" in command
    assert "textContent" in command
    assert "replaceChildren" in command
    assert "innerHTML" not in command
    assert "localStorage" not in command
    assert "sessionStorage" not in command
    assert "fetch(" not in command


def test_command_center_responsive_contract_and_secondary_search():
    source = sources()
    index = source["index.html"]
    styles = source["styles.css"]
    assert 'placeholder="Filter current analysis"' in index
    assert 'aria-label="Filter cases, alerts, and hunts"' in index
    assert ".command-primary-grid" in styles
    assert "grid-template-columns: minmax(0, 1.65fr) minmax(320px, .85fr)" in styles
    assert "@media (max-width: 1100px)" in styles
    assert "@media (max-width: 820px)" in styles
    assert ".command-primary-grid { grid-template-columns: 1fr; }" in styles
    assert ".compact-search" in styles
