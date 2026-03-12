from soc_forge.rules.engine import load_rules, run_rules

def test_yaml_rule_audit_logs_cleared_matches_event_1102(tmp_path):
    rules_yml = tmp_path / "rules.yml"
    rules_yml.write_text(
        """
version: 1
rules:
  - id: "SOCF-009"
    enabled: true
    title: "Audit logs cleared"
    severity: "high"
    score: 80
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "eq"
          value: 1102
""".strip(),
        encoding="utf-8",
    )

    events = [{
        "timestamp": "2026-03-11T10:25:00Z",
        "event_id": 1102,
        "actor": "bob",
        "host": "WIN10",
        "message": "The audit log was cleared.",
    }]

    rules = load_rules([str(rules_yml)])
    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-009"
