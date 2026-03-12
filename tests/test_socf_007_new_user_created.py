from soc_forge.rules.engine import load_rules, run_rules

def test_yaml_rule_new_user_created_matches_event_4720(tmp_path):
    rules_yml = tmp_path / "rules.yml"
    rules_yml.write_text(
        """
version: 1
rules:
  - id: "SOCF-007"
    enabled: true
    title: "New user account created"
    severity: "medium"
    score: 55
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "eq"
          value: 4720
""".strip(),
        encoding="utf-8",
    )

    events = [{
        "timestamp": "2026-03-11T10:15:00Z",
        "event_id": 4720,
        "actor": "admin1",
        "target_user": "tempuser",
        "host": "WIN10",
        "message": "A user account was created.",
    }]

    rules = load_rules([str(rules_yml)])
    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-007"
