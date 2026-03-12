from soc_forge.rules.engine import load_rules, run_rules

def test_yaml_rule_privileged_group_change_matches_event(tmp_path):
    rules_yml = tmp_path / "rules.yml"
    rules_yml.write_text(
        """
version: 1
rules:
  - id: "SOCF-008"
    enabled: true
    title: "User added to privileged group"
    severity: "high"
    score: 75
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "eq"
          value: 4732
        - field: "message"
          op: "regex"
          value: '(?i)administrators|domain admins|enterprise admins|remote desktop users|backup operators'
""".strip(),
        encoding="utf-8",
    )

    events = [{
        "timestamp": "2026-03-11T10:20:00Z",
        "event_id": 4732,
        "actor": "admin1",
        "target_user": "tempuser",
        "group_name": "Administrators",
        "host": "WIN10",
        "message": "A member was added to a security-enabled local group. Group: Administrators",
    }]

    rules = load_rules([str(rules_yml)])
    alerts = run_rules(events, rules)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-008"
