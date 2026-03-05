from soc_forge.rules.engine import load_rules, run_rules

def test_yaml_rule_rdp_logon_type_10_matches_message(tmp_path):
    rules_yml = tmp_path / "rules.yml"
    rules_yml.write_text(
        """
version: 1
rules:
  - id: "SOCF-006"
    enabled: true
    title: "RDP logon detected (LogonType 10)"
    severity: "medium"
    score: 55
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "eq"
          value: 4624
        - field: "message"
          op: "regex"
          value: '(?i)logon\\s*type:\\s*10'
""".strip(),
        encoding="utf-8",
    )

    rules = load_rules([str(rules_yml)])
    events = [{
        "timestamp": "2026-02-27T22:15:00Z",
        "event_id": 4624,
        "username": "bob",
        "ip": "203.0.113.50",
        "host": "WIN10",
        "message": "An account was successfully logged on. Logon Type: 10",
    }]

    alerts = run_rules(events, rules)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-006"
