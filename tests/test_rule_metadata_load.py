from pathlib import Path
from soc_forge.rules.engine import load_rules, run_rules

def test_rule_metadata_is_loaded_and_emitted(tmp_path: Path):
    yml = tmp_path / "meta.yml"
    yml.write_text(
        """
version: 1
rules:
  - id: "META-1"
    enabled: true
    title: "Meta rule"
    description: "Detects something"
    author: "Paul"
    created: "2026-03-04"
    logsource: "windows-security"
    tags: ["windows", "test"]
    severity: "low"
    score: 1
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "eq"
          value: 1
""".strip(),
        encoding="utf-8",
    )

    rules = load_rules([str(yml)])
    alerts = run_rules([{"timestamp":"t","event_id":1}], rules)

    assert len(alerts) == 1
    rule_meta = alerts[0]["rule"]
    assert rule_meta["author"] == "Paul"
    assert "windows" in rule_meta["tags"]
