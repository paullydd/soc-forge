from pathlib import Path
import pytest

from soc_forge.rules.engine import load_rules


def test_rule_validation_rejects_bad_op(tmp_path: Path):
    bad = tmp_path / "bad.yml"
    bad.write_text(
        """
version: 1
rules:
  - id: "BAD-1"
    enabled: true
    title: "Bad op"
    severity: "medium"
    score: 10
    mitre: []
    match:
      all:
        - field: "event_id"
          op: "equals"
          value: 4624
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as e:
        load_rules([str(bad)])

    assert "unsupported op" in str(e.value).lower()
