from pathlib import Path
from soc_forge.rules.engine import load_rules

def test_all_rules_load():
    rules_dir = Path("soc_forge/rules")
    rules = load_rules([str(rules_dir)])
    assert len(rules) > 0
