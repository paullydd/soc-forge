import json
from pathlib import Path

import pytest

from soc_forge.rules.engine import load_rules, run_rules

FIXTURES = json.loads(Path("tests/fixtures/rule_fixtures.json").read_text())
FIXTURES += json.loads(Path("tests/fixtures/process_credential_rule_fixtures.json").read_text())
FIXTURES += json.loads(Path("tests/fixtures/lateral_persistence_collection_rule_fixtures.json").read_text())


@pytest.mark.parametrize("fixture", FIXTURES, ids=[f["rule_id"] for f in FIXTURES])
def test_rule_positive_and_negative_fixtures(fixture):
    rules = load_rules([str(Path("soc_forge/rules") / fixture["rule_file"])])

    match_events = [
        {**fixture["match"], **overrides}
        for overrides in fixture.get("match_overrides", [{}])
    ]
    positive = run_rules(match_events, rules)
    assert any(alert.get("rule_id") == fixture["rule_id"] for alert in positive)

    negative = run_rules([fixture["non_match"]], rules)
    assert not any(alert.get("rule_id") == fixture["rule_id"] for alert in negative)


def test_each_yaml_rule_has_a_detection_fixture():
    rule_ids = {rule.id for rule in load_rules(["soc_forge/rules"])}
    fixture_ids = {fixture["rule_id"] for fixture in FIXTURES}

    assert rule_ids == fixture_ids
