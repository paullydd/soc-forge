"""Every alternative in a rule's match/score_modifier `any` blocks must be
independently exercised by at least one fixture event.

This exists because SOCF-005 and SOCF-006 both shipped with a dead
alternative inside an `any` block (a double-escaped regex that could never
match) that went unnoticed for weeks: the base fixture happened to satisfy
a *different* alternative in the same `any`, so `test_each_yaml_rule_has_a_detection_fixture`
and the positive/negative fixture check both passed while the broken
branch sat untested. Per-rule fixture coverage proves a rule can fire at
all; it does not prove every alternative inside it actually works.

This test closes that gap for every rule, present and future: if a new
`any` alternative is added without fixture coverage that specifically
satisfies it, this test fails and names exactly which rule and branch is
unverified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

from soc_forge.rules.engine import _eval_node

RULES_DIR = Path("soc_forge/rules")
FIXTURE_FILES = (
    "tests/fixtures/rule_fixtures.json",
    "tests/fixtures/process_credential_rule_fixtures.json",
    "tests/fixtures/lateral_persistence_collection_rule_fixtures.json",
    "tests/fixtures/defense_impact_rule_fixtures.json",
)


def _fixtures_by_rule() -> Dict[str, List[Dict[str, Any]]]:
    by_rule: Dict[str, List[Dict[str, Any]]] = {}
    for path in FIXTURE_FILES:
        for fixture in json.loads(Path(path).read_text()):
            by_rule.setdefault(fixture["rule_id"], []).append(fixture)
    return by_rule


def _find_any_groups(node: Any, path: str) -> List[Tuple[str, List[dict]]]:
    """Recursively collect every `any` block in a match/when tree, with a
    human-readable path for failure messages."""
    groups: List[Tuple[str, List[dict]]] = []
    if isinstance(node, dict):
        if "any" in node:
            children = node["any"] or []
            groups.append((path, children))
            for index, child in enumerate(children):
                groups.extend(_find_any_groups(child, f"{path}.any[{index}]"))
        elif "all" in node:
            for index, child in enumerate(node["all"] or []):
                groups.extend(_find_any_groups(child, f"{path}.all[{index}]"))
    return groups


def _rule_any_groups(rule: dict) -> List[Tuple[str, str, List[dict]]]:
    groups = [
        (rule["id"], loc, children)
        for loc, children in _find_any_groups(rule.get("match", {}) or {}, "match")
    ]
    for mod_index, modifier in enumerate(rule.get("score_modifiers", []) or []):
        groups.extend(
            (rule["id"], f"score_modifiers[{mod_index}].when{loc[len('match'):]}", children)
            for loc, children in _find_any_groups(modifier.get("when", {}) or {}, "match")
        )
    return groups


def _load_all_rule_dicts() -> List[dict]:
    rules: List[dict] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        doc = yaml.safe_load(path.read_text()) or {}
        rules.extend(doc.get("rules", []) or [])
    return rules


def _events_for_rule(fixtures_by_rule: Dict[str, List[dict]], rule_id: str) -> List[dict]:
    events = []
    for fixture in fixtures_by_rule.get(rule_id, []):
        base = fixture["match"]
        for overrides in fixture.get("match_overrides", [{}]):
            events.append({**base, **overrides})
    return events


def _uncovered_cases():
    fixtures_by_rule = _fixtures_by_rule()
    cases = []
    for rule in _load_all_rule_dicts():
        events = _events_for_rule(fixtures_by_rule, rule["id"])
        for rule_id, loc, children in _rule_any_groups(rule):
            for index, child in enumerate(children):
                covered = any(
                    _safe_eval(child, event) for event in events
                )
                cases.append((rule_id, loc, index, covered))
    return cases


def _safe_eval(node: dict, event: dict) -> bool:
    try:
        return bool(_eval_node(node, event))
    except Exception:
        return False


_CASES = _uncovered_cases()


@pytest.mark.parametrize(
    "rule_id,location,index,covered",
    _CASES,
    ids=[f"{c[0]}:{c[1]}[{c[2]}]" for c in _CASES],
)
def test_every_any_branch_is_exercised_by_a_fixture(rule_id, location, index, covered):
    assert covered, (
        f"{rule_id} {location}[{index}] is never independently satisfied by any "
        f"fixture event (base match or match_overrides). Add a match_overrides "
        f"entry that isolates this alternative, or it may be silently dead."
    )
