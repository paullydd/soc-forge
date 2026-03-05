from soc_forge.rules.coverage import mitre_coverage_by_tactic
from soc_forge.rules.engine import Rule


def test_mitre_coverage_counts_unique_tactics_per_rule():
    rules = [
        Rule(
            id="A", enabled=True, title="A", severity="low", score=1,
            mitre=[{"tactic": "Persistence"}, {"tactic": "Persistence"}],  # dup tactic in same rule
            match={"all": [{"field": "event_id", "op": "eq", "value": 1}]},
            emit={}, score_modifiers=[],
            description="", author="", created="", logsource="", tags=[]
        ),
        Rule(
            id="B", enabled=True, title="B", severity="low", score=1,
            mitre=[{"tactic": "Persistence"}, {"tactic": "Lateral Movement"}],
            match={"all": [{"field": "event_id", "op": "eq", "value": 2}]},
            emit={}, score_modifiers=[],
            description="", author="", created="", logsource="", tags=[]
        ),
    ]

    rows = dict(mitre_coverage_by_tactic(rules))
    assert rows["Persistence"] == 2
    assert rows["Lateral Movement"] == 1
