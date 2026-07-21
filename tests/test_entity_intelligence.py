from soc_forge.core.entity_intelligence import build_entity_profile, get_entity_timeline
from soc_forge.core.investigation_graph import build_investigation_graph
from soc_forge.ui.investigation.attack_path import _attack_path_items, _render_node


def _case():
    return {
        "title": "Password Spray Case",
        "indicators": {"ips": ["203.0.113.10"], "users": ["alice"], "hosts": ["DC1"]},
        "alerts": [
            {
                "rule_id": "SOCF-010",
                "title": "Password spray suspected",
                "timestamp": "2026-07-16T16:07:28Z",
                "details": {"ip": "203.0.113.10", "username": "alice", "host": "DC1"},
                "mitre": [{"tactic": "Credential Access", "technique_id": "T1110.003"}],
            }
        ],
        "timeline": [
            {"timestamp": "2026-07-16T16:07:28Z", "title": "Password spray suspected", "rule_id": "SOCF-010"}
        ],
        "attack_path": [{"label": "203.0.113.10", "type": "ip"}, {"label": "alice", "type": "user"}],
    }


def test_build_entity_profile_matches_generated_case_alerts_and_relationships():
    case = _case()
    graph = build_investigation_graph(case)

    profile = build_entity_profile(graph, case, "alice")

    assert profile["id"] == "alice"
    assert profile["type"] == "user"
    assert profile["case_title"] == "Password Spray Case"
    assert profile["alerts"][0]["rule_id"] == "SOCF-010"
    assert profile["relationships"]
    assert profile["timeline"][0]["title"] == "Password spray suspected"


def test_get_entity_timeline_falls_back_to_title_and_rule_fields():
    case = _case()

    timeline = get_entity_timeline(case, "SOCF-010")

    assert timeline[0]["title"] == "Password spray suspected"


def test_attack_path_items_support_generated_attack_path():
    case = _case()

    items = _attack_path_items(case)

    assert items == case["attack_path"]
    assert _render_node(items[0]) == "[IP] 203.0.113.10"
