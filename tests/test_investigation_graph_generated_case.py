from soc_forge.core.investigation_graph import build_investigation_graph, summarize_graph
from soc_forge.investigations.replay import describe_timeline_event


def test_build_investigation_graph_supports_generated_case_shape():
    case = {
        "indicators": {
            "ips": ["203.0.113.10"],
            "hosts": ["DC1"],
            "users": ["alice"],
        },
        "alerts": [
            {
                "rule_id": "SOCF-010",
                "title": "Password spray suspected",
                "timestamp": "2026-07-16T16:07:28Z",
                "details": {"host": "DC1", "username": "alice", "ip": "203.0.113.10"},
                "mitre": [{"tactic": "Credential Access", "technique_id": "T1110.003"}],
            }
        ],
        "timeline": [{"timestamp": "2026-07-16T16:07:28Z", "title": "Password spray suspected"}],
    }

    graph = build_investigation_graph(case)
    summary = summarize_graph(graph)

    assert "203.0.113.10" in graph["nodes"]
    assert "alice" in graph["nodes"]
    assert "DC1" in graph["nodes"]
    assert graph["alert_count"] == 1
    assert graph["timeline_count"] == 1
    assert summary["total_edges"] >= 2


def test_describe_timeline_event_prefers_generated_title():
    event = {"timestamp": "2026-07-16T16:07:28Z", "rule_id": "SOCF-010", "title": "Password spray suspected"}

    assert describe_timeline_event(event) == "Password spray suspected"

def test_build_investigation_graph_extracts_ip_from_alert_message():
    case = {
        "indicators": {"ips": ["unknown"], "users": ["alice"], "hosts": ["DC1"]},
        "alerts": [
            {
                "rule_id": "SOCF-010",
                "title": "Password spray suspected",
                "details": {
                    "username": "alice",
                    "host": "DC1",
                    "ip": None,
                    "message": "Source Network Address: 203.0.113.55",
                },
            }
        ],
    }

    graph = build_investigation_graph(case)

    assert "unknown" not in graph["nodes"]
    assert "203.0.113.55" in graph["nodes"]



def test_investigation_graph_adds_relationship_metadata_and_primary_path():
    case = {
        "indicators": {"ips": ["203.0.113.10"], "users": ["alice"], "hosts": ["WS-01"], "scheduled_tasks": ["\\Updater"]},
        "alerts": [{"rule_id": "SOCF-017", "title": "Scheduled task", "details": {"host": "WS-01", "username": "alice", "ip": "203.0.113.10"}}],
    }

    graph = build_investigation_graph(case)

    assert graph["primary_path"] == ["203.0.113.10", "alice", "WS-01", "\\Updater"]
    assert all("confidence" in edge for edge in graph["edges"])
    assert any(edge["severity"] == "critical" for edge in graph["edges"])
