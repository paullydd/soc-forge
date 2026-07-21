from soc_forge.report.html_report import build_attack_graph


def test_build_attack_graph_creates_nodes_and_edges():
    items = [
        {
            "title": "RDP logon detected",
            "rule_id": "SOCF-006",
            "host": "WIN10",
            "username": "bob",
            "details": {"src_ip": "203.0.113.50"},
        }
    ]

    graph = build_attack_graph(items)

    labels = {n["label"] for n in graph["nodes"]}
    assert "203.0.113.50" in labels
    assert "bob" in labels
    assert "WIN10" in labels
    assert "Remote Access" in labels

    assert len(graph["edges"]) >= 1

def test_report_attack_graph_extracts_ip_from_message():
    from soc_forge.report.html_report import build_attack_graph, build_attack_path

    graph = build_attack_graph([
        {
            "rule_id": "SOCF-010",
            "title": "Password spray suspected",
            "details": {
                "ip": None,
                "username": "alice",
                "host": "DC1",
                "message": "Source Network Address: 203.0.113.55",
            },
        }
    ])
    path = build_attack_path(graph)

    assert graph["nodes"][0]["label"] == "Password spray suspected" or any(node["label"] == "203.0.113.55" for node in graph["nodes"])
    assert path[0]["label"] == "203.0.113.55"

