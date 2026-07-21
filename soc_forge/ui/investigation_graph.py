from soc_forge.ui.panels import section, divider, status_card, warning
from soc_forge.ui.investigation.attack_path import attack_path_panel


def graph_panel(graph, case=None):
    render_investigation_graph(graph)
    if case:
        divider()
        attack_path_panel(case)


def render_investigation_graph(graph):
    section("Investigation Graph")

    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])

    status_card(
        "Graph Summary",
        [
            ("Entities", len(nodes)),
            ("Relationships", len(edges)),
        ],
    )

    divider()

    if not nodes:
        warning("No entity relationships were found for this case.")
        return

    print("Entities")
    print("-" * 50)

    for entity_id, node in nodes.items():
        print(f"[{node.get('type', 'unknown').upper()}] {entity_id}")
        print(f"  Events: {node.get('events', 0)}")
        print(f"  Risk: {node.get('risk', 0)}")

        if node.get("techniques"):
            print(f"  Techniques: {', '.join(node['techniques'])}")

        print()

    divider()

    print("Relationships")
    print("-" * 50)

    if not edges:
        print("No relationships found.")
        return

    for edge in edges:
        print(
            f"{edge.get('source')} "
            f"--[{edge.get('relationship')}]--> "
            f"{edge.get('target')}"
        )

        if edge.get("evidence"):
            print(f"  Evidence: {edge['evidence']}")
        elif edge.get("event_type"):
            print(f"  Evidence: {edge['event_type']}")

        if edge.get("timestamp"):
            print(f"  Time: {edge['timestamp']}")

        print()
