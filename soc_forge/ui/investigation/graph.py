from soc_forge.ui.panels import section, divider, status_card, warning


def graph_panel(graph):
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

    section("Entities")

    for entity_id, node in nodes.items():
        print(f"[{node['type'].upper()}] {entity_id}")
        print(f"  Events: {node['events']}")
        print(f"  Risk: {node['risk']}")

        techniques = node.get("techniques", [])
        if techniques:
            print(f"  Techniques: {', '.join(techniques)}")

        print()

    divider()

    section("Relationships")

    if not edges:
        warning("No relationships found.")
        return

    for edge in edges:
        print(
            f"{edge['source']} "
            f"--[{edge['relationship']}]--> "
            f"{edge['target']}"
        )

        if edge.get("evidence"):
            print(f"  Evidence: {edge['evidence']}")

        print()