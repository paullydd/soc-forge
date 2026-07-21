from soc_forge.ui.panels import section, divider, status_card, warning
from soc_forge.ui.investigation.attack_path import attack_path_panel


def graph_overview_panel(graph, case=None):
    section("Entity Relationship Explorer")

    if case is not None:
        attack_path_panel(case)

    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])

    techniques = set()

    for node in nodes.values():
        for technique in node.get("techniques", []):
            techniques.add(technique)

    status_card(
        "Graph Summary",
        [
            ("Entities", len(nodes)),
            ("Relationships", len(edges)),
            ("Techniques", len(techniques)),
        ],
    )

    divider()

    if not nodes:
        warning("No entity relationships were found for this case.")