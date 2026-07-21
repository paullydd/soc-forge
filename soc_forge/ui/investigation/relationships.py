from soc_forge.ui.panels import section, warning, divider


def _short(value, limit=110):
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def relationships_panel(graph):
    section("Relationship Explorer")

    edges = graph.get("edges", [])

    if not edges:
        warning("No relationships found.")
        return

    for index, edge in enumerate(edges, start=1):
        print(f"{index}. {edge['source']} --{edge['relationship']}--> {edge['target']}")
        if edge.get("evidence"):
            print(f"   Evidence: {_short(edge['evidence'])}")

    choice = input("\nOpen relationship number for details, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or not (1 <= int(choice) <= len(edges)):
        warning("Invalid relationship selection.")
        return

    edge = edges[int(choice) - 1]
    divider()
    print(f"Source:       {edge.get('source')}")
    print(f"Relationship: {edge.get('relationship')}")
    print(f"Target:       {edge.get('target')}")

    if edge.get("evidence"):
        print("\nEvidence")
        print("-" * 60)
        print(edge["evidence"])
    else:
        warning("No evidence attached to this relationship.")
