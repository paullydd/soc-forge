from soc_forge.ui.panels import section, warning, menu_option, footer


def entity_browser_panel(graph):
    section("Entity Browser")

    nodes = graph.get("nodes", {})

    if not nodes:
        warning("No entities found.")
        return None

    entity_ids = list(nodes.keys())

    for index, entity_id in enumerate(entity_ids, start=1):
        node = nodes[entity_id]
        menu_option(str(index), f"{entity_id} ({node['type']})")

    menu_option("0", "Back")
    footer()

    choice = input("\nSelect entity: ").strip()

    if choice == "0":
        return None

    if not choice.isdigit():
        return None

    index = int(choice) - 1

    if index < 0 or index >= len(entity_ids):
        return None

    return entity_ids[index]