from soc_forge.ui.panels import section, warning


def _render_node(node):
    if isinstance(node, dict):
        label = node.get("label") or node.get("title") or node.get("stage") or node.get("id") or "Unknown step"
        node_type = node.get("type")
        if node_type:
            return f"[{str(node_type).upper()}] {label}"
        return str(label)
    return str(node)


def _attack_path_items(case):
    if not isinstance(case, dict):
        return []

    attack_path = case.get("attack_path")
    if attack_path:
        return attack_path

    attack_graph = case.get("attack_graph", [])
    if isinstance(attack_graph, dict):
        return attack_graph.get("nodes", [])

    return attack_graph


def attack_path_panel(case):
    section("Attack Path")

    items = _attack_path_items(case)

    if not items:
        warning("No attack path is available for this case.")
        return

    for index, item in enumerate(items):
        print(_render_node(item))
        if index < len(items) - 1:
            print("  ->")
