from soc_forge.ui.panels import menu_option, footer


def investigation_graph_menu():
    menu_option("1", "View Entity Profiles")
    menu_option("2", "Relationship Explorer")
    menu_option("3", "View Attack Path")
    menu_option("0", "Back")

    footer()
    return input("\nSelect option: ").strip()