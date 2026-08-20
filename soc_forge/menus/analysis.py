from soc_forge.menus.architecture import show_architecture_notice
from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


ANALYSIS_DESTINATIONS = {
    "1": (
        "Threat Activity Overview",
        "Cross-source threat activity analysis is not implemented in this slice.",
        ("detection activity", "investigation activity", "ATT&CK activity"),
    ),
    "2": (
        "Entity Explorer",
        "Cross-investigation entity analysis is not implemented in this slice.",
        ("host", "user", "IP", "process", "cross-investigation relationships"),
    ),
    "3": (
        "ATT&CK Activity",
        "Cross-investigation ATT&CK activity analysis is not implemented in this slice.",
        ("tactics", "techniques", "observed activity"),
    ),
    "4": (
        "Cross-Investigation Analysis",
        "Cross-investigation comparison is not implemented in this slice.",
        ("shared entities", "shared behaviors", "investigation relationships"),
    ),
    "5": (
        "Temporal Analysis",
        "Cross-investigation temporal analysis is not implemented in this slice.",
        ("event sequences", "time windows", "activity patterns"),
    ),
    "6": (
        "Hunt Workspace",
        "The v3.5 Hunt Workspace is not implemented in this slice.",
        ("hunt questions", "search scope", "analyst findings"),
    ),
}


def analysis_menu(pause, attack_stories, attack_graph_viewer):
    while True:
        begin_screen("ANALYSIS")
        print(render_breadcrumb(("SOC-FORGE", "ANALYSIS")))
        menu_group("SECURITY ANALYSIS")
        for number, (title, _summary, _scope) in ANALYSIS_DESTINATIONS.items():
            menu_option(number, title)
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()
        if choice in ANALYSIS_DESTINATIONS:
            title, summary, scope = ANALYSIS_DESTINATIONS[choice]
            show_architecture_notice("ANALYSIS", title, summary, pause, scope)
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()
