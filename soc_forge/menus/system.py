from soc_forge import __version__
from soc_forge.menus.architecture import show_architecture_notice
from soc_forge.ui.panels import error, info_panel, menu_group, menu_option
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


SYSTEM_DESTINATIONS = {
    "1": (
        "Platform Status",
        "Live Platform Status is deferred because no shared authoritative readiness "
        "source exists yet.",
        ("runtime readiness", "service availability", "asset availability"),
    ),
    "2": (
        "Configuration",
        "Configuration inspection and editing are not implemented in this slice.",
        ("effective configuration", "configuration sources", "read-only validation"),
    ),
    "3": (
        "Rule / Asset Health",
        "Rule and asset health inspection is not implemented in this slice.",
        ("rule availability", "static assets", "validation results"),
    ),
    "4": (
        "Repository & Storage",
        "Repository and storage administration are not implemented in this slice.",
        ("repository location", "storage availability", "schema information"),
    ),
    "5": (
        "Environment",
        "Environment inspection is not implemented in this slice.",
        ("Python runtime", "operating system", "terminal capabilities"),
    ),
}


def system_menu(clear_screen, pause, create_demo_case=None):
    while True:
        begin_screen("SYSTEM")
        print(render_breadcrumb(("SOC-FORGE", "SYSTEM")))
        menu_group("SYSTEM")
        for number, (title, _summary, _scope) in SYSTEM_DESTINATIONS.items():
            menu_option(number, title)
        menu_option("6", "About SOC-Forge")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()
        if choice in SYSTEM_DESTINATIONS:
            title, summary, scope = SYSTEM_DESTINATIONS[choice]
            show_architecture_notice("SYSTEM", title, summary, pause, scope)
        elif choice == "6":
            show_about()
            pause()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()


def show_about():
    info_panel(
        "ABOUT SOC-FORGE",
        [
            ("Platform", "Security Operations Platform"),
            ("Version", __version__),
            ("Interfaces", "Terminal and local web"),
            ("Detection", "Rules, correlation, alerts, simulation"),
            ("Investigation", "Evidence, reasoning, Findings, Response Actions"),
            ("Operations", "Read-only queue and deterministic prioritization"),
            ("Delivery", "Summaries, reports, and Investigation Handoff"),
            ("Execution", "No automated remediation"),
        ],
    )
