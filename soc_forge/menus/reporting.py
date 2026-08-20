from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


def reporting_menu(
    clear_screen,
    pause,
    open_report,
    view_mitre_coverage,
):
    while True:
        begin_screen("REPORTING")
        print(render_breadcrumb(("SOC-FORGE", "REPORTING")))
        menu_group("REPORTING")
        menu_option("1", "Analysis Report")
        menu_option("2", "ATT&CK Coverage")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()
        if choice == "1":
            open_report()
        elif choice == "2":
            view_mitre_coverage()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()
