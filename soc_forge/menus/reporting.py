from soc_forge.ui.panels import header, menu_option, error, warning
from soc_forge.ui.screen import begin_screen


def reporting_menu(
    clear_screen,
    pause,
    open_report,
    view_mitre_coverage,
):
    while True:
        begin_screen("REPORTING")

        menu_option("1", "Open HTML Report")
        menu_option("2", "MITRE Coverage")
        menu_option("3", "Export Investigation Bundle Coming Soon")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            open_report()
        elif choice == "2":
            view_mitre_coverage()
        elif choice == "3":
            warning("Export Bundle will be added later.")
            pause()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()