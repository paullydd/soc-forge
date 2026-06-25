import sys
from soc_forge.ui.panels import header, menu_option, info_panel, error


def system_menu(
    clear_screen,
    pause,
    create_demo_case,
):
    while True:
        clear_screen()

        header("SYSTEM")

        menu_option("1", "Create Demo Case")
        menu_option("2", "About SOC-Forge")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            create_demo_case()
            pause()
        elif choice == "2":
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
            ("Version", "v1.8.0-dev"),
            ("Mode", "Investigation Workspace Edition"),
            ("Focus", "Detection, Correlation, Case Analysis"),
        ],
    )