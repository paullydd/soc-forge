from soc_forge.ui.panels import header, menu_option, error
from soc_forge.investigations.workspace import launch_case_workspace
from soc_forge.investigations.ioc_explorer import build_ioc_index, list_iocs


def investigations_menu(
    clear_screen,
    pause,
    load_cases,
    view_cases,
    view_or_add_notes,
    manage_case_status,
):
    while True:
        clear_screen()

        header("INVESTIGATIONS")

        menu_option("1", "View Cases")
        menu_option("2", "Investigation Workspace")
        menu_option("3", "IOC Explorer")
        menu_option("4", "Analyst Notes")
        menu_option("5", "Case Status Management")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            view_cases()

        elif choice == "2":
            cases = load_cases()
            launch_case_workspace(cases)

        elif choice == "3":
            cases = load_cases()
            ioc_index = build_ioc_index(cases)
            list_iocs(ioc_index)

        elif choice == "4":
            view_or_add_notes()

        elif choice == "5":
            manage_case_status()

        elif choice == "0":
            return

        else:
            error("Invalid option.")
            pause()