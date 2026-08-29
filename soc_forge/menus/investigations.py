from soc_forge.ui.panels import header, menu_option, error
from soc_forge.investigations.ioc_explorer import build_ioc_index, list_iocs
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


def investigations_menu(
    pause,
    load_cases,
    view_cases,
    view_or_add_notes,
    manage_case_status,
    workspace_controller=None,
):
    while True:
        begin_screen("INVESTIGATIONS")
        print(render_breadcrumb(("SOC-FORGE", "INVESTIGATIONS")))

        menu_option("1", "View Cases")
        menu_option("2", "Entity Explorer")
        menu_option("3", "Analyst Notes")
        menu_option("4", "Case Status Management")
        menu_option("5", "Investigation Workspaces")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            view_cases()

        elif choice == "2":
            cases = load_cases()
            ioc_index = build_ioc_index(cases)
            list_iocs(ioc_index, title="ENTITY EXPLORER")

        elif choice == "3":
            view_or_add_notes()

        elif choice == "4":
            manage_case_status()
        elif choice == "5":
            if workspace_controller is None:
                error("Investigation workspaces are unavailable.")
                pause()
            else:
                workspace_controller.run()


        elif choice == "0":
            return

        else:
            error("Invalid option.")
            pause()