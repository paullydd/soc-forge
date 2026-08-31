from soc_forge.ui.panels import header, menu_option, error
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


def investigations_menu(
    pause,
    view_cases,
    workspace_controller=None,
):
    while True:
        begin_screen("INVESTIGATIONS")
        print(render_breadcrumb(("SOC-FORGE", "INVESTIGATIONS")))

        menu_option("1", "View Cases")
        menu_option("2", "Investigation Workspaces")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            view_cases()

        elif choice == "2":
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