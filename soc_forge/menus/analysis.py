from soc_forge.menus.architecture import show_architecture_notice
from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


ANALYSIS_DESTINATIONS = {


}


def analysis_menu(pause,
                  threat_activity_controller=None, entity_explorer_controller=None,
                  attack_activity_controller=None,
                  cross_investigation_controller=None,
                  temporal_analysis_controller=None,
                  hunt_workspace_controller=None):
    while True:
        begin_screen("ANALYSIS")
        print(render_breadcrumb(("SOC-FORGE", "ANALYSIS")))
        menu_group("SECURITY ANALYSIS")
        menu_option("1", "Threat Activity Overview")
        menu_option("2", "Entity Explorer")
        menu_option("3", "ATT&CK Activity")
        menu_option("4", "Cross-Investigation Analysis")
        menu_option("5", "Temporal Analysis")
        menu_option("6", "Hunt Workspace")
        for number, (title, _summary, _scope) in ANALYSIS_DESTINATIONS.items():
            menu_option(number, title)
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()
        if choice == "1":
            if threat_activity_controller is None:
                error("Threat Activity Overview is unavailable.")
                pause()
            else:
                threat_activity_controller.run()
        elif choice == "2":
            if entity_explorer_controller is None:
                error("Entity Explorer is unavailable.")
                pause()
            else:
                entity_explorer_controller.run()
        elif choice == "3":
            if attack_activity_controller is None:
                error("ATT&CK Activity is unavailable.")
                pause()
            else:
                attack_activity_controller.run()
        elif choice == "4":
            if cross_investigation_controller is None:
                error("Cross-Investigation Analysis is unavailable.")
                pause()
            else:
                cross_investigation_controller.run()
        elif choice == "5":
            if temporal_analysis_controller is None:
                error("Temporal Analysis is unavailable.")
                pause()
            else:
                temporal_analysis_controller.run()
        elif choice == "6":
            if hunt_workspace_controller is None:
                error("Hunt Workspace is unavailable.")
                pause()
            else:
                hunt_workspace_controller.run()
        elif choice in ANALYSIS_DESTINATIONS:
            title, summary, scope = ANALYSIS_DESTINATIONS[choice]
            show_architecture_notice("ANALYSIS", title, summary, pause, scope)
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()
