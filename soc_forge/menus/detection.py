from soc_forge.ui.panels import header, menu_option, error
from soc_forge.ui.screen import begin_screen


def detection_menu(
    clear_screen,
    pause,
    analyze_log_file,
    run_attack_simulation,
    view_alerts,
    run_rules_only,
    search_alerts,
):
    while True:
        begin_screen("DETECTION")

        menu_option("1", "Analyze Log File")
        menu_option("2", "Run Attack Simulation")
        menu_option("3", "View Alerts")
        menu_option("4", "Rules Only Mode")
        menu_option("5", "Search Alerts")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            analyze_log_file()
        elif choice == "2":
            run_attack_simulation()
        elif choice == "3":
            view_alerts()
        elif choice == "4":
            run_rules_only()
        elif choice == "5":
            search_alerts()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()