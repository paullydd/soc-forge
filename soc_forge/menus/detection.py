from soc_forge.menus.architecture import show_architecture_notice
from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import render_breadcrumb


def detection_menu(
    clear_screen,
    pause,
    analyze_log_file,
    run_attack_simulation,
    view_alerts,
    run_rules_only,
    search_alerts,
    show_detection_overview=None,
    show_rule_catalog=None,
    show_rule_explainability=None,
):
    while True:
        begin_screen("DETECTION")
        print(render_breadcrumb(("SOC-FORGE", "DETECTION")))

        menu_group("DETECTION ENGINEERING")
        menu_option("1", "Detection Overview")
        menu_option("2", "Rule Catalog")
        menu_option("3", "Detection Lab")
        menu_option("4", "Detection Coverage")
        menu_option("5", "Rule Explainability")
        menu_option("6", "Detection Gaps")
        menu_group("DETECTION RESULTS")
        menu_option("7", "Alert Explorer")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            if show_detection_overview is not None:
                show_detection_overview()
            else:
                show_architecture_notice(
                    "DETECTION",
                    "Detection Overview",
                    "Detection Overview is unavailable in this console session. "
                    "Use Detection Lab and Alert Explorer for current workflows.",
                    pause,
                )
        elif choice == "2":
            if show_rule_catalog is not None:
                show_rule_catalog()
            else:
                show_architecture_notice(
                    "DETECTION",
                    "Rule Catalog",
                    "Rule Catalog is unavailable in this console session. Rules Only "
                    "Mode remains available through Detection Lab.",
                    pause,
                )
        elif choice == "3":
            detection_lab(
                analyze_log_file, run_attack_simulation, run_rules_only, pause
            )
        elif choice == "4":
            show_architecture_notice(
                "DETECTION",
                "Detection Coverage",
                "Detection coverage analysis is not implemented in this slice.",
                pause,
                ("ATT&CK coverage", "data-source coverage", "rule coverage"),
            )
        elif choice == "5":
            if show_rule_explainability is not None:
                show_rule_explainability()
            else:
                show_architecture_notice(
                    "DETECTION",
                    "Rule Explainability",
                    "Rule Explainability is unavailable in this console session.",
                    pause,
                )
        elif choice == "6":
            show_architecture_notice(
                "DETECTION",
                "Detection Gaps",
                "Detection gap analysis is not implemented in this slice.",
                pause,
                ("uncovered behaviors", "missing telemetry", "coverage limitations"),
            )
        elif choice == "7":
            alert_explorer(view_alerts, search_alerts, pause)
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()


def detection_lab(analyze_log_file, run_attack_simulation, run_rules_only, pause):
    while True:
        begin_screen("DETECTION LAB")
        print(render_breadcrumb(("SOC-FORGE", "DETECTION", "DETECTION LAB")))
        menu_option("1", "Analyze Log File")
        menu_option("2", "Run Attack Simulation")
        menu_option("3", "Rules Only Mode")
        menu_option("0", "Back")
        choice = input("\nSelect option: ").strip()
        if choice == "1":
            analyze_log_file()
        elif choice == "2":
            run_attack_simulation()
        elif choice == "3":
            run_rules_only()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()


def alert_explorer(view_alerts, search_alerts, pause):
    while True:
        begin_screen("ALERT EXPLORER")
        print(render_breadcrumb(("SOC-FORGE", "DETECTION", "ALERT EXPLORER")))
        menu_option("1", "View Alerts")
        menu_option("2", "Search Alerts")
        menu_option("0", "Back")
        choice = input("\nSelect option: ").strip()
        if choice == "1":
            view_alerts()
        elif choice == "2":
            search_alerts()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()
