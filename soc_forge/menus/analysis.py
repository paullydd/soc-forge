from soc_forge.ui.panels import header, menu_option, error, warning


def analysis_menu(
    clear_screen,
    pause,
    attack_stories,
    attack_graph_viewer,
):
    while True:
        clear_screen()

        header("ANALYSIS")

        menu_option("1", "Attack Stories")
        menu_option("2", "Attack Graph Viewer")
        menu_option("3", "Timeline Viewer Coming Soon")
        menu_option("4", "SOC Statistics Coming Soon")
        menu_option("0", "Back")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            attack_stories()
        elif choice == "2":
            attack_graph_viewer()
        elif choice == "3":
            warning("Timeline Viewer will be added next.")
            pause()
        elif choice == "4":
            warning("SOC Statistics will be added later.")
            pause()
        elif choice == "0":
            return
        else:
            error("Invalid option.")
            pause()