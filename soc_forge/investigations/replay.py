import time
from typing import Any, Dict, List

from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, info_panel, menu_option, warning
from soc_forge.ui.screen import begin_screen


def replay_case(case: Dict[str, Any], clear_screen=None) -> None:
    timeline = case.get("timeline", [])

    if not timeline:
        print("No timeline available.")
        input("\nPress Enter...")
        return

    index = 0

    while True:
        show_event(case, timeline, index, clear_screen)

        choice = input("\nSelect option: ").strip().lower()

        if choice == "n":
            if index < len(timeline) - 1:
                index += 1

        elif choice == "p":
            if index > 0:
                index -= 1

        elif choice == "a":
            auto_play(case, clear_screen)

        elif choice == "q":
            return
        
def show_event(case, timeline, index, clear_screen=None):
    event = timeline[index]

    begin_screen("INVESTIGATION REPLAY")

    print(
        f"{Colors.BOLD}Event {index + 1} of {len(timeline)}{Colors.RESET}\n"
    )

    info_panel(
        "CURRENT EVENT",
        [
            ("Time", event.get("timestamp", "Unknown")),
            ("Event", event.get("description", event.get("event", "Unknown"))),
            ("Status", case.get("status", "New")),
        ],
    )

    print()

    menu_option("N", "Next Event")
    menu_option("P", "Previous Event")
    menu_option("A", "Auto Play")
    menu_option("Q", "Back")

def auto_play(case, clear_screen=None):
    timeline = case.get("timeline", [])

    if not timeline:
        warning("No timeline available.")
        input("\nPress Enter...")
        return

    visible_events = []

    for index, event in enumerate(timeline):
        visible_events.append(event)

        begin_screen("INVESTIGATION REPLAY")

        print(f"{Colors.BOLD}Auto Play: Event {index + 1} of {len(timeline)}{Colors.RESET}\n")

        for idx, visible_event in enumerate(visible_events):
            timestamp = visible_event.get("timestamp", "Unknown")
            description = visible_event.get("description", visible_event.get("event", "Unknown Event"))

            print(
                f"{Colors.CYAN}{timestamp:<8}{Colors.RESET} "
                f"{Colors.RED}●{Colors.RESET} "
                f"{description}"
            )

            if idx < len(visible_events) - 1:
                print(f"{'':<8} {Colors.GRAY}│{Colors.RESET}")

        time.sleep(1)

    input("\nReplay complete. Press Enter...")