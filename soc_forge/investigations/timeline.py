from typing import Any, Dict
from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, info_panel, warning
from soc_forge.ui.screen import begin_screen


def show_timeline(case: Dict[str, Any], clear_screen=None) -> None:

    timeline = case.get("timeline", [])
    title = case.get("title", case.get("name", "Untitled Case"))
    status = case.get("status", "New")

    begin_screen("ATTACK TIMELINE")

    print(Colors.BOLD + title + Colors.RESET)

    if not timeline:
        warning("No timeline data available for this case.")
        input("\nPress Enter to return...")
        return

    print()

    for idx, event in enumerate(timeline):
        timestamp = event.get("timestamp", "Unknown")
        description = event.get("description", event.get("event", "Unknown Event"))

        print(
            f"{Colors.CYAN}{timestamp:<8}{Colors.RESET} "
            f"{Colors.RED}●{Colors.RESET} "
            f"{description}"
        )

        if idx < len(timeline) - 1:
            print(f"{'':<8} {Colors.GRAY}│{Colors.RESET}")

    duration = calculate_duration(timeline)

    info_panel(
        "TIMELINE SUMMARY",
        [
            ("Events", len(timeline)),
            ("Duration", duration),
            ("Status", status),
        ],
    )

    input("\nPress Enter to return...")


def calculate_duration(timeline):
    if len(timeline) < 2:
        return "N/A"

    first = timeline[0].get("timestamp", "Unknown")
    last = timeline[-1].get("timestamp", "Unknown")

    return f"{first} to {last}"