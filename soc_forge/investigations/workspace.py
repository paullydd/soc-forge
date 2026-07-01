from typing import Any, Dict, List
from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, section, divider, info_panel, menu_option, warning, error, success, status_card, progress_bar_line
from soc_forge.ui.screen import begin_screen
from soc_forge.investigations.timeline import show_timeline
from soc_forge.investigations.export import export_investigation_bundle
from soc_forge.investigations.replay import replay_case
from soc_forge.core.analyst import (
    build_analyst_summary,
    build_analyst_findings,
    build_analyst_recommendations,
    calculate_confidence, 
    calculate_investigation_score,
)

VALID_STATUSES = ["New", "Investigating", "Contained", "Closed", "False Positive"]


def launch_case_workspace(cases: List[Dict[str, Any]], clear_screen=None) -> None:
    if not cases:
        print(Colors.YELLOW + "\nNo cases available." + Colors.RESET)
        return

    while True:
        begin_screen("INVESTIGATION WORKSPACE")

        for idx, case in enumerate(cases, start=1):
            title = case.get("title", case.get("name", "Untitled Case"))
            risk = case.get("risk_score", case.get("risk", "N/A"))
            status = case.get("status", "New")
            severity = get_severity(risk)

            print(
                f"{Colors.BOLD}[{idx}]{Colors.RESET} "
                f"{title} | "
                f"Risk: {color_severity(severity)} {risk} | "
                f"Status: {color_status(status)}"
            )

        print(Colors.GRAY + "[0] Back" + Colors.RESET)

        choice = input("\nSelect a case: ").strip()

        if choice == "0":
            return

        if not choice.isdigit() or not (1 <= int(choice) <= len(cases)):
            print(Colors.RED + "Invalid selection." + Colors.RESET)
            continue

        selected_case = cases[int(choice) - 1]
        open_case_menu(selected_case, clear_screen)

def get_severity(risk: Any) -> str:
    try:
        risk_value = int(risk)
    except (TypeError, ValueError):
        return "Unknown"

    if risk_value >= 300:
        return "Critical"
    if risk_value >= 200:
        return "High"
    if risk_value >= 100:
        return "Medium"
    if risk_value > 0:
        return "Low"
    return "Informational"

def show_soc_forge_analyst(case: Dict[str, Any]) -> None:
    section("SOC-FORGE ANALYST")

    print(build_analyst_summary(case))

    confidence = calculate_confidence(case)

    print()
    progress_bar_line("Confidence", confidence)
    investigation_score = calculate_investigation_score(case)
    progress_bar_line("Case Score", investigation_score)

    findings = build_analyst_findings(case)

    if findings:
        print()
        print("Findings")
        for finding in findings:
            print(f"- {finding}")

    recommendations = build_analyst_recommendations(case)

    if recommendations:
        print()
        print("Recommended Next Steps")
        for index, recommendation in enumerate(recommendations, start=1):
            print(f"{index}. {recommendation['action']}")
            print(f"   Reason: {recommendation['reason']}")

def get_mitre_summary(case: Dict[str, Any]) -> str:
    mitre = case.get("mitre", case.get("mitre_attack", case.get("techniques", [])))

    if isinstance(mitre, list):
        if not mitre:
            return "None"
        return ", ".join(str(item) for item in mitre)

    if isinstance(mitre, dict):
        values = []
        for key, value in mitre.items():
            if isinstance(value, list):
                values.extend(str(item) for item in value)
            else:
                values.append(str(value))
        return ", ".join(values) if values else "None"

    if mitre:
        return str(mitre)

    return "None"


def count_items(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    if value:
        return 1
    return 0


def count_indicators(case: Dict[str, Any]) -> int:
    indicators = case.get("indicators", case.get("iocs", {}))

    if not indicators:
        return 0

    if isinstance(indicators, dict):
        total = 0
        for value in indicators.values():
            if isinstance(value, list):
                total += len(value)
            elif value:
                total += 1
        return total

    if isinstance(indicators, list):
        return len(indicators)

    return 1

def color_severity(severity: str) -> str:
    if severity == "Critical":
        return Colors.RED + severity + Colors.RESET
    if severity == "High":
        return Colors.YELLOW + severity + Colors.RESET
    if severity == "Medium":
        return Colors.BLUE + severity + Colors.RESET
    if severity == "Low":
        return Colors.GREEN + severity + Colors.RESET
    return severity


def color_status(status: str) -> str:
    if status == "Closed":
        return Colors.GREEN + status + Colors.RESET
    if status == "Investigating":
        return Colors.YELLOW + status + Colors.RESET
    if status == "Contained":
        return Colors.BLUE + status + Colors.RESET
    if status == "False Positive":
        return Colors.GRAY + status + Colors.RESET
    return Colors.CYAN + status + Colors.RESET

def print_case_summary(case: Dict[str, Any]) -> None:
    title = case.get("title", case.get("name", "Untitled Case"))
    case_id = case.get("id", case.get("case_id", "N/A"))
    risk = case.get("risk_score", case.get("risk", 0))
    status = case.get("status", "New")
    created = case.get("created_at", case.get("created", "Unknown"))

    severity = get_severity(risk)
    mitre = get_mitre_summary(case)
    alert_count = count_items(case.get("alerts", []))
    indicator_count = count_indicators(case)
    note_count = count_items(case.get("notes", []))

    print("\n" + Colors.CYAN + "=" * 60 + Colors.RESET)
    begin_screen(f"CASE #{case_id}")

    info_panel(
        title=title,
        rows=[
            ("Status", color_status(status)),
            ("Severity", color_severity(severity)),
            ("Risk Score", risk),
            ("MITRE", mitre),
            ("Created", created),
            ("Alerts", alert_count),
            ("Indicators", indicator_count),
            ("Notes", note_count),
        ],
    )

def print_case_dashboard(case: Dict[str, Any]) -> None:
    title = case.get("title", case.get("name", "Untitled Case"))
    risk = case.get("risk_score", case.get("risk", 0))
    status = case.get("status", "New")
    created = case.get("created_at", case.get("created", "Unknown"))

    severity = get_severity(risk)
    mitre = get_mitre_summary(case)
    alert_count = count_items(case.get("alerts", []))
    indicator_count = count_indicators(case)
    note_count = count_items(case.get("notes", []))
    timeline = case.get("timeline", [])

    begin_screen("CASE DASHBOARD")

    status_card(
        title,
        [
            ("Status", color_status(status)),
            ("Severity", color_severity(severity)),
            ("Risk Score", risk),
            ("MITRE", mitre),
            ("Created", created),
            ("Alerts", alert_count),
            ("Entities", indicator_count),
            ("Notes", note_count),
        ],
    )

    section("INVESTIGATION HEALTH")

    try:
        risk_value = int(risk)
    except (TypeError, ValueError):
        risk_value = 0

    risk_percent = min(100, int(risk_value / 4))
    evidence_percent = min(100, alert_count * 20)
    entity_percent = min(100, indicator_count * 15)
    note_percent = min(100, note_count * 25)

    progress_bar_line("Risk", risk_percent)
    progress_bar_line("Evidence", evidence_percent)
    progress_bar_line("Entities", entity_percent)
    progress_bar_line("Notes", note_percent)

    show_soc_forge_analyst(case)

    section("RECENT TIMELINE")

    # if timeline:
        # for event in timeline[:3]:
            # timestamp = event.get("timestamp", "Unknown")
            #description = event.get("description", event.get("event", "Unknown Event"))
            #print(f"{Colors.CYAN}{timestamp:<8}{Colors.RESET} {description}")
    #else:
        #warning("No timeline events available.")

    print()

    # show_insights(case)

    print()

    # show_recommendations(case)

def open_case_menu(case: Dict[str, Any], clear_screen=None) -> None:
    while True:
        if clear_screen:
            clear_screen()

        print_case_dashboard(case)
        section("INVESTIGATION ACTIONS")

        menu_option("1", "Investigation Replay")
        menu_option("2", "Timeline")
        menu_option("3", "Investigation Narrative")
        menu_option("4", "Attack Graph")
        menu_option("5", "Entity Explorer")
        menu_option("6", "Notes")
        menu_option("7", "Change Status")
        menu_option("8", "Export")
        menu_option("0", "Back")

        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            replay_case(case, clear_screen)

        elif choice == "2":
            show_timeline(case, clear_screen)

        elif choice == "3":
            show_story(case)

        elif choice == "4":
            show_attack_graph(case)

        elif choice == "5":
            show_indicators(case)

        elif choice == "6":
            manage_notes(case)

        elif choice == "7":
            change_status(case)

        elif choice == "8":
            export_investigation_bundle(case)
        elif choice == "0":
            if clear_screen:
                clear_screen()
            return
        else:
            error("Invalid option.")

def show_story(case: Dict[str, Any]) -> None:
    begin_screen("ATTACK STORY")

    story = case.get("story") or case.get("analyst_summary")

    if not story:
        warning("No story available yet.")
        input("\nPress Enter to return...")
        return

    print(story)
    input("\nPress Enter to return...")


def show_attack_graph(case: Dict[str, Any]) -> None:
    begin_screen("ATTACK GRAPH")

    graph = case.get("attack_graph") or case.get("graph")

    if not graph:
        warning("No attack graph available yet.")
        input("\nPress Enter to return...")
        return

    if isinstance(graph, list):
        for line in graph:
            print(line)
    else:
        print(graph)

    input("\nPress Enter to return...")

def show_indicators(case: Dict[str, Any]) -> None:
    indicators = case.get("indicators", case.get("iocs", {}))
    mitre = case.get("mitre", case.get("mitre_attack", case.get("techniques", [])))

    print("\n" + Colors.CYAN + "=" * 60 + Colors.RESET)
    print(Colors.BOLD + "INDICATORS OF COMPROMISE" + Colors.RESET)
    print(Colors.CYAN + "=" * 60 + Colors.RESET)

    if not indicators and not mitre:
        print(Colors.YELLOW + "No indicators available yet." + Colors.RESET)
        return

    if isinstance(indicators, dict):
        for category, values in indicators.items():
            print_indicator_section(category, values)

    elif isinstance(indicators, list):
        print_indicator_section("Indicators", indicators)

    else:
        print_indicator_section("Indicators", [indicators])

    if mitre:
        print_indicator_section("MITRE ATT&CK", mitre)

    print(Colors.CYAN + "=" * 60 + Colors.RESET)
    input("\nPress Enter to return...")

def print_indicator_section(title: str, values: Any) -> None:
    icon = get_indicator_icon(title)

    print()
    print(Colors.BOLD + f"{icon} {title}" + Colors.RESET)
    print(Colors.GRAY + "-" * 40 + Colors.RESET)

    if values is None or values == [] or values == "":
        print(Colors.YELLOW + "  None" + Colors.RESET)
        return

    if not isinstance(values, list):
        values = [values]

    for value in values:
        print(f"  {Colors.GREEN}- {value}{Colors.RESET}")


def get_indicator_icon(title: str) -> str:
    normalized = title.lower()

    if "ip" in normalized:
        return "🌐"
    if "user" in normalized or "account" in normalized:
        return "👤"
    if "host" in normalized or "computer" in normalized:
        return "🖥"
    if "service" in normalized:
        return "⚙"
    if "task" in normalized:
        return "📅"
    if "mitre" in normalized or "attack" in normalized:
        return "🎯"
    if "hash" in normalized:
        return "#"
    if "domain" in normalized or "url" in normalized:
        return "🔗"

    return "•"

def manage_notes(case: Dict[str, Any]) -> None:
    case.setdefault("notes", [])

    while True:
        print("\nCase Notes")
        print("-" * 60)
        print("[1] View Notes")
        print("[2] Add Note")
        print("[0] Back")

        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            return
        elif choice == "1":
            view_notes(case)
        elif choice == "2":
            add_note(case)
        else:
            print("Invalid option.")


def view_notes(case: Dict[str, Any]) -> None:
    notes = case.get("notes", [])

    print("\nNotes")
    print("-" * 60)

    if not notes:
        print("No notes added yet.")
        return

    for idx, note in enumerate(notes, start=1):
        print(f"[{idx}] {note}")


def add_note(case: Dict[str, Any]) -> None:
    note = input("\nEnter note: ").strip()

    if not note:
        print("Note not added.")
        return

    case.setdefault("notes", []).append(note)
    print("Note added.")


def change_status(case: Dict[str, Any]) -> None:
    print("\nChange Case Status")
    print("-" * 60)

    for idx, status in enumerate(VALID_STATUSES, start=1):
        print(f"[{idx}] {status}")

    choice = input("\nSelect status: ").strip()

    if not choice.isdigit() or not (1 <= int(choice) <= len(VALID_STATUSES)):
        print("Invalid status.")
        return

    case["status"] = VALID_STATUSES[int(choice) - 1]
    print(f"Status updated to: {case['status']}")


def export_placeholder(case: Dict[str, Any]) -> None:
    print("\nExport Investigation")
    print("-" * 60)
    print("Export bundle will be added in Phase 18.6.")