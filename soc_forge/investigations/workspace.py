from typing import Any, Dict, List
from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, section, divider, info_panel, menu_option, warning, error, success, status_card, progress_bar_line
from soc_forge.core.investigation_graph import build_investigation_graph, summarize_graph
from soc_forge.ui.investigation.graph import graph_overview_panel
from soc_forge.ui.investigation.navigation import investigation_graph_menu
from soc_forge.ui.investigation.entity_browser import entity_browser_panel
from soc_forge.ui.investigation.entity_profile import entity_profile_panel
from soc_forge.ui.investigation.relationships import relationships_panel
from soc_forge.ui.investigation.attack_path import attack_path_panel
from soc_forge.core.entity_intelligence import build_entity_profile
from soc_forge.ui.screen import begin_screen
from soc_forge.investigations.timeline import show_timeline
from soc_forge.investigations.export import export_investigation_bundle
from soc_forge.investigations.replay import replay_case
from soc_forge.cases.lifecycle import (
    VALID_CASE_STATUSES,
    add_case_note,
    assign_case_owner,
    change_case_status,
    ensure_case_lifecycle,
)
from soc_forge.cases.store import filter_cases, replace_case, sort_cases
from soc_forge.core.analyst import (
    build_analyst_summary,
    build_analyst_findings,
    build_analyst_recommendations,
    calculate_confidence,
    calculate_investigation_score,
)

VALID_STATUSES = VALID_CASE_STATUSES


def launch_case_workspace(cases: List[Dict[str, Any]], clear_screen=None, save_cases=None) -> None:
    if not cases:
        print(Colors.YELLOW + "\nNo cases available." + Colors.RESET)
        return

    active_filter = "all"
    active_sort = "risk_desc"
    current_owner = ""

    while True:
        begin_screen("INVESTIGATION WORKSPACE")
        visible_cases = sort_cases(filter_cases(cases, active_filter, current_owner=current_owner), active_sort)

        print(f"Filter: {active_filter.replace('_', ' ').title()} | Sort: {active_sort.replace('_', ' ').title()} | Showing {len(visible_cases)} of {len(cases)} case(s)")
        print()

        for idx, case in enumerate(visible_cases, start=1):
            ensure_case_lifecycle(case)
            title = case.get("title", case.get("name", "Untitled Case"))
            risk = case.get("risk_score", case.get("risk", "N/A"))
            status = case.get("status", "New")
            owner = case.get("owner", "Unassigned")
            severity = get_severity(risk)

            print(
                f"{Colors.BOLD}[{idx}]{Colors.RESET} "
                f"{title} | "
                f"Risk: {color_severity(severity)} {risk} | "
                f"Status: {color_status(status)} | "
                f"Owner: {owner}"
            )

        print()
        print(Colors.GRAY + "[F] Filter  [S] Sort  [0] Back" + Colors.RESET)

        choice = input("\nSelect a case: ").strip()

        if choice == "0":
            if save_cases:
                save_cases(cases)
            return

        if choice.lower() == "f":
            active_filter, current_owner = choose_case_filter(current_owner)
            continue

        if choice.lower() == "s":
            active_sort = choose_case_sort(active_sort)
            continue

        if not choice.isdigit() or not (1 <= int(choice) <= len(visible_cases)):
            print(Colors.RED + "Invalid selection." + Colors.RESET)
            continue

        selected_case = visible_cases[int(choice) - 1]
        open_case_menu(selected_case, clear_screen, save_case=lambda case: save_case_update(cases, case, save_cases))

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
    ensure_case_lifecycle(case)
    created = case.get("created_at", case.get("created", "Unknown"))
    updated = case.get("updated_at", "Unknown")
    owner = case.get("owner", "Unassigned")

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
            ("Owner", owner),
            ("Created", created),
            ("Updated", updated),
            ("Alerts", alert_count),
            ("Indicators", indicator_count),
            ("Notes", note_count),
        ],
    )

def print_case_dashboard(case: Dict[str, Any]) -> None:
    title = case.get("title", case.get("name", "Untitled Case"))
    risk = case.get("risk_score", case.get("risk", 0))
    status = case.get("status", "New")
    ensure_case_lifecycle(case)
    created = case.get("created_at", case.get("created", "Unknown"))
    updated = case.get("updated_at", "Unknown")
    owner = case.get("owner", "Unassigned")

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
            ("Owner", owner),
            ("Created", created),
            ("Updated", updated),
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

def open_case_menu(case: Dict[str, Any], clear_screen=None, save_case=None) -> None:
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
        menu_option("8", "Assign Owner")
        menu_option("9", "Lifecycle")
        menu_option("10", "Next Actions")
        menu_option("11", "Close Case")
        menu_option("12", "Export")
        menu_option("13", "View Investigation Graph")
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
            persist_case(case, save_case)

        elif choice == "7":
            change_status(case)
            persist_case(case, save_case)

        elif choice == "8":
            assign_owner(case)
            persist_case(case, save_case)

        elif choice == "9":
            show_lifecycle(case)

        elif choice == "10":
            show_next_actions(case)

        elif choice == "11":
            close_case(case)
            persist_case(case, save_case)

        elif choice == "12":
            export_investigation_bundle(case)

        elif choice == "13":
            while True:
                begin_screen("Entity Relationship Explorer")

                graph = build_investigation_graph(case)
                graph["summary"] = summarize_graph(graph)

                graph_overview_panel(graph, case)

                graph_choice = investigation_graph_menu()

                if graph_choice == "0":
                    break

                elif graph_choice == "1":
                    begin_screen("Entity Browser")
                    selected_entity = entity_browser_panel(graph)

                    if selected_entity:
                        begin_screen("Entity Profile")
                        profile = build_entity_profile(graph, case, selected_entity)
                        related = entity_profile_panel(profile)

                        if related:
                            print()
                            pivot = input("Select related entity number to pivot, or Enter to return: ").strip()

                            if pivot.isdigit():
                                index = int(pivot) - 1

                                if 0 <= index < len(related):
                                    begin_screen("Entity Profile")
                                    pivot_profile = build_entity_profile(graph, case, related[index])
                                    entity_profile_panel(pivot_profile)
                                    input("\nPress Enter to return...")

                        else:
                            input("\nPress Enter to return...")

                elif graph_choice == "2":
                    begin_screen("Relationship Explorer")
                    relationships_panel(graph)
                    input("\nPress Enter to return...")

                elif graph_choice == "3":
                    begin_screen("Attack Path")
                    attack_path_panel(case)
                    input("\nPress Enter to return...")
        elif choice == "0":
            persist_case(case, save_case)
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
    ensure_case_lifecycle(case)
    notes = case.get("notes", [])

    print("\nNotes")
    print("-" * 60)

    if not notes:
        print("No notes added yet.")
        return

    for idx, note in enumerate(notes, start=1):
        if isinstance(note, dict):
            timestamp = note.get("created_at") or "unknown time"
            author = note.get("author") or "analyst"
            text = note.get("text", "")
            print(f"[{idx}] {timestamp} | {author}: {text}")
        else:
            print(f"[{idx}] {note}")


def add_note(case: Dict[str, Any]) -> None:
    note = input("\nEnter note: ").strip()

    if not note:
        print("Note not added.")
        return

    author = input("Author [analyst]: ").strip() or "analyst"
    add_case_note(case, note, author=author)
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

    reason = input("Reason [optional]: ").strip()
    change_case_status(case, VALID_STATUSES[int(choice) - 1], reason=reason)
    print(f"Status updated to: {case['status']}")


def assign_owner(case: Dict[str, Any]) -> None:
    owner = input("\nOwner [Unassigned]: ").strip()
    assign_case_owner(case, owner)
    print(f"Owner updated to: {case['owner']}")


def export_placeholder(case: Dict[str, Any]) -> None:
    print("\nExport Investigation")
    print("-" * 60)
    print("Export bundle will be added in Phase 18.6.")

def persist_case(case: Dict[str, Any], save_case=None) -> None:
    ensure_case_lifecycle(case)
    if save_case:
        save_case(case)


def save_case_update(cases: List[Dict[str, Any]], case: Dict[str, Any], save_cases=None) -> None:
    replace_case(cases, case)
    if save_cases:
        save_cases(cases)


def choose_case_sort(current_sort: str) -> str:
    print("\nCase Sorting")
    print("-" * 60)
    options = [
        ("1", "risk_desc", "Risk, highest first"),
        ("2", "updated_desc", "Recently updated"),
        ("3", "status", "Status"),
        ("4", "owner", "Owner"),
        ("5", "title", "Title"),
    ]

    for key, value, label in options:
        marker = "*" if value == current_sort else " "
        print(f"[{key}] {marker} {label}")

    choice = input("\nSelect sort: ").strip()
    return next((value for key, value, _label in options if key == choice), current_sort)


def choose_case_filter(current_owner: str) -> tuple[str, str]:
    print("\nCase Filters")
    print("-" * 60)
    options = [
        ("1", "all", "All cases"),
        ("2", "open", "Open / active cases"),
        ("3", "high_risk", "High risk"),
        ("4", "assigned_to_me", "Assigned to me"),
        ("5", "has_notes", "Has notes"),
        ("6", "no_notes", "No notes"),
        ("7", "closed", "Closed"),
    ]

    for key, _value, label in options:
        print(f"[{key}] {label}")

    choice = input("\nSelect filter: ").strip()
    selected = next((value for key, value, _label in options if key == choice), "all")

    if selected == "assigned_to_me":
        owner = input(f"Owner [{current_owner or 'analyst'}]: ").strip() or current_owner or "analyst"
        return selected, owner

    return selected, current_owner


def show_lifecycle(case: Dict[str, Any]) -> None:
    ensure_case_lifecycle(case)
    begin_screen("CASE LIFECYCLE")

    print(f"Case: {case.get('case_id', case.get('id', 'Unknown'))}")
    print(f"Status: {case.get('status', 'New')}")
    print(f"Owner: {case.get('owner', 'Unassigned')}")
    print(f"Created: {case.get('created_at', 'Unknown')}")
    print(f"Updated: {case.get('updated_at', 'Unknown')}")
    print(f"Evidence Items: {len(case.get('evidence', []))}")
    print(f"Notes: {len(case.get('notes', []))}")

    print("\nStatus History")
    print("-" * 60)
    for event in case.get("status_history", []):
        print(
            f"{event.get('changed_at', 'unknown time')} | "
            f"{event.get('changed_by', 'analyst')} | "
            f"{event.get('status', 'Unknown')}"
        )
        if event.get("reason"):
            print(f"  Reason: {event['reason']}")

    input("\nPress Enter to return...")


def show_next_actions(case: Dict[str, Any]) -> None:
    begin_screen("NEXT ACTIONS")
    recommendations = build_analyst_recommendations(case)

    if not recommendations:
        warning("No recommendations available.")
        input("\nPress Enter to return...")
        return

    for index, recommendation in enumerate(recommendations, start=1):
        print(f"{index}. {recommendation['action']}")
        print(f"   Reason: {recommendation['reason']}")

    input("\nPress Enter to return...")


def close_case(case: Dict[str, Any]) -> None:
    print("\nClose Case")
    print("-" * 60)
    print("[1] True Positive")
    print("[2] False Positive")
    print("[3] Benign Authorized")
    print("[4] Duplicate")
    print("[0] Cancel")

    choice = input("\nDisposition: ").strip()
    dispositions = {
        "1": "True Positive",
        "2": "False Positive",
        "3": "Benign Authorized",
        "4": "Duplicate",
    }

    if choice == "0":
        return

    disposition = dispositions.get(choice)
    if not disposition:
        print("Invalid disposition.")
        return

    summary = input("Closure summary: ").strip()
    containment = input("Containment action [optional]: ").strip()

    case["disposition"] = disposition
    case["closure_summary"] = summary
    case["containment_action"] = containment

    target_status = "False Positive" if disposition == "False Positive" else "Closed"
    reason = summary or disposition
    change_case_status(case, target_status, reason=reason)

    if containment:
        add_case_note(case, f"Containment action: {containment}")

    print(f"Case closed as: {disposition}")

