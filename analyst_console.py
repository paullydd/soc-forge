import os
import subprocess
import sys
import json
from colorama import Fore, Style, init
import time
import sys
from soc_forge.investigations.workspace import launch_case_workspace
from soc_forge.investigations.ioc_explorer import build_ioc_index, list_iocs
from soc_forge.ui.loading import startup_screen as ui_startup_screen
from soc_forge.ui.panels import menu_group, menu_option
from soc_forge.menus.investigations import investigations_menu
from soc_forge.menus.detection import detection_menu
from soc_forge.menus.analysis import analysis_menu
from soc_forge.menus.reporting import reporting_menu
from soc_forge.menus.system import system_menu

init()


def startup_screen():
    ui_startup_screen(clear_screen)

def color_severity(severity):
    severity = severity.lower()
    icon = severity_icon(severity)

    if severity == "high":
        return Fore.RED + f"{icon} HIGH" + Style.RESET_ALL

    if severity == "medium":
        return Fore.YELLOW + f"{icon} MEDIUM" + Style.RESET_ALL

    if severity == "low":
        return Fore.GREEN + f"{icon} LOW" + Style.RESET_ALL

    return f"{icon} {severity.upper()}"

def success(message):
    print(Fore.GREEN + f"[+] {message}" + Style.RESET_ALL)


def warning(message):
    print(Fore.YELLOW + f"[!] {message}" + Style.RESET_ALL)


def error(message):
    print(Fore.RED + f"[-] {message}" + Style.RESET_ALL)

def box_row(label, value, color=""):
    width = 48
    plain_text = f"{label:<18}: {value}"
    padding = width - len(plain_text)

    if color:
        value = color + str(value) + Style.RESET_ALL

    print(f"│ {label:<18}: {value}{' ' * padding}│")

def severity_icon(severity):
    severity = severity.lower()

    if severity == "high":
        return "🔴"
    if severity == "medium":
        return "🟡"
    if severity == "low":
        return "🟢"

    return "⚪"

def case_has_notes(story, index):
    note_id = get_case_note_id(story, index)
    note_path = f"out/notes/{note_id}.txt"

    return os.path.exists(note_path) and os.path.getsize(note_path) > 0

def load_case_statuses():
    path = "out/case_status.json"

    if not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_case_statuses(statuses):
    with open("out/case_status.json", "w", encoding="utf-8") as file:
        json.dump(statuses, file, indent=2)

def color_status(status):
    status = status.lower()

    if status == "open":
        return Fore.RED + "OPEN" + Style.RESET_ALL

    if status == "investigating":
        return Fore.YELLOW + "INVESTIGATING" + Style.RESET_ALL

    if status == "closed":
        return Fore.GREEN + "CLOSED" + Style.RESET_ALL

    return status.upper()

def section_title(title):
    print()
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)
    print(Fore.CYAN + title.upper().center(50) + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 50 + Style.RESET_ALL)

BANNER = Fore.CYAN + """
==================================================
SOC-FORGE v1.2
Security Operations Platform
==================================================
""" + Style.RESET_ALL

def create_demo_case():
    os.makedirs("out", exist_ok=True)

    demo_case = {
        "case_id": 1,
        "title": "Password Spray Suspected",
        "status": "Investigating",
        "risk_score": 320,
        "created_at": "2026-06-25 15:44",
        "mitre": ["T1110 - Brute Force", "Credential Access"],
        "alerts": [
            "SOCF-010 Password Spray",
            "SOCF-001 Brute Force",
            "SOCF-002 Account Lockout"
        ],
        "indicators": {
            "IP Addresses": ["203.0.113.10"],
            "Users": ["alice", "bob"],
            "Hosts": ["DC1"],
            "Services": ["Spooler"],
            "Scheduled Tasks": ["Windows Update"]
        },
        "timeline": [
            {
                "timestamp": "15:42",
                "description": "Multiple failed logins detected"
            },
            {
                "timestamp": "15:43",
                "description": "Failed logins observed across multiple users"
            },
            {
                "timestamp": "15:44",
                "description": "Password Spray rule SOCF-010 triggered"
            },
            {
                "timestamp": "15:45",
                "description": "Account lockout detected"
            },
            {
                "timestamp": "15:46",
                "description": "Case created for analyst review"
            }
        ],
        "story": "A suspected password spraying attack targeted multiple user accounts from external IP 203.0.113.10. The activity generated repeated failed authentication events and resulted in at least one account lockout.",
        "attack_graph": [
            "203.0.113.10",
            "   |",
            "   v",
            "alice / bob",
            "   |",
            "   v",
            "DC1",
            "   |",
            "   v",
            "Password Spray"
        ],
        "notes": [
            "Initial investigation opened.",
            "Source IP should be reviewed and blocked if malicious."
        ]
    }

    with open("out/cases.json", "w", encoding="utf-8") as file:
        json.dump([demo_case], file, indent=4)

    print("Demo case created.")

def load_cases():
    file_path = "out/cases.json"

    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if "cases" in data:
            return data["cases"]
        return [data]

    return []


def view_cases():
    clear_screen()
    print("VIEW CASES")
    print("-" * 50)

    cases = load_cases()

    if not cases:
        warning("No case file found yet.")
        print("\nRun an analysis or simulation first.")
        pause()
        return

    for index, case in enumerate(cases, start=1):
        header = case.get("header", {})

        case_id = header.get("title", case.get("case_id", case.get("id", f"CASE-{index:03}")))
        threat = header.get("severity", case.get("threat_level", case.get("severity", "UNKNOWN")))
        score = header.get("score", case.get("risk_score", case.get("score", "N/A")))

        print(f"[{index}] {case_id} | Threat: {threat} | Score: {score}")

    choice = input("\nOpen case number, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(cases):
        error("Invalid case number.")
        pause()
        return

    open_case(cases[int(choice) - 1])


def open_case(case):
    clear_screen()

    header = case.get("header", {})

    case_id = header.get("title", case.get("case_id", case.get("id", "UNKNOWN CASE")))
    threat = header.get("severity", case.get("threat_level", case.get("severity", "UNKNOWN")))
    score = header.get("score", case.get("risk_score", case.get("score", "N/A")))
    details = header.get("details", {})

    print(case_id)
    print("=" * 50)
    print(f"Threat Level: {threat}")
    print(f"Risk Score: {score}")

    summary = case.get("summary", case.get("analyst_summary", case.get("story", "")))

    if summary:
        print("\nAnalyst Summary")
        print("-" * 50)
        print(summary)

    timeline = case.get("timeline", [])

    if timeline:
        print("\nTimeline")
        print("-" * 50)

        for item in timeline:
            if isinstance(item, dict):
                timestamp = item.get("timestamp", item.get("time", "Unknown time"))
                event = item.get("event", item.get("description", item.get("rule_name", "Unknown event")))
                print(f"{timestamp} - {event}")
            else:
                print(item)

    evidence = case.get("evidence", [])

    if evidence:
        print("\nEvidence")
        print("-" * 50)

        for item in evidence:
            if isinstance(item, dict):
                for key, value in item.items():
                    print(f"{key}: {value}")
                print()
            else:
                print(item)

    mitre = case.get("mitre", case.get("mitre_techniques", []))

    if mitre:
        print("\nMITRE Techniques")
        print("-" * 50)

        for technique in mitre:
            print(f"- {technique}")

    recommendations = details.get(
        "recommended_actions",
        case.get("recommended_actions", case.get("recommendations", []))
    )

    if recommendations:
        print("\nRecommended Actions")
        print("-" * 50)

        for action in recommendations:
            print(f"- {action}")

    pause()

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\nPress Enter to return to the menu...")


def run_command(command):
    print("\nRunning command...\n")
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError:
        print("\nSomething went wrong while running that command.")


def analyze_log_file():
    clear_screen()
    print("ANALYZE LOG FILE")
    print("-" * 50)

    input_file = input("Enter log file path: ").strip()

    if not input_file:
        warning("No file entered.")
        pause()
        return

    html_choice = input("Generate HTML report? (y/n): ").lower().strip()

    command = f"python -m soc_forge.cli --input {input_file}"

    if html_choice == "y":
        command += " --html out/report.html"

    run_command(command)
    pause()


def run_attack_simulation():
    clear_screen()
    print("ATTACK SIMULATION")
    print("-" * 50)

    print("[1] Brute Force")
    print("[2] Password Spray")
    print("[3] Privilege Escalation")

    choice = input("\nSelect simulation: ").strip()

    scenarios = {
        "1": "brute_force",
        "2": "password_spray",
        "3": "privilege_escalation",
    }

    scenario = scenarios.get(choice)

    if not scenario:
        error("Invalid choice.")
        pause()
        return

    sim_output = f"out/{scenario}_events.jsonl"
    alerts_output = f"out/{scenario}_alerts.json"
    html_output = f"out/{scenario}_report.html"

    generate_command = (
        f"python -m soc_forge.cli "
        f"--simulate {scenario} "
        f"--sim-output {sim_output}"
    )

    analyze_command = (
        f"python -m soc_forge.cli "
        f"--input {sim_output} "
        f"--html {html_output}"
    )

    run_command(generate_command)
    run_command(analyze_command)
    pause()


def view_mitre_coverage():
    clear_screen()
    print("MITRE COVERAGE")
    print("-" * 50)

    command = "python -m soc_forge.cli --coverage"
    run_command(command)
    pause()


def run_rules_only():
    clear_screen()
    print("RULES ONLY MODE")
    print("-" * 50)

    input_file = input("Enter log file path: ").strip()

    if not input_file:
        warning("No file entered.")
        pause()
        return

    command = f"python -m soc_forge.cli --input {input_file} --rules-only"
    run_command(command)
    pause()

def load_all_alerts():
    alert_files = [
        "out/brute_force_alerts.json",
        "out/password_spray_alerts.json",
        "out/privilege_escalation_alerts.json",
        "out/alerts.json",
    ]

    all_alerts = []

    for file_path in alert_files:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r", encoding="utf-8") as file:
            alerts = json.load(file)

        for alert in alerts:
            alert["_source_file"] = file_path
            all_alerts.append(alert)

    return all_alerts

def search_alerts():
    clear_screen()
    section_title("Search Alerts")

    alerts = load_all_alerts()

    if not alerts:
        warning("No alerts found yet.")
        pause()
        return

    print("[1] Search by Rule ID")
    print("[2] Search by Severity")
    print("[3] Search by Keyword")
    print("[0] Return")

    choice = input("\nSelect search type: ").strip()

    if choice == "0":
        return

    query = input("Enter search value: ").strip().lower()

    if not query:
        warning("No search value entered.")
        pause()
        return

    results = []

    for alert in alerts:
        if choice == "1":
            if query in alert.get("rule_id", "").lower():
                results.append(alert)

        elif choice == "2":
            if query == alert.get("severity", "").lower():
                results.append(alert)

        elif choice == "3":
            searchable_text = json.dumps(alert).lower()

            if query in searchable_text:
                results.append(alert)

        else:
            error("Invalid search type.")
            pause()
            return

    clear_screen()
    section_title("Search Results")

    if not results:
        warning("No matching alerts found.")
        pause()
        return

    print(f"Found {len(results)} matching alert(s).\n")

    for index, alert in enumerate(results, start=1):
        rule_id = alert.get("rule_id", "N/A")
        severity = color_severity(alert.get("severity", "unknown"))
        title = alert.get("title", "Unknown Alert")
        timestamp = alert.get("timestamp", "N/A")

        print(f"[{index}] {rule_id} | {severity} | {title}")
        print(f"    Time: {timestamp}")
        print()

    open_choice = input("Open alert number, or press Enter to return: ").strip()

    if not open_choice:
        return

    if not open_choice.isdigit() or int(open_choice) < 1 or int(open_choice) > len(results):
        error("Invalid alert number.")
        pause()
        return

    open_alert(results[int(open_choice) - 1])

def open_alert(alert):
    clear_screen()
    section_title("Alert Details")
    print("=" * 50)

    print(f"Rule ID:      {alert.get('rule_id', 'N/A')}")
    print(f"Title:        {alert.get('title', 'N/A')}")
    print(f"Severity:     {color_severity(alert.get('severity', 'unknown'))}")
    print(f"Timestamp:    {alert.get('timestamp', 'N/A')}")
    print(f"Risk Score:   {alert.get('score', 'N/A')}")
    print(f"Status:       {alert.get('status', 'N/A')}")
    print(f"Correlation:  {alert.get('correlation_id', 'N/A')}")

    details = alert.get("details", {})

    if details:
        print("\nDetails")
        print("-" * 50)

        for key, value in details.items():
            print(f"{key}: {value}")

    mitre = alert.get("mitre", [])

    if mitre:
        print("\nMITRE Mapping")
        print("-" * 50)

        for item in mitre:
            tactic = item.get("tactic", "N/A")
            technique = item.get("technique", "N/A")
            technique_id = item.get("technique_id", "N/A")

            print(f"{technique_id} | {tactic} | {technique}")

    pause()

def view_alerts():
    clear_screen()
    print("VIEW ALERTS")
    print("-" * 50)

    alert_files = [
        "out/brute_force_alerts.json",
        "out/password_spray_alerts.json",
        "out/privilege_escalation_alerts.json",
        "out/alerts.json",
    ]

    all_alerts = []

    for file_path in alert_files:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r", encoding="utf-8") as file:
            alerts = json.load(file)

        for alert in alerts:
            alert["_source_file"] = file_path
            all_alerts.append(alert)

    if not all_alerts:
        warning("No alerts found yet.")
        pause()
        return

    for index, alert in enumerate(all_alerts, start=1):
        title = alert.get("title", "Unknown alert")
        severity = alert.get("severity", "unknown")
        timestamp = alert.get("timestamp", "unknown time")
        rule_id = alert.get("rule_id", "unknown rule")

        print(f"[{index}] {rule_id} | {color_severity(severity)} | {title}")
        print(f"    Time:   {timestamp}")
        print(f"    Source: {alert.get('_source_file')}")
        print()

    choice = input("\nOpen alert number, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(all_alerts):
        error("Invalid alert number.")
        pause()
        return

    open_alert(all_alerts[int(choice) - 1])

def get_recent_activity(limit=5):
    activities = []

    alert_files = [
        "out/brute_force_alerts.json",
        "out/password_spray_alerts.json",
        "out/privilege_escalation_alerts.json",
        "out/alerts.json",
    ]

    for file_path in alert_files:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r", encoding="utf-8") as file:
            alerts = json.load(file)

        for alert in alerts:
            activities.append({
                "timestamp": alert.get("timestamp", ""),
                "title": alert.get("title", "Unknown Alert"),
                "severity": alert.get("severity", "unknown"),
            })

    activities.sort(key=lambda item: item["timestamp"], reverse=True)
    return activities[:limit]

def get_dashboard_stats():
    stats = {
        "alerts": 0,
        "cases": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "open": 0,
        "investigating": 0,
        "closed": 0,
    }

    alert_files = [
        "out/brute_force_alerts.json",
        "out/password_spray_alerts.json",
        "out/privilege_escalation_alerts.json",
        "out/alerts.json",
    ]

    for file_path in alert_files:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r", encoding="utf-8") as file:
            alerts = json.load(file)

        stats["alerts"] += len(alerts)

        for alert in alerts:
            severity = alert.get("severity", "").lower()

            if severity == "high":
                stats["high"] += 1
            elif severity == "medium":
                stats["medium"] += 1
            elif severity == "low":
                stats["low"] += 1

    if os.path.exists("out/cases.json"):
        with open("out/cases.json", "r", encoding="utf-8") as file:
            cases = json.load(file)

        if isinstance(cases, list):
            stats["cases"] = len(cases)

    statuses = load_case_statuses()

    for status in statuses.values():
        status = status.lower()

        if status == "open":
            stats["open"] += 1
        elif status == "investigating":
            stats["investigating"] += 1
        elif status == "closed":
            stats["closed"] += 1

    return stats

def load_attack_stories():
    story_files = [
        "out/reconstructions.json",
        "out/cases.json",
    ]

    for file_path in story_files:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            for key in ["reconstructions", "stories", "cases", "items"]:
                if key in data and isinstance(data[key], list):
                    return data[key]

            return [data]

    return []

def attack_stories():
    clear_screen()
    section_title("Attack Stories")

    stories = load_attack_stories()

    if not stories:
        warning("No attack stories found yet.")
        pause()
        return

    for index, story in enumerate(stories, start=1):
        header = story.get("header", {})
        details = header.get("details", {})

        title = header.get("title", story.get("title", f"Attack Story {index}"))
        severity = header.get("severity", story.get("severity", "unknown"))

        notes_badge = " 📝" if case_has_notes(story, index) else ""

        print(f"[{index}] {color_severity(severity)} | {title}{notes_badge}")

    choice = input("\nOpen story number, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(stories):
        error("Invalid story number.")
        pause()
        return

    open_attack_story(stories[int(choice) - 1])

def open_attack_story(story):
    clear_screen()
    section_title("Attack Story")

    header = story.get("header", {})
    details = header.get("details", {})

    title = header.get("title", story.get("title", "Unknown Attack Story"))
    severity = header.get("severity", story.get("severity", "unknown"))
    score = header.get("score", story.get("score", "N/A"))
    timestamp = header.get("timestamp", story.get("timestamp", "N/A"))

    print(f"Title:      {title}")
    print(f"Severity:   {color_severity(severity)}")
    print(f"Score:      {score}")
    print(f"Timestamp:  {timestamp}")

    case_risk = details.get("case_risk", {})

    if case_risk:
        print("\nRisk Summary")
        print("-" * 50)
        print(f"Threat Level: {color_severity(case_risk.get('case_threat_level', severity))}")
        print(f"Case Score:   {case_risk.get('case_score', 'N/A')}")
        print(f"Alert Count:  {case_risk.get('alert_count', 'N/A')}")

    attack_flow = details.get("attack_flow", [])

    if attack_flow:
        print("\nAttack Flow")
        print("-" * 50)

        for step in attack_flow:
            timestamp = step.get("timestamp", "N/A")
            label = step.get("label", "Unknown Step")
            rule_id = step.get("rule_id", "N/A")
            step_severity = color_severity(step.get("severity", "unknown"))

            print(f"{timestamp}")
            print(f"  {step_severity} {rule_id} - {label}")
            print("  ↓")

    recommendations = details.get("recommended_actions", [])

    if recommendations:
        print("\nRecommended Actions")
        print("-" * 50)

        for action in recommendations:
            print(f"- {action}")

    pause()

def manage_case_status():
    clear_screen()
    section_title("Case Status")

    stories = load_attack_stories()

    if not stories:
        warning("No cases found.")
        pause()
        return

    statuses = load_case_statuses()

    for index, story in enumerate(stories, start=1):
        note_id = get_case_note_id(story, index)

        status = statuses.get(note_id, "Open")

        header = story.get("header", {})
        title = header.get(
            "title",
            story.get("title", f"Case {index}")
        )

        notes_badge = " 📝" if case_has_notes(story, index) else ""

        print(
            f"[{index}] "
            f"{title} "
            f"({color_status(status)})"
            f"{notes_badge}"
        )

    choice = input(
        "\nSelect case or press Enter to return: "
    ).strip()

    if not choice:
        return

    if not choice.isdigit():
        error("Invalid selection.")
        pause()
        return

    index = int(choice)

    if index < 1 or index > len(stories):
        error("Invalid selection.")
        pause()
        return

    story = stories[index - 1]

    case_id = get_case_note_id(story, index)

    print("\n[1] Open")
    print("[2] Investigating")
    print("[3] Closed")

    status_choice = input(
        "\nSelect status: "
    ).strip()

    mapping = {
        "1": "Open",
        "2": "Investigating",
        "3": "Closed",
    }

    if status_choice not in mapping:
        error("Invalid status.")
        pause()
        return

    statuses[case_id] = mapping[status_choice]

    save_case_statuses(statuses)

    success(
        f"Status updated to {mapping[status_choice]}"
    )

    pause()

def open_report():
    clear_screen()
    print("OPEN REPORT")
    print("-" * 50)

    report_files = [
        "out/brute_force_report.html",
        "out/password_spray_report.html",
        "out/privilege_escalation_report.html",
        "out/report.html",
    ]

    available_reports = [
        file_path for file_path in report_files if os.path.exists(file_path)
    ]

    if not available_reports:
        warning("No reports found yet.")
        pause()
        return

    for index, file_path in enumerate(available_reports, start=1):
        print(f"[{index}] {file_path}")

    choice = input("\nOpen report number, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(available_reports):
        error("Invalid report number.")
        pause()
        return

    selected_report = available_reports[int(choice) - 1]
    absolute_path = os.path.abspath(selected_report)

    print("\nReport selected:")
    print(absolute_path)

    print("\nTo open it from Windows, copy this into PowerShell or Run:")
    print(f"wslview {absolute_path}")

    print("\nOr open this folder in Windows Explorer:")
    print("explorer.exe .")

    pause()

def attack_graph_viewer():
    clear_screen()
    section_title("Attack Graph Viewer")

    stories = load_attack_stories()

    if not stories:
        warning("No attack stories found yet.")
        pause()
        return

    for index, story in enumerate(stories, start=1):
        header = story.get("header", {})
        title = header.get("title", story.get("title", f"Attack Story {index}"))
        severity = header.get("severity", story.get("severity", "unknown"))

        print(f"[{index}] {color_severity(severity)} | {title}")

    choice = input("\nSelect story for graph, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(stories):
        error("Invalid story number.")
        pause()
        return

    story = stories[int(choice) - 1]
    header = story.get("header", {})
    details = header.get("details", {})

    title = header.get("title", story.get("title", "Unknown Attack Story"))
    severity = header.get("severity", story.get("severity", "unknown"))
    attack_flow = details.get("attack_flow", [])

    clear_screen()
    section_title("Attack Graph")

    print(f"Title:    {title}")
    print(f"Severity: {color_severity(severity)}")
    print()

    print(Fore.CYAN + "        ┌──────────────────────┐")
    print("        │   External Source    │")
    print("        └──────────┬───────────┘" + Style.RESET_ALL)

    if attack_flow:
        for step in attack_flow:
            label = step.get("label", "Unknown Step")
            rule_id = step.get("rule_id", "N/A")
            step_severity = color_severity(step.get("severity", severity))

            print(Fore.CYAN + "                   │" + Style.RESET_ALL)
            print(Fore.CYAN + "                   ▼" + Style.RESET_ALL)
            print("        ┌──────────────────────┐")
            print(f"        │ {label[:20].center(20)} │")
            print("        └──────────┬───────────┘")
            print(f"          {step_severity} | {rule_id}")
    else:
        warning("No attack flow data available.")

    print(Fore.CYAN + "                   │")
    print("                   ▼")
    print("        ┌──────────────────────┐")
    print("        │   Investigation      │")
    print("        └──────────────────────┘" + Style.RESET_ALL)

    pause()

def get_case_note_id(story, index=1):
    header = story.get("header", {})
    title = header.get("title", story.get("title", f"case_{index}"))

    safe_title = (
        title.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "")
    )

    return safe_title


def view_or_add_notes():
    clear_screen()
    section_title("Analyst Notes")

    stories = load_attack_stories()

    if not stories:
        warning("No cases/stories found yet.")
        pause()
        return

    for index, story in enumerate(stories, start=1):
        header = story.get("header", {})
        title = header.get("title", story.get("title", f"Attack Story {index}"))
        severity = header.get("severity", story.get("severity", "unknown"))

        print(f"[{index}] {color_severity(severity)} | {title}")

    choice = input("\nSelect case/story for notes, or press Enter to return: ").strip()

    if not choice:
        return

    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(stories):
        error("Invalid selection.")
        pause()
        return

    selected_index = int(choice)
    story = stories[selected_index - 1]

    note_id = get_case_note_id(story, selected_index)

    os.makedirs("out/notes", exist_ok=True)
    note_path = f"out/notes/{note_id}.txt"

    clear_screen()
    section_title("Case Notes")

    if os.path.exists(note_path):
        print("Existing Notes")
        print("-" * 50)

        with open(note_path, "r", encoding="utf-8") as file:
            print(file.read())
    else:
        warning("No notes yet for this case.")

    print("\n[1] Add Note")
    print("[0] Return")

    action = input("\nSelect option: ").strip()

    if action == "0":
        return

    if action != "1":
        error("Invalid option.")
        pause()
        return

    print("\nEnter analyst note.")
    note = input("> ").strip()

    if not note:
        warning("Empty note not saved.")
        pause()
        return

    with open(note_path, "a", encoding="utf-8") as file:
        file.write(note + "\n")

    success("Analyst note saved.")
    pause()

def main_menu():
    while True:
        clear_screen()
        print(BANNER)

        stats = get_dashboard_stats()
        recent = get_recent_activity()

        print(Fore.CYAN + "┌" + "─" * 48 + "┐")
        print("│" + "DASHBOARD".center(48) + "│")
        print("├" + "─" * 48 + "┤" + Style.RESET_ALL)

        box_row("Alerts Generated", stats["alerts"])
        box_row("Cases Created", stats["cases"])

        print(Fore.CYAN + "├" + "─" * 48 + "┤" + Style.RESET_ALL)

        box_row("High Severity", stats["high"], Fore.RED)
        box_row("Medium Severity", stats["medium"], Fore.YELLOW)
        box_row("Low Severity", stats["low"], Fore.GREEN)

        print(Fore.CYAN + "└" + "─" * 48 + "┘" + Style.RESET_ALL)

        print()
        print(Fore.CYAN + "Case Status")
        print("-" * 50 + Style.RESET_ALL)

        print(f"Open Cases:          {color_status('Open')} {stats['open']}")
        print(f"Investigating Cases: {color_status('Investigating')} {stats['investigating']}")
        print(f"Closed Cases:        {color_status('Closed')} {stats['closed']}")

        print("\nRecent Activity")
        print("-" * 50)

        if recent:
            for item in recent:
                severity = color_severity(item["severity"])
                print(f"{item['timestamp']} | {severity} | {item['title']}")
        else:
            warning("No recent activity found.")

        print("\n" + "=" * 50)

        menu_group("Command Center")
        menu_option("1", "Detection")
        menu_option("2", "Investigations")
        menu_option("3", "Analysis")
        menu_option("4", "Reporting")
        menu_option("5", "System")
        menu_option("0", "Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            detection_menu(
                clear_screen,
                pause,
                analyze_log_file,
                run_attack_simulation,
                view_alerts,
                run_rules_only,
                search_alerts,
            )

        elif choice == "2":
            investigations_menu(
                clear_screen,
                pause,
                load_cases,
                view_cases,
                view_or_add_notes,
                manage_case_status,
            )

        elif choice == "3":
            analysis_menu(
                clear_screen,
                pause,
                attack_stories,
                attack_graph_viewer,
            )

        elif choice == "4":
            reporting_menu(
                clear_screen,
                pause,
                open_report,
                view_mitre_coverage,
            )

        elif choice == "5":
            system_menu(
                clear_screen,
                pause,
                create_demo_case,
            )

        elif choice == "0":
            print("\nExiting SOC-Forge Analyst Console.")
            sys.exit(0)

        else:
            print("\nInvalid option.")
            pause()

if __name__ == "__main__":
    startup_screen()
    main_menu()
