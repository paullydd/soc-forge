import os
from pathlib import Path
import subprocess
import sys
import json
from colorama import Fore, Style, init
import time
import sys
from soc_forge.attack_activity import AttackActivityService
from soc_forge.reporting import (
    ExecutiveSummaryService, InvestigationReportService, ReportCenterService,
)
from soc_forge.menus.reporting import ReportingConsoleController
from soc_forge.hunt_workspace import HuntWorkspaceService
from soc_forge.menus.hunt_workspace import HuntWorkspaceConsoleController
from soc_forge.temporal_analysis import TemporalAnalysisService
from soc_forge.menus.temporal_analysis import TemporalAnalysisConsoleController
from soc_forge.cross_investigation import CrossInvestigationAnalysisService
from soc_forge.menus.cross_investigation import CrossInvestigationConsoleController
from soc_forge.menus.attack_activity import AttackActivityConsoleController
from soc_forge.entity_explorer import EntityExplorerService, EntityObservationService
from soc_forge.menus.entity_explorer import EntityExplorerConsoleController
from soc_forge.detection_engineering import DetectionEngineeringService
from soc_forge.detection_coverage import (
    DetectionCoverageService,
    DetectionGapService,
)
from soc_forge.menus.detection_coverage import (
    DetectionCoverageConsoleController,
)
from soc_forge.detection_lab import DetectionLabService
from soc_forge.menus.detection_lab import DetectionLabConsoleController
from soc_forge.menus.detection_engineering import (
    DetectionEngineeringConsoleController,
)
from soc_forge.ui.loading import startup_screen as ui_startup_screen
from soc_forge.ui.panels import menu_group, menu_option
from soc_forge.menus.investigations import investigations_menu
from soc_forge.menus.detection import detection_menu
from soc_forge.menus.analysis import analysis_menu
from soc_forge.menus.threat_activity import ThreatActivityConsoleController
from soc_forge.threat_activity import ThreatActivityOverviewService
from soc_forge.menus.reporting import reporting_menu
from soc_forge.menus.system import SystemConsoleController, system_menu
from soc_forge.system_workspace import SystemWorkspaceService
from soc_forge.dashboard.dashboard import show_dashboard
from soc_forge.ui.screen import begin_screen, set_clear_screen
from soc_forge.cases.store import load_cases_file
from soc_forge.pipeline import AnalysisOptions, run_analysis
from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.paths import resolve_workspace_root
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.operational_summary import OperationalSummaryService
from soc_forge.investigations.operations_prioritization import OperationsPrioritizationService
from soc_forge.investigations.operations_queue import OperationsQueueService
from soc_forge.investigations.operations_queue_console import (
    OperationsQueueConsoleController,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.investigations.repository import InvestigationRepositoryError
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore

init()

WORKSPACE_ROOT = resolve_workspace_root(Path("out"))
_current_analysis_result = None


def get_current_analysis_result():
    return _current_analysis_result


def activate_completed_analysis(result):
    global _current_analysis_result
    _current_analysis_result = result


def retain_completed_analysis(result):
    CompletedAnalysisSnapshotStore(result.output_dir).publish(result)
    activate_completed_analysis(result)
    return result


def build_investigation_console_controller(
    workspace_root=None,
    *,
    input_func=None,
    output_func=None,
    screen_func=None,
    pause_func=None,
):
    workspace_root = WORKSPACE_ROOT if workspace_root is None else workspace_root
    input_func = input if input_func is None else input_func
    output_func = print if output_func is None else output_func
    screen_func = begin_screen if screen_func is None else screen_func
    pause_func = pause if pause_func is None else pause_func
    repository = InvestigationRepository(workspace_root)
    service = InvestigationWorkspaceService(repository)
    adapter = InvestigationBootstrapAdapter(service)
    return InvestigationConsoleController(
        bootstrap_adapter=adapter,
        workspace_service=service,
        analysis_provider=get_current_analysis_result,
        workspace_root=workspace_root,
        input_func=input_func,
        output_func=output_func,
        screen_func=screen_func,
        pause_func=pause_func,
        snapshot_store=CompletedAnalysisSnapshotStore(Path(workspace_root).parent),
        analysis_activator=activate_completed_analysis,
    )


def build_operations_queue_controller(workspace_controller):
    return OperationsQueueConsoleController(
        queue_service=OperationsQueueService(
            workspace_controller.workspace_service.repository
        ),
        workspace_service=workspace_controller.workspace_service,
        response_action_controller=workspace_controller.response_action_controller,
        finding_controller=workspace_controller.finding_controller,
        input_func=input,
        output_func=print,
        screen_func=begin_screen,
    )


def build_threat_activity_controller(workspace_controller):
    return ThreatActivityConsoleController(
        ThreatActivityOverviewService(
            workspace_controller.workspace_service.repository,
            get_current_analysis_result,
        )
    )


def build_entity_explorer_controller(workspace_controller):
    return EntityExplorerConsoleController(
        EntityExplorerService(EntityObservationService(
            workspace_controller.workspace_service.repository,
            get_current_analysis_result,
        ))
    )


def build_attack_activity_controller(workspace_controller):
    return AttackActivityConsoleController(AttackActivityService(
        workspace_controller.workspace_service.repository,
        get_current_analysis_result,
    ))


def build_cross_investigation_controller(workspace_controller):
    repository = workspace_controller.workspace_service.repository
    return CrossInvestigationConsoleController(CrossInvestigationAnalysisService(
        EntityObservationService(repository, get_current_analysis_result),
        AttackActivityService(repository, get_current_analysis_result),
    ))

def build_temporal_analysis_controller(workspace_controller):
    return TemporalAnalysisConsoleController(TemporalAnalysisService(
        workspace_controller.workspace_service.repository,
        get_current_analysis_result,
    ))

def build_hunt_workspace_controller(workspace_controller):
    repository = workspace_controller.workspace_service.repository
    entity = EntityExplorerService(EntityObservationService(
        repository, get_current_analysis_result,
    ))
    attack = AttackActivityService(repository, get_current_analysis_result)
    temporal = TemporalAnalysisService(repository, get_current_analysis_result)
    return HuntWorkspaceConsoleController(HuntWorkspaceService(
        entity, attack, temporal, get_current_analysis_result,
    ))

def build_reporting_controller(workspace_controller):
    repository = workspace_controller.workspace_service.repository
    operational = OperationalSummaryService(OperationsPrioritizationService(
        OperationsQueueService(repository)
    ))
    return ReportingConsoleController(
        ReportCenterService(Path("out")),
        InvestigationReportService(repository, get_current_analysis_result),
        ExecutiveSummaryService(
            operational,
            ThreatActivityOverviewService(repository, get_current_analysis_result),
            AttackActivityService(repository, get_current_analysis_result),
        ),
        open_report,
    )

def build_system_controller(workspace_controller):
    repository = workspace_controller.workspace_service.repository
    return SystemConsoleController(SystemWorkspaceService(
        repository,
        config_path=Path("config.yml"),
        output_path=Path("out"),
    ))


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

def severity_icon(severity):
    severity = severity.lower()

    if severity == "high":
        return "🔴"
    if severity == "medium":
        return "🟡"
    if severity == "low":
        return "🟢"

    return "⚪"

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

def load_cases():
    return load_cases_file("out/cases.json")


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
    if not sys.stdout.isatty() or os.getenv("TERM", "").lower() == "dumb":
        return
    # Fixed literal command, no user input reaches the shell here.
    os.system("cls" if os.name == "nt" else "clear")  # nosec B605


def pause():
    input("\nPress Enter to return to the menu...")


def run_command(args):
    print("\nRunning command...\n")
    try:
        subprocess.run(args, check=True)
    except subprocess.CalledProcessError:
        print("\nSomething went wrong while running that command.")


def analyze_log_file():
    clear_screen()
    print("ANALYZE LOG FILE")
    print("-" * 50)
    global _current_analysis_result

    input_file = input("Enter log file path: ").strip()

    if not input_file:
        warning("No file entered.")
        pause()
        return

    html_choice = input("Generate HTML report? (y/n): ").lower().strip()

    try:
        _current_analysis_result = retain_completed_analysis(
            run_analysis(
                AnalysisOptions(
                    input_path=Path(input_file),
                    output_dir=Path("out"),
                    report_path=Path("out/report.html") if html_choice == "y" else None,
                    write_report=html_choice == "y",
                )
            )
        )
    except Exception as exc:
        error(f"Analysis failed: {exc}")
        pause()
        return

    success(
        f"Analysis complete: {_current_analysis_result.event_count} events, "
        f"{len(_current_analysis_result.alerts)} alerts, "
        f"{len(_current_analysis_result.cases)} cases."
    )
    pause()


def run_attack_simulation():
    clear_screen()
    print("ATTACK SIMULATION")
    print("-" * 50)
    global _current_analysis_result

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

    generate_command = [
        sys.executable, "-m", "soc_forge.cli",
        "--simulate", scenario,
        "--sim-output", sim_output,
    ]

    run_command(generate_command)

    try:
        _current_analysis_result = retain_completed_analysis(
            run_analysis(
                AnalysisOptions(
                    input_path=Path(sim_output),
                    output_dir=Path("out"),
                    report_path=Path(html_output),
                    write_report=True,
                )
            )
        )
    except Exception as exc:
        error(f"Analysis failed: {exc}")
        pause()
        return

    success(
        f"Analysis complete: {_current_analysis_result.event_count} events, "
        f"{len(_current_analysis_result.alerts)} alerts, "
        f"{len(_current_analysis_result.cases)} cases."
    )
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

    command = [sys.executable, "-m", "soc_forge.cli", "--input", input_file, "--rules-only"]
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

def get_dashboard_stats(workspace_service=None):
    stats = {
        "alerts": 0,
        "cases": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "open": 0,
        "in_progress": 0,
        "escalated": 0,
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

    if workspace_service is not None:
        try:
            summaries = workspace_service.list_investigations()
        except InvestigationRepositoryError:
            summaries = []

        for summary in summaries:
            status = (summary.status or "").lower()

            if status in {"open", "in_progress", "escalated", "closed"}:
                stats[status] += 1

    return stats

def open_report(selected_report=None):
    clear_screen()
    print("OPEN REPORT")
    print("-" * 50)

    if selected_report is not None:
        absolute_path = os.path.abspath(selected_report)
        print(f"Report selected:\n{absolute_path}")
        print("\nOpen with your platform browser or file manager.")
        pause()
        return

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

def main_menu():
    workspace_controller = build_investigation_console_controller()
    operations_queue_service = OperationsQueueService(
        InvestigationRepository(WORKSPACE_ROOT)
    )
    operations_prioritization_service = OperationsPrioritizationService(
        operations_queue_service
    )
    operational_summary_service = OperationalSummaryService(
        operations_prioritization_service
    )
    detection_engineering_service = DetectionEngineeringService(
        alert_loader=load_all_alerts
    )
    detection_engineering_controller = DetectionEngineeringConsoleController(
        detection_engineering_service,
        input_func=input,
        output_func=print,
        screen_func=clear_screen,
        pause_func=pause,
    )
    detection_lab_controller = DetectionLabConsoleController(
        DetectionLabService(analysis_runner=run_analysis),
        detection_engineering_controller.explanation_service,
        input_func=input,
        output_func=print,
        screen_func=clear_screen,
        pause_func=pause,
    )
    detection_coverage_service = DetectionCoverageService(
        rules_path=detection_engineering_service.rules_path,
        rule_loader=detection_engineering_service.rule_loader,
    )
    detection_coverage_controller = DetectionCoverageConsoleController(
        detection_coverage_service,
        DetectionGapService(detection_coverage_service),
        detection_engineering_service,
        detection_engineering_controller.explanation_service,
        input_func=input,
        output_func=print,
        screen_func=clear_screen,
        pause_func=pause,
    )
    while True:
        clear_screen()
        show_dashboard(
            lambda: get_dashboard_stats(workspace_controller.workspace_service),
            get_recent_activity,
            operations_queue_service.summarize,
            lambda: operations_prioritization_service.summarize().top_item,
            operational_summary_service.summarize,
        )

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            detection_menu(
                pause,
                analyze_log_file,
                run_attack_simulation,
                view_alerts,
                run_rules_only,
                search_alerts,
                detection_engineering_controller.show_overview,
                detection_engineering_controller.run_rule_catalog,
                detection_engineering_controller.run_rule_explainability,
                detection_lab_controller,
                detection_coverage_controller.run_coverage,
                detection_coverage_controller.run_gaps,
            )

        elif choice == "2":
            investigations_menu(
                pause,
                view_cases,
                workspace_controller,
            )

        elif choice == "3":
            analysis_menu(
                pause,
                build_threat_activity_controller(workspace_controller),
                build_entity_explorer_controller(workspace_controller),
                build_attack_activity_controller(workspace_controller),
                build_cross_investigation_controller(workspace_controller),
                build_temporal_analysis_controller(workspace_controller),
                build_hunt_workspace_controller(workspace_controller),
            )

        elif choice == "4":
            reporting_menu(
                pause,
                build_reporting_controller(workspace_controller),
            )

        elif choice == "5":
            system_menu(
                pause,
                controller=build_system_controller(workspace_controller),
            )

        elif choice == "6":
            build_operations_queue_controller(workspace_controller).run()

        elif choice == "0":
            print("\nExiting SOC-Forge Analyst Console.")
            sys.exit(0)

        else:
            print("\nInvalid option.")
            pause()

if __name__ == "__main__":
    set_clear_screen(clear_screen)
    startup_screen()
    main_menu()
