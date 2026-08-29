from __future__ import annotations

from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen, screen_output
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb,
    render_message_block, render_metadata, render_panel, resolve_terminal_width,
)

SENSITIVE_NOTICE = (
    "Reports may contain sensitive security telemetry and analyst-authored "
    "content. Review before external sharing."
)


def _screen(panels, *, section, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=width, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "REPORTING", section),
                          width=width, ansi=ansi, unicode=unicode), *panels,
    ))


def render_report_center(reports, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    rows = tuple(
        f"[{index}] {row.filename} | {row.report_type} | {row.path}"
        for index, row in enumerate(reports, 1)
    )
    if not rows:
        rows = tuple(render_message_block(
            "empty", "No existing Analysis Reports were found.",
            width=width - 4, ansi=ansi,
        ).splitlines())
    return _screen((render_panel(rows, title="EXISTING ANALYSIS REPORTS",
                                 width=width, ansi=ansi, unicode=unicode),),
                   section="REPORT CENTER", width=width, ansi=ansi, unicode=unicode)


def render_report_artifact(report, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return _screen((render_panel(render_metadata((
        ("File", report.filename), ("Type", report.report_type),
        ("Path", report.path), ("Available", "Yes" if report.available else "No"),
        ("Modified", report.modified_at or "Unavailable"),
    ), width=width - 4, ansi=ansi, wrap_values=True),
        title="REPORT ARTIFACT", width=width, ansi=ansi, unicode=unicode),
        render_panel(("[1] Open Report", "[0] Back"), title="ACTIONS",
                     width=width, ansi=ansi, unicode=unicode)),
        section="REPORT CENTER", width=width, ansi=ansi, unicode=unicode)


def render_investigation_report(report, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    metadata = render_panel(render_metadata((
        ("ID", report.investigation_id), ("Title", report.title),
        ("Status", report.status), ("Owner", report.owner or "Unassigned"),
        ("Revision", report.revision), ("Created", report.created_at),
        ("Updated", report.updated_at),
        ("Mode", render_badge("summary_mode", report.mode, ansi=ansi)),
    ), width=width - 4, ansi=ansi), title="INVESTIGATION",
        width=width, ansi=ansi, unicode=unicode)
    findings = []
    for label, values in (("ACTIVE", report.active_findings),
                          ("HISTORICAL", report.historical_findings)):
        findings.append(label)
        findings.extend(
            f"{row.finding_id} [{row.confidence.upper()}] {row.title} | "
            f"{row.conclusion} | Limitations: {', '.join(row.limitations) or 'None'}"
            for row in values
        )
        if not values:
            findings.append("None")
    reasoning = (
        *(f"HYPOTHESIS {row.hypothesis_id} [{row.state}] {row.statement}"
          for row in report.hypotheses),
        *(f"DECISION {row.decision_id} {row.outcome}" for row in report.decisions),
        *(f"ANNOTATION {row.annotation_id} {row.body}" for row in report.annotations),
    ) or ("No durable reasoning records.",)
    response = []
    for row in report.response_actions:
        response.extend((
            f"{row.action_id} [{row.priority.upper()}] [{row.status}] {row.title}",
            f"Owner: {row.owner}",
            f"Related Findings: {', '.join(row.finding_ids)}",
            f"Transitions: {len(row.transition_history)}",
            "",
        ))
    if not response:
        response = ["No Response Actions."]
    evidence = (
        f"Selected/Referenced Evidence: {report.evidence_count}",
        *(f"{key}: {count}" for key, count in report.evidence_classifications),
        "Protected evidence values are not revealed in this report.",
    )
    attack = (
        "Tactics: " + (", ".join(report.attack_tactics) or "None explicit"),
        "Techniques: " + (", ".join(report.attack_techniques) or "None explicit"),
    )
    limitations = (
        "Source analysis: " + ("Available" if report.source_analysis_available
                               else "Unavailable; durable analyst state only."),
        *render_message_block("warning", SENSITIVE_NOTICE, width=width - 4,
                              ansi=ansi).splitlines(),
    )
    panels = (
        metadata,
        render_panel(findings, title="ANALYST ASSESSMENT", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(reasoning, title="REASONING", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(response, title="RESPONSE", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(attack, title="OBSERVED ATT&CK", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(evidence, title="EVIDENCE", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(limitations, title="SOURCE LIMITATIONS", width=width,
                     ansi=ansi, unicode=unicode),
    )
    return _screen(panels, section="INVESTIGATION REPORT", width=width,
                   ansi=ansi, unicode=unicode)


def render_executive_summary(summary, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    operations = render_panel(render_metadata((
        ("Investigations", summary.investigation_count),
        ("Investigations With Activity", summary.investigations_with_activity),
        ("Active Findings", summary.active_findings),
        ("Historical Findings", summary.historical_findings),
        ("Open Response Actions", summary.open_response_actions),
        ("Attention Items", summary.attention_items),
        ("Queue Investigations", summary.investigations_represented_in_queue),
        ("Critical / High / Medium / Low",
         f"{summary.critical_attention} / {summary.high_attention} / "
         f"{summary.medium_attention} / {summary.low_attention}"),
    ), width=width - 4, ansi=ansi), title="OPERATIONS",
        width=width, ansi=ansi, unicode=unicode)
    if summary.top_attention:
        item = summary.top_attention
        source = item.queue_item
        top = (f"[{item.priority_tier.upper()}] {source.source_id}",
               f"{source.investigation_title} | {source.investigation_id}",
               source.reason)
    else:
        top = ("Top Attention: None",)
    tactics = tuple(
        f"{row.tactic} | {row.observation_count} observations"
        for row in summary.observed_attack_tactics
    )
    techniques = tuple(
        f"{row.technique_key} | {row.observation_count} observations"
        for row in summary.observed_attack_techniques
    )
    activity = tuple(
        f"{row.timestamp} [{row.origin.upper()}] {row.source_type.upper()} "
        f"{row.source_id} | {row.description}"
        for row in summary.recent_analyst_activity
    ) or ("No recent analyst activity.",)
    context = (
        f"Mode: [{summary.mode.upper()}]",
        "Machine Analysis: " + ("Available" if summary.machine_context_available
                                else "Unavailable"),
        *render_message_block("warning", SENSITIVE_NOTICE, width=width - 4,
                              ansi=ansi).splitlines(),
    )
    return _screen((
        operations,
        render_panel(top, title="TOP ATTENTION", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel((*tactics, *techniques) or ("No observed ATT&CK activity.",),
                     title="OBSERVED ATT&CK", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(activity, title="RECENT ANALYST ACTIVITY", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(context, title="SOURCE CONTEXT", width=width,
                     ansi=ansi, unicode=unicode),
    ), section="EXECUTIVE SUMMARY", width=width, ansi=ansi, unicode=unicode)


def render_export_center(*, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return _screen((render_panel((
        "[1] Investigation Handoff",
        "[2] Analysis Reports",
        "[0] Back",
    ), title="EXPORT CENTER", width=width, ansi=ansi, unicode=unicode),
        render_panel((
            "Investigation Handoff remains authoritative in Investigation Workspace.",
            "Reporting does not duplicate the Handoff schema or export implementation.",
        ), title="OWNERSHIP", width=width, ansi=ansi, unicode=unicode)),
        section="EXPORT CENTER", width=width, ansi=ansi, unicode=unicode)


class ReportingConsoleController:
    def __init__(self, report_center, investigation_reports, executive,
                 open_report, *, input_func=input, output_func=print):
        self.report_center = report_center
        self.investigation_reports = investigation_reports
        self.executive = executive
        self.open_report = open_report
        self.input_func = input_func
        self.output = screen_output(output_func)

    def report_center_run(self):
        reports = self.report_center.list_reports()
        self.output(render_report_center(reports))
        value = self.input_func("\nReport number, or Enter to return: ").strip()
        if not value.isdigit() or not (1 <= int(value) <= len(reports)):
            return
        report = reports[int(value) - 1]
        self.output(render_report_artifact(report))
        if self.input_func("\nSelect option: ").strip() == "1":
            self.open_report(report.path)

    def investigation_report_run(self):
        rows = self.investigation_reports.list_investigations()
        if not rows:
            self.output(_screen((render_panel(("No Investigations available.",),
                title="INVESTIGATION REPORT", width=80),),
                section="INVESTIGATION REPORT"))
            self.input_func("\nPress Enter to go back...")
            return
        choices = "\n".join(f"[{i}] {row.investigation_id} | {row.title}"
                            for i, row in enumerate(rows, 1))
        self.output(_screen((render_panel(choices.splitlines(),
            title="SELECT INVESTIGATION", width=80),),
            section="INVESTIGATION REPORT"))
        value = self.input_func("\nInvestigation number: ").strip()
        if value.isdigit() and 1 <= int(value) <= len(rows):
            self.output(render_investigation_report(
                self.investigation_reports.build(
                    rows[int(value) - 1].investigation_id
                )
            ))
            self.input_func("\nPress Enter to go back...")

    def executive_run(self):
        self.output(render_executive_summary(self.executive.summarize()))
        self.input_func("\nPress Enter to go back...")

    def export_run(self):
        self.output(render_export_center())
        choice = self.input_func("\nSelect option: ").strip()
        if choice == "1":
            self.output(_screen((render_panel((
                "Open Investigations > Investigation Workspaces > Handoff.",
            ), title="INVESTIGATION HANDOFF", width=80),),
                section="EXPORT CENTER"))
            self.input_func("\nPress Enter to go back...")
        elif choice == "2":
            self.report_center_run()


def reporting_menu(pause, controller=None):
    while True:
        begin_screen("REPORTING")
        print(render_breadcrumb(("SOC-FORGE", "REPORTING")))
        menu_group("REPORTING")
        menu_option("1", "Report Center")
        menu_option("2", "Investigation Report")
        menu_option("3", "Executive Summary")
        menu_option("4", "Export Center")
        menu_option("0", "Back")
        choice = input("\nSelect option: ").strip()
        if choice == "0":
            return
        if controller is None:
            error("Reporting workspace is unavailable.")
            pause()
        elif choice == "1":
            controller.report_center_run()
        elif choice == "2":
            controller.investigation_report_run()
        elif choice == "3":
            controller.executive_run()
        elif choice == "4":
            controller.export_run()
        else:
            error("Invalid option.")
            pause()
