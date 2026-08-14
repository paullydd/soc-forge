from __future__ import annotations

from textwrap import wrap
from typing import Iterable

from soc_forge.investigations.summary import InvestigationSummary
from soc_forge.ui.colors import Colors
from soc_forge.ui.terminal import (
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_grouped_menu,
    render_metadata,
    render_message_block,
    render_panel,
    render_section_header,
    resolve_terminal_width,
)


SUMMARY_DRILLDOWN_GROUPS = (
    (
        "INVESTIGATION ANALYSIS",
        (
            ("1", "Evidence Workspace"),
            ("2", "Hypotheses and Decisions"),
            ("3", "Timeline and Pivot Workbench"),
            ("5", "Investigation Findings"),
        ),
    ),
    (
        "OUTPUT & RECOVERY",
        (
            ("4", "Investigation Handoff"),
            ("6", "Load Source Analysis Snapshot"),
        ),
    ),
)


def _wrapped(value: object, width: int) -> tuple[str, ...]:
    text = str(value or "").strip()
    return tuple(
        wrap(
            text,
            width=max(8, width),
            break_long_words=True,
            break_on_hyphens=False,
        )
    ) or ("",)


def _section(title: str, bodies: Iterable[str], *, width: int, ansi: bool | None) -> str:
    parts = [render_section_header(title, width=width, ansi=ansi)]
    parts.extend(bodies)
    return "\n".join(parts)


def _warning_block(message: object, *, width: int, ansi: bool | None) -> str:
    return render_message_block(
        "warning",
        message,
        width=width,
        ansi=ansi,
    )


def render_summary_investigation(
    summary: InvestigationSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = (
        ("ID" if resolved < 40 else "Investigation ID", summary.investigation_id),
        ("Title", summary.title),
        ("State" if resolved < 40 else "Status", render_badge("investigation", summary.status, ansi=ansi)),
        ("Owner", summary.owner or "Unassigned"),
        ("Revision", summary.revision),
        ("Summary Mode", render_badge("summary_mode", summary.mode, ansi=ansi)),
        ("Cases", ", ".join(summary.selected_case_ids) or "None"),
        ("Source analysis", summary.source_analysis_id),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="INVESTIGATION",
        width=resolved,
        ansi=ansi,
    )


def render_analyst_assessment(
    summary: InvestigationSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    content_width = max(8, resolved - 4)
    lines = list(_wrapped(summary.narrative, content_width))
    active = tuple(
        item for item in summary.analyst_findings if item.lifecycle_state == "active"
    )
    for finding in active:
        if lines:
            lines.append("")
        lines.extend(
            render_metadata(
                (
                    ("Finding", finding.finding_id),
                    ("Status", render_badge("finding_status", finding.status, ansi=ansi)),
                    ("Lifecycle", render_badge("finding_lifecycle", finding.lifecycle_state, ansi=ansi)),
                    ("Confidence", render_badge("confidence", finding.confidence, ansi=ansi)),
                    ("Analyst", finding.author),
                ),
                width=content_width,
                ansi=ansi,
            )
        )
    return render_panel(
        lines,
        title="ANALYST ASSESSMENT",
        width=resolved,
        ansi=ansi,
        accent=Colors.GREEN,
    )


def render_summary_state(
    summary: InvestigationSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    states = dict(summary.state.hypothesis_counts_by_state)
    timed = "Unavailable" if summary.timeline is None else summary.timeline.timed_entry_count
    untimed = "Unavailable" if summary.timeline is None else summary.timeline.untimed_entry_count
    if resolved < 72:
        rows = (
            ("Annotations", summary.state.annotation_count),
            ("Selected evidence", summary.state.selected_evidence_count),
            ("Supporting", summary.state.supporting_evidence_count),
            ("Contradicting", summary.state.contradicting_evidence_count),
            ("Context", summary.state.context_evidence_count),
            ("Hypotheses", sum(states.values())),
            ("Open", states.get("open", 0)),
            ("Supported", states.get("supported", 0)),
            ("Rejected", states.get("rejected", 0)),
            ("Inconclusive", states.get("inconclusive", 0)),
            ("Response Actions", f"{summary.response_action_counts.total} total | {summary.response_action_counts.proposed} proposed | {summary.response_action_counts.approved} approved | {summary.response_action_counts.in_progress} in progress | {summary.response_action_counts.completed} completed | {summary.response_action_counts.dismissed} dismissed"),
            ("Decisions", summary.state.decision_count),
            ("Findings", summary.finding_counts.total),
            ("Active Findings", summary.finding_counts.active),
            ("Finding history", summary.finding_counts.superseded),
            ("Response Actions", summary.response_action_counts.total),
            ("Timed entries", timed),
            ("Untimed entries", untimed),
        )
    else:
        rows = (
            (
                "Evidence",
                f"{summary.state.selected_evidence_count} selected | "
                f"{summary.state.supporting_evidence_count} supporting | "
                f"{summary.state.contradicting_evidence_count} contradicting | "
                f"{summary.state.context_evidence_count} context",
            ),
            (
                "Hypotheses",
                f"{sum(states.values())} total | {states.get('open', 0)} open | "
                f"{states.get('supported', 0)} supported",
            ),
            (
                "Hypothesis review",
                f"{states.get('rejected', 0)} rejected | "
                f"{states.get('inconclusive', 0)} inconclusive",
            ),
            (
                "Findings",
                f"{summary.finding_counts.total} total | "
                f"{summary.finding_counts.active} active | "
                f"{summary.finding_counts.superseded} historical",
            ),
            ("Decisions", summary.state.decision_count),
            ("Annotations", summary.state.annotation_count),
            ("Timeline", f"{timed} timed | {untimed} untimed"),
        )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="INVESTIGATION STATE",
        width=resolved,
        ansi=ansi,
    )


def render_machine_context(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    bodies = []
    if summary.mode == "offline":
        bodies.append(_warning_block(
            "Source analysis is not active. Detection context requiring the matching analysis is unavailable.",
            width=width,
            ansi=ansi,
        ))
    elif not summary.findings:
        bodies.append(render_empty_state("No selected-case detection context is available.", width=width, ansi=ansi))
    else:
        for finding in summary.findings:
            severity = ", ".join(
                render_badge("severity", item, ansi=ansi) for item in finding.severities
            ) or "Unknown"
            body = list(render_metadata(
                (
                    ("Case", finding.case_id),
                    ("Severity", severity),
                    ("Rule IDs", ", ".join(finding.rule_ids) or "None"),
                    ("ATT&CK tactics", ", ".join(finding.attack_tactics) or "None"),
                    ("ATT&CK techniques", ", ".join(finding.attack_techniques) or "None"),
                ),
                width=width - 4,
                ansi=ansi,
            ))
            body.extend(_wrapped(f"Title: {finding.title}", width - 4))
            bodies.append(render_panel(body, width=width, ansi=ansi))
    return _section("MACHINE-GENERATED DETECTION CONTEXT", bodies, width=width, ansi=ansi)


def render_evidence(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    bodies = []
    if not summary.evidence:
        bodies.append(render_empty_state("No analyst-selected evidence.", width=width, ansi=ansi))
    for evidence in summary.evidence:
        sensitive = "YES" if evidence.sensitive_content is True else "NO" if evidence.sensitive_content is False else "UNKNOWN"
        body = list(render_metadata(
            (
                ("Evidence ID", evidence.evidence_id),
                ("Type", evidence.evidence_type),
                ("Classification", render_badge("evidence", evidence.classification, ansi=ansi)),
                ("Sensitive", sensitive),
                ("Related cases", ", ".join(evidence.related_case_ids) or "None"),
            ),
            width=width - 4,
            ansi=ansi,
        ))
        body.extend(_wrapped(f"Rationale: {evidence.rationale_summary or 'None'}", width - 4))
        bodies.append(render_panel(body, width=width, ansi=ansi))
    return _section("ANALYST-SELECTED EVIDENCE", bodies, width=width, ansi=ansi)


def render_hypotheses(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    bodies = []
    if not summary.hypotheses:
        bodies.append(render_empty_state("No analyst hypotheses.", width=width, ansi=ansi))
    for hypothesis in summary.hypotheses:
        latest = "None"
        if hypothesis.latest_assessment_outcome:
            latest = f"{hypothesis.latest_assessment_outcome} ({hypothesis.latest_assessment_decision_id})"
        body = list(render_metadata(
            (
                ("Hypothesis", hypothesis.hypothesis_id),
                ("Analyst assessment", render_badge("hypothesis", hypothesis.state, ansi=ansi)),
                ("Supporting evidence", hypothesis.supporting_evidence_count),
                ("Contradicting evidence", hypothesis.contradicting_evidence_count),
                ("Latest assessment", latest),
            ),
            width=width - 4,
            ansi=ansi,
        ))
        body.extend(_wrapped(f"Statement: {hypothesis.statement_summary}", width - 4))
        bodies.append(render_panel(body, width=width, ansi=ansi))
    return _section("ANALYST HYPOTHESES", bodies, width=width, ansi=ansi)


def render_decisions(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    bodies = []
    if not summary.decisions:
        bodies.append(render_empty_state("No analyst decisions.", width=width, ansi=ansi))
    for decision in summary.decisions:
        body = list(render_metadata(
            (
                ("Decision", decision.decision_id),
                ("Type", decision.decision_type),
                ("Outcome", decision.outcome),
                ("Analyst", decision.author or "Unknown"),
                ("Timestamp", decision.timestamp or "Unknown"),
                ("Hypotheses", len(decision.hypothesis_ids)),
                ("Evidence", len(decision.evidence_reference_ids)),
            ),
            width=width - 4,
            ansi=ansi,
        ))
        body.extend(_wrapped(f"Rationale: {decision.rationale_summary or 'None'}", width - 4))
        bodies.append(render_panel(body, width=width, ansi=ansi))
    return _section("ANALYST DECISIONS", bodies, width=width, ansi=ansi)


def _finding_panel(finding, *, width: int, ansi: bool | None, historical: bool) -> str:
    rows = [
        ("Finding", finding.finding_id),
        ("Status", render_badge("finding_status", finding.status, ansi=ansi)),
        ("Lifecycle", render_badge("finding_lifecycle", finding.lifecycle_state, ansi=ansi)),
        ("Confidence", render_badge("confidence", finding.confidence, ansi=ansi)),
        ("Analyst", finding.author),
        ("Basis", f"{finding.evidence_count} evidence | {finding.hypothesis_count} hypotheses | {finding.decision_count} decisions"),
        ("ATT&CK", ", ".join(finding.attack_tactics + finding.attack_techniques) or "None"),
    ]
    if historical:
        rows.extend((
            ("Superseded by", finding.superseded_by_finding_id or "None"),
            ("Reason", finding.supersession_reason or "None"),
            ("Superseded by analyst", finding.supersession_author or "Unknown"),
            ("Superseded at", finding.superseded_at or "Unknown"),
        ))
    body = list(render_metadata(rows, width=width - 4, ansi=ansi))
    body.extend(_wrapped(f"Title: {finding.title}", width - 4))
    body.extend(_wrapped(f"Conclusion: {finding.conclusion}", width - 4))
    for limitation in finding.limitations:
        body.extend(_wrapped(f"Limitation: {limitation}", width - 4))
    if not finding.limitations:
        body.append("Limitations: None")
    return render_panel(
        body,
        width=width,
        ansi=ansi,
        accent=Colors.GRAY if historical else Colors.GREEN,
    )


def render_findings(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    active = tuple(item for item in summary.analyst_findings if item.lifecycle_state == "active")
    historical = tuple(item for item in summary.analyst_findings if item.lifecycle_state == "superseded")
    parts = [
        render_section_header("ACTIVE FINDINGS", width=width, ansi=ansi),
        *(
            (_finding_panel(item, width=width, ansi=ansi, historical=False) for item in active)
            if active else (render_empty_state("No active analyst-authored findings.", width=width, ansi=ansi),)
        ),
        "",
        render_section_header("HISTORICAL / SUPERSEDED FINDINGS", width=width, ansi=ansi),
        *(
            (_finding_panel(item, width=width, ansi=ansi, historical=True) for item in historical)
            if historical else (render_empty_state("No historical analyst-authored findings.", width=width, ansi=ansi),)
        ),
    ]
    return "\n".join(parts)


def render_response_actions(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    parts = [render_section_header("RESPONSE ACTIONS", width=width, ansi=ansi)]
    parts.append(_warning_block("Response Actions record analyst-controlled work and do not represent executed remediation.", width=width, ansi=ansi))
    if not summary.response_actions:
        parts.append(render_empty_state("No analyst-controlled Response Actions.", width=width, ansi=ansi))
    for action in summary.response_actions:
        body = list(render_metadata((("Action", action.action_id), ("Type", action.action_type), ("Priority", render_badge("priority", action.priority, ansi=ansi)), ("Status", render_badge("response_action_status", action.status, ansi=ansi)), ("Owner", action.owner), ("Related Findings", ", ".join(action.finding_ids)), ("Lifecycle transitions", action.transition_count)), width=width - 4, ansi=ansi))
        body.extend(_wrapped(f"Title: {action.title}", width - 4))
        body.extend(_wrapped(f"Rationale: {action.rationale}", width - 4))
        parts.append(render_panel(body, width=width, ansi=ansi))
    return "\n".join(parts)


def render_timeline(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    if summary.timeline is None:
        body = (_warning_block("Chronology requires the matching source analysis.", width=width - 4, ansi=ansi),)
    else:
        rows = [
            ("First timed activity", summary.timeline.first_timed_activity or "None"),
            ("Last timed activity", summary.timeline.last_timed_activity or "None"),
            ("Timed entries", summary.timeline.timed_entry_count),
            ("Untimed entries", summary.timeline.untimed_entry_count),
        ]
        body = list(render_metadata(rows, width=width - 4, ansi=ansi))
        for index, item in enumerate(summary.timeline.milestones, start=1):
            body.extend(_wrapped(
                f"Milestone {index}: {item.timestamp} | {item.entry_type} | {item.title}",
                width - 4,
            ))
    return render_panel(body, title="TIMELINE SUMMARY", width=width, ansi=ansi)


def render_limitations(summary: InvestigationSummary, *, width: int, ansi: bool | None) -> str:
    bodies = [
        _warning_block(item, width=width, ansi=ansi)
        for item in summary.limitations
    ]
    if not bodies:
        bodies.append(render_empty_state("No summary limitations.", width=width, ansi=ansi))
    return _section("LIMITATIONS", bodies, width=width, ansi=ansi)


def render_investigation_summary(
    summary: InvestigationSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    parts = [
        render_breadcrumb(("SOC-FORGE", "INVESTIGATIONS", summary.investigation_id, "SUMMARY"), width=resolved, ansi=ansi),
        _warning_block("Terminal scrollback may retain investigation and analyst-authored content.", width=resolved, ansi=ansi),
        render_summary_investigation(summary, width=resolved, ansi=ansi),
    ]
    if summary.mode == "offline":
        parts.append(_warning_block(
            "Source analysis is not active. Persisted analyst state remains available; machine detection and chronology context requiring the matching analysis are omitted.",
            width=resolved,
            ansi=ansi,
        ))
    parts.extend((
        render_analyst_assessment(summary, width=resolved, ansi=ansi),
        render_summary_state(summary, width=resolved, ansi=ansi),
        render_machine_context(summary, width=resolved, ansi=ansi),
        render_evidence(summary, width=resolved, ansi=ansi),
        render_hypotheses(summary, width=resolved, ansi=ansi),
        render_decisions(summary, width=resolved, ansi=ansi),
        render_findings(summary, width=resolved, ansi=ansi),
        render_response_actions(summary, width=resolved, ansi=ansi),
        render_timeline(summary, width=resolved, ansi=ansi),
        render_limitations(summary, width=resolved, ansi=ansi),
        render_grouped_menu(SUMMARY_DRILLDOWN_GROUPS, back_option=("0", "Back"), width=resolved, ansi=ansi),
    ))
    return "\n\n".join(parts)
