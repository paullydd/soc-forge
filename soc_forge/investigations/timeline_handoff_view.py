from __future__ import annotations

from textwrap import wrap
from typing import Iterable

from soc_forge.investigations.handoff import (
    HandoffManifestSummary,
    HandoffPreview,
    HandoffResult,
)
from soc_forge.investigations.query_models import (
    InvestigationTimeline,
    InvestigationTimelineEntry,
    PivotResult,
    RelatedEntitiesResult,
)
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.colors import Colors
from soc_forge.ui.terminal import (
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_grouped_menu,
    render_metadata,
    render_message_block,
    render_panel,
    resolve_terminal_width,
)


TIMELINE_MENU_GROUPS = (
    (
        "TIMELINE REVIEW",
        (
            ("1", "Investigation Timeline"),
            ("2", "Filter Timeline"),
            ("3", "Browse Entities"),
            ("4", "Pivot from Entity"),
        ),
    ),
    (
        "RELATIONSHIPS",
        (
            ("5", "Inspect Evidence Relationship"),
            ("6", "Inspect Hypothesis Relationships"),
            ("7", "View Query Limitations"),
        ),
    ),
    ("WORKBENCH", (("8", "Refresh Workbench"),)),
)
PIVOT_MENU_OPTIONS = (
    ("1", "Events"),
    ("2", "Alerts"),
    ("3", "Cases"),
    ("4", "Evidence"),
    ("5", "Hypotheses"),
    ("6", "Related Entities"),
    ("7", "Timeline"),
)
HANDOFF_MENU_GROUPS = (
    (
        "HANDOFF REVIEW",
        (
            ("1", "Preview Handoff"),
            ("4", "View Last Handoff Result"),
        ),
    ),
    (
        "HANDOFF OPERATIONS",
        (
            ("2", "Export Handoff"),
            ("3", "Validate Handoff Bundle"),
        ),
    ),
)


def _wrapped(value: object, width: int) -> tuple[str, ...]:
    text = " ".join(str(value or "").split())
    return tuple(
        wrap(
            text,
            width=max(8, width),
            break_long_words=True,
            break_on_hyphens=False,
        )
    ) or ("",)


def _breadcrumb(
    current: WorkspaceResult,
    leaf: str,
    width: int,
    ansi: bool | None,
) -> str:
    return render_breadcrumb(
        (
            "SOC-FORGE",
            "INVESTIGATIONS",
            current.investigation.investigation_id,
            leaf,
        ),
        width=width,
        ansi=ansi,
    )


def render_timeline_workspace(
    current: WorkspaceResult,
    timeline: InvestigationTimeline | None,
    *,
    source_mode: str,
    stale: bool = False,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = (
        ("Timed entries", len(timeline.entries) if timeline is not None else "Unavailable"),
        (
            "Untimed entries",
            len(timeline.untimed_entries) if timeline is not None else "Unavailable",
        ),
        ("Source analysis", render_badge("availability", source_mode, ansi=ansi)),
        ("Revision", current.revision),
    )
    parts = [
        _breadcrumb(current, "TIMELINE", width=resolved, ansi=ansi),
        render_message_block("warning",
            "Timeline/Pivot Workbench is read only. Terminal scrollback may retain displayed values.",
            width=resolved,
            ansi=ansi,
        ),
        render_panel(
            render_metadata(rows, width=resolved - 4, ansi=ansi),
            title="TIMELINE STATE",
            width=resolved,
            ansi=ansi,
        ),
    ]
    if timeline is None:
        parts.append(
            render_message_block("warning",
                "Chronology requires the matching completed analysis. The durable investigation remains available.",
                width=resolved,
                ansi=ansi,
            )
        )
    if stale:
        parts.append(
            render_message_block("warning",
                "The investigation changed. Refresh the workbench before continuing with reasoning overlays.",
                width=resolved,
                ansi=ansi,
            )
        )
    parts.append(
        render_grouped_menu(
            TIMELINE_MENU_GROUPS,
            back_option=("0", "Back"),
            width=resolved,
            ansi=ansi,
        )
    )
    return "\n\n".join(parts)


def _timeline_badges(entry: InvestigationTimelineEntry, ansi: bool | None) -> str:
    return " ".join(
        (
            render_badge("activity_origin", entry.context_kind, ansi=ansi),
            render_badge("timeline_entry", entry.entry_type, ansi=ansi),
        )
    )


def render_timeline(
    timeline: InvestigationTimeline,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> tuple[str, tuple[InvestigationTimelineEntry, ...]]:
    resolved = resolve_terminal_width(width)
    lines: list[str] = ["CHRONOLOGICAL ACTIVITY"]
    index = 1
    if not timeline.entries:
        lines.append(render_empty_state("No timed entries.", width=resolved, ansi=ansi))
    for entry in timeline.entries:
        lines.extend(_timeline_entry_lines(index, entry, width=resolved, ansi=ansi))
        index += 1
    lines.extend(("", "UNTIMED ACTIVITY"))
    if not timeline.untimed_entries:
        lines.append(render_empty_state("No untimed entries.", width=resolved, ansi=ansi))
    for entry in timeline.untimed_entries:
        lines.extend(_timeline_entry_lines(index, entry, resolved, ansi, untimed=True))
        if entry.limitations:
            lines.extend(_wrapped(f"Untimed reason: {entry.limitations[0]}", resolved))
        index += 1
    return "\n".join(lines), timeline.entries + timeline.untimed_entries


def _timeline_entry_lines(
    index: int,
    entry: InvestigationTimelineEntry,
    width: int,
    ansi: bool | None,
    *,
    untimed: bool = False,
) -> tuple[str, ...]:
    timestamp = "Untimed" if untimed else entry.timestamp or "Untimed"
    header = f"[{index}] {timestamp}  {_timeline_badges(entry, ansi)}"
    lines = list(_wrapped(header, width))
    lines.extend(_wrapped(entry.title, width - 2))
    details = tuple(
        value
        for value in (
            entry.host,
            entry.user,
            entry.rule_id,
            ", ".join(entry.case_ids) if entry.case_ids else None,
            f"Analyst evidence: {entry.evidence_classification.title()}"
            if entry.evidence_classification
            else None,
            "Hypothesis overlay" if entry.hypothesis_overlays else None,
            "Decision overlay" if entry.decision_overlays else None,
            "SENSITIVE" if entry.sensitive_fields else None,
        )
        if value
    )
    if details:
        lines.extend(_wrapped(" | ".join(details), width - 2))
    lines.extend(_wrapped(f"Entry ID: {entry.entry_id}", width - 2))
    return tuple(lines)


def render_timeline_entry_detail(
    entry: InvestigationTimelineEntry,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = (
        ("Entry ID", entry.entry_id),
        ("Timestamp", entry.timestamp or "Untimed"),
        ("Entry type", entry.entry_type),
        ("Origin", render_badge("activity_origin", entry.context_kind, ansi=ansi)),
        ("Source ID", entry.source_id),
        ("Source analysis", entry.source_analysis_id),
        ("Case IDs", ", ".join(entry.case_ids) or "None"),
        ("Host", entry.host or "None"),
        ("User", entry.user or "None"),
        ("IP", entry.ip or "None"),
        ("Process", entry.process or "None"),
        ("Rule ID", entry.rule_id or "None"),
        ("Severity", entry.severity or "None"),
        ("ATT&CK tactic", entry.attack_tactic or "None"),
        ("ATT&CK technique", entry.attack_technique or "None"),
        ("Evidence", entry.evidence_id or "None"),
        ("Classification", entry.evidence_classification or "None"),
        ("Hypothesis IDs", ", ".join(entry.related_hypothesis_ids) or "None"),
        ("Decision IDs", ", ".join(entry.related_decision_ids) or "None"),
        ("Sensitive fields", ", ".join(entry.sensitive_fields) or "None"),
        ("Provenance fields", ", ".join(entry.provenance_fields) or "None"),
    )
    body = list(render_metadata(rows, width=resolved - 4, ansi=ansi))
    for label, value in (
        ("Title", entry.title),
        ("Summary", entry.summary),
        ("Why this entry is present", entry.relationship_reason),
        ("Limitations", "; ".join(entry.limitations) or "None"),
    ):
        body.extend(_wrapped(f"{label}: {value}", resolved - 4))
    for overlay in entry.hypothesis_overlays:
        body.extend(
            _wrapped(
                f"Hypothesis overlay: {overlay.hypothesis_id} | {overlay.relationship} | {overlay.state}",
                resolved - 4,
            )
        )
    for overlay in entry.decision_overlays:
        body.extend(
            _wrapped(
                f"Decision overlay: {overlay.decision_id} | {overlay.decision_type}",
                resolved - 4,
            )
        )
    return render_panel(
        body,
        title="TIMELINE ENTRY - READ ONLY",
        width=resolved,
        ansi=ansi,
    )



def render_pivot_menu(
    entity_type: str,
    display_value: str,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    return "\n\n".join(
        (
            render_panel(
                render_metadata(
                    (("Entity type", entity_type), ("Entity", display_value)),
                    width=resolved - 4,
                    ansi=ansi,
                ),
                title="PIVOT WORKBENCH",
                width=resolved,
                ansi=ansi,
            ),
            render_grouped_menu(
                (("PIVOT RESULTS", PIVOT_MENU_OPTIONS),),
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_pivot_result(
    label: str,
    result: PivotResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    parts = [
        render_panel(
            render_metadata(
                (
                    ("Pivot", f"{result.entity.entity_type}: {result.entity.display_value}"),
                    ("Result type", label),
                    ("Matches", len(result.matches)),
                ),
                width=resolved - 4,
                ansi=ansi,
            ),
            title="PIVOT RESULTS",
            width=resolved,
            ansi=ansi,
        )
    ]
    if not result.matches:
        parts.append(render_empty_state("No explicit relationships found.", width=resolved, ansi=ansi))
    for match in result.matches:
        body = list(
            render_metadata(
                (
                    ("Source ID", match.source_id),
                    ("Source type", match.source_type),
                    ("First seen", match.first_seen or "Untimed"),
                    ("Cases", ", ".join(match.case_ids) or "None"),
                    ("Relationship", match.relationship_type),
                    ("Classification", match.evidence_classification or "None"),
                ),
                width=resolved - 4,
                ansi=ansi,
            )
        )
        body.extend(_wrapped(f"Why: {match.relationship_reason}", resolved - 4))
        if match.evidence_classification:
            body.extend(
                _wrapped(
                    f"Analyst evidence: {match.evidence_classification.title()}",
                    resolved - 4,
                )
            )
        for item in match.hypothesis_overlays:
            body.extend(_wrapped(f"Hypothesis: {item.hypothesis_id} | {item.relationship} | {item.state}", resolved - 4))
        for item in match.decision_overlays:
            body.extend(_wrapped(f"Decision: {item.decision_id} | {item.decision_type}", resolved - 4))
        parts.append(render_panel(body, width=resolved, ansi=ansi))
    return "\n\n".join(parts)


def render_related_entities(
    result: RelatedEntitiesResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    parts = [
        render_panel(
            render_metadata(
                (
                    ("Pivot", f"{result.entity.entity_type}: {result.entity.display_value}"),
                    ("Relationships", len(result.relationships)),
                ),
                width=resolved - 4,
                ansi=ansi,
            ),
            title="RELATED ENTITIES",
            width=resolved,
            ansi=ansi,
        )
    ]
    if not result.relationships:
        parts.append(render_empty_state("No observed relationships.", width=resolved, ansi=ansi))
    for item in result.relationships:
        body = list(
            render_metadata(
                (
                    ("Entity type", item.entity.entity_type),
                    ("Display value", item.entity.display_value),
                    ("Normalized", item.entity.normalized_value),
                    ("Count", item.count),
                    ("First seen", item.first_seen or "Untimed"),
                    ("Last seen", item.last_seen or "Untimed"),
                    ("Sources", ", ".join(item.source_ids)),
                ),
                width=resolved - 4,
                ansi=ansi,
            )
        )
        body.extend(_wrapped(f"Why: {item.relationship_reason}", resolved - 4))
        parts.append(render_panel(body, width=resolved, ansi=ansi))
    return "\n\n".join(parts)


def render_handoff_workspace(
    current: WorkspaceResult,
    *,
    source_available: bool,
    last_result: HandoffResult | None,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    findings = current.investigation.findings
    rows = (
        ("Investigation", current.investigation.investigation_id),
        ("Revision", current.revision),
        (
            "Source analysis",
            render_badge(
                "availability",
                "available" if source_available else "offline",
                ansi=ansi,
            ),
        ),
        ("Findings", len(findings)),
        ("Active Findings", sum(item.lifecycle_state == "active" for item in findings)),
        (
            "Historical",
            sum(item.lifecycle_state == "superseded" for item in findings),
        ),
        ("Last export", "Available" if last_result is not None else "None"),
    )
    return "\n\n".join(
        (
            _breadcrumb(current, "HANDOFF", width=resolved, ansi=ansi),
            render_message_block("warning",
                "Read-only snapshot/export workflow. Investigation state is not modified.",
                width=resolved,
                ansi=ansi,
            ),
            render_panel(
                render_metadata(rows, width=resolved - 4, ansi=ansi),
                title="HANDOFF STATE",
                width=resolved,
                ansi=ansi,
            ),
            render_grouped_menu(
                HANDOFF_MENU_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_handoff_preview(
    preview: HandoffPreview,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    parts = [
        render_panel(
            render_metadata(
                (
                    ("Investigation", preview.investigation_id),
                    ("Title", preview.title),
                    ("Owner", preview.owner or "Unassigned"),
                    ("Status", preview.status),
                    ("Revision", preview.revision),
                    (
                        "Mode",
                        render_badge("availability", preview.mode, ansi=ansi),
                    ),
                    ("Source analysis", preview.source_analysis_id),
                    (
                        "Source context",
                        "Available"
                        if preview.source_analysis_available
                        else "Unavailable",
                    ),
                    ("Selected cases", preview.selected_case_count),
                    ("Selected evidence", preview.analyst_evidence_count),
                    ("Hypotheses", preview.hypothesis_count),
                    ("Decisions", preview.decision_count),
                    ("Response Actions", preview.response_action_count),
                    ("Annotations", preview.annotation_count),
                    ("Timed entries", preview.timed_entry_count),
                    ("Untimed entries", preview.untimed_entry_count),
                ),
                width=resolved - 4,
                ansi=ansi,
            ),
            title="INVESTIGATION",
            width=resolved,
            ansi=ansi,
        )
    ]
    if not preview.source_analysis_available:
        parts.append(
            render_message_block(
                "warning",
                "OFFLINE handoff: durable investigation state is available. "
                "Analysis-derived timeline entries and source artifacts are unavailable.",
                width=resolved,
                ansi=ansi,
            )
        )
    active = tuple(item for item in preview.findings if item.lifecycle_state == "active")
    historical = tuple(item for item in preview.findings if item.lifecycle_state == "superseded")
    for heading, findings in (
        ("ACTIVE FINDINGS", active),
        ("HISTORICAL / SUPERSEDED FINDINGS", historical),
    ):
        parts.append("\n".join(_wrapped(heading, resolved)))
        if not findings:
            parts.append(render_empty_state(f"No {heading.lower()}.", width=resolved, ansi=ansi))
        for finding in findings:
            body = list(
                render_metadata(
                    (
                        ("Finding ID", finding.finding_id),
                        ("Status", render_badge("finding_status", finding.status, ansi=ansi)),
                        ("Lifecycle", render_badge("finding_lifecycle", finding.lifecycle_state, ansi=ansi)),
                        ("Confidence", render_badge("confidence", finding.confidence, ansi=ansi)),
                        ("Analyst", finding.author),
                        ("Updated", finding.updated_at),
                        (
                            "Basis",
                            f"{finding.evidence_count} evidence | "
                            f"{finding.hypothesis_count} hypotheses | "
                            f"{finding.decision_count} decisions",
                        ),
                        ("Evidence IDs", ", ".join(finding.evidence_ids) or "None"),
                        ("Hypothesis IDs", ", ".join(finding.hypothesis_ids) or "None"),
                        ("Decision IDs", ", ".join(finding.decision_ids) or "None"),
                        ("ATT&CK tactics", ", ".join(finding.attack_tactics) or "None"),
                        (
                            "ATT&CK techniques",
                            ", ".join(finding.attack_techniques) or "None",
                        ),
                        ("Supersedes", finding.supersedes_finding_id or "None"),
                        ("Superseded by", finding.superseded_by_finding_id or "None"),
                    ),
                    width=resolved - 4,
                    ansi=ansi,
                )
            )
            body.extend(_wrapped(f"Title: {finding.title}", resolved - 4))
            body.extend(_wrapped(f"Conclusion: {finding.conclusion}", resolved - 4))
            if finding.supersession_reason:
                body.extend(_wrapped(f"Supersession reason: {finding.supersession_reason}", resolved - 4))
            if finding.supersession_author:
                body.extend(_wrapped(f"Supersession author: {finding.supersession_author}", resolved - 4))
            if finding.superseded_at:
                body.extend(_wrapped(f"Superseded at: {finding.superseded_at}", resolved - 4))
            for limitation in finding.limitations:
                body.extend(_wrapped(f"Limitation: {limitation}", resolved - 4))
            parts.append(render_panel(body, width=resolved, ansi=ansi))
    parts.append("\n".join(_wrapped("RESPONSE ACTIONS", resolved)))
    parts.append("\n".join(_wrapped("Response Actions record analyst-controlled work and do not represent executed remediation.", resolved)))
    if not preview.response_actions:
        parts.append(render_empty_state("No analyst-controlled Response Actions.", width=resolved, ansi=ansi))
    for action in preview.response_actions:
        body = list(render_metadata((("Action ID", action.action_id), ("Type", action.action_type), ("Priority", render_badge("priority", action.priority, ansi=ansi)), ("Current status", render_badge("response_action_status", action.status, ansi=ansi)), ("Owner", action.owner), ("Related Findings", ", ".join(action.finding_ids)), ("Lifecycle transitions", action.transition_count)), width=resolved - 4, ansi=ansi))
        body.extend(_wrapped(f"Title: {action.title}", resolved - 4))
        parts.append(render_panel(body, width=resolved, ansi=ansi))
    parts.append(
        render_panel(
            render_metadata(
                (
                    ("Available", ", ".join(preview.available_artifact_keys) or "None"),
                    (
                        "Required artifacts",
                        render_badge(
                            "availability",
                            "available" if preview.required_artifacts_available else "missing",
                            ansi=ansi,
                        ),
                    ),
                    (
                        "Missing required",
                        ", ".join(preview.missing_required_artifact_keys) or "None",
                    ),
                    (
                        "Missing optional",
                        ", ".join(preview.missing_optional_artifact_keys) or "None",
                    ),
                ),
                width=resolved - 4,
                ansi=ansi,
            ),
            title="ARTIFACTS",
            width=resolved,
            ansi=ansi,
        )
    )
    parts.append(render_message_block("warning", preview.sensitive_data_warning, width=resolved, ansi=ansi))
    parts.append(render_message_block("warning", "Terminal scrollback may retain displayed handoff metadata.", width=resolved, ansi=ansi))
    return "\n\n".join(parts)


def render_handoff_result(
    result: HandoffResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    body = list(
        render_metadata(
            (
                ("Status", render_badge("validation", result.validation_status, ansi=ansi)),
                ("Handoff ID", result.handoff_id),
                ("Investigation", result.investigation_id),
                ("Revision", result.revision),
                ("Files", len(result.files)),
            ),
            width=resolved - 4,
            ansi=ansi,
        )
    )
    body.extend(
        render_metadata(
            (
                ("Output path", result.output_path),
                ("Manifest path", result.manifest_path),
            ),
            width=resolved - 4,
            ansi=ansi,
            wrap_values=True,
        )
    )
    for warning in result.warnings:
        body.extend(_wrapped(f"Warning: {warning}", resolved - 4))
    body.append("Investigation state was not modified.")
    return render_panel(body, title="HANDOFF EXPORT COMPLETE", width=resolved, ansi=ansi)


def render_handoff_manifest(
    summary: HandoffManifestSummary,
    *,
    validation: bool = False,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = [
        ("Status", render_badge("validation", "valid", ansi=ansi)),
        ("Handoff ID", summary.handoff_id),
        ("Investigation", summary.investigation_id),
        ("Schema version", summary.schema_version),
        ("Source analysis", summary.source_analysis_id),
        ("Revision", summary.revision),
        ("Owner", summary.owner or "Unassigned"),
        ("Investigation status", summary.status),
        ("Selected cases", ", ".join(summary.selected_case_ids) or "None"),
        ("Files verified", len(summary.files)),
    ]
    if validation:
        rows.append(("Digest status", "verified"))
    body = list(render_metadata(rows, width=resolved - 4, ansi=ansi))
    if validation:
        body.extend(_wrapped("Reference integrity: verified", resolved - 4))
    if not validation:
        body.append("File inventory:")
        for item in summary.files:
            body.extend(
                _wrapped(
                    f"{item.filename} | {item.logical_type} | {item.size} bytes | SHA-256 {item.sha256}",
                    resolved - 4,
                )
            )
    for limitation in summary.limitations:
        body.extend(_wrapped(f"Warning: {limitation}", resolved - 4))
    body.extend(_wrapped(f"Sensitive data notice: {summary.sensitive_data_warning}", resolved - 4))
    body.extend(_wrapped("Terminal scrollback may retain displayed handoff metadata.", resolved - 4))
    return render_panel(
        body,
        title="HANDOFF VALIDATION" if validation else "HANDOFF MANIFEST",
        width=resolved,
        ansi=ansi,
        accent=Colors.GREEN,
    )
