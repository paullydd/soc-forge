from __future__ import annotations

from typing import Any

from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.terminal import (
    render_badge,
    render_breadcrumb,
    render_grouped_menu,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


INVESTIGATION_WORKSPACE_GROUPS = (
    (
        "ANALYSIS",
        (
            ("1", "Investigation Summary"),
            ("10", "Evidence Workspace"),
            ("11", "Hypotheses and Decisions"),
            ("12", "Investigation Findings"),
            ("13", "Timeline and Pivot Workbench (Read Only)"),
            ("17", "Investigation Replay (Read Only)"),
            ("18", "Entity Relationship Explorer (Read Only)"),
        ),
    ),
    (
        "RESPONSE",
        (("16", "Response Actions"),),
    ),
    (
        "CASE MANAGEMENT",
        (
            ("2", "Assign or Clear Owner"),
            ("3", "Change Status"),
            ("4", "Reopen Investigation"),
        ),
    ),
    (
        "ANNOTATIONS & DECISIONS",
        (
            ("5", "View Annotations"),
            ("6", "Add Annotation"),
            ("7", "Edit Annotation"),
            ("8", "Remove Annotation"),
            ("9", "View Decisions"),
        ),
    ),
    (
        "OUTPUT & RECOVERY",
        (
            ("14", "Investigation Handoff (Read Only)"),
            ("15", "Load Source Analysis Snapshot"),
        ),
    ),
)


def _selected_case_ids(current: WorkspaceResult) -> tuple[str, ...]:
    return tuple(
        reference.source_id
        for reference in current.investigation.evidence_references
        if reference.origin == "scope" and reference.source_type == "case"
    )


def render_investigation_overview(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    investigation = current.investigation
    metadata = investigation.metadata
    rows: tuple[tuple[str, Any], ...] = (
        ("ID" if resolved < 40 else "Investigation ID", investigation.investigation_id),
        ("Title", metadata.title),
        ("State" if resolved < 40 else "Status", render_badge("investigation", metadata.status, ansi=ansi)),
        ("Owner", metadata.owner or "Unassigned"),
        ("Revision", current.revision),
        ("Source analysis ID", investigation.analysis_id),
        ("Selected case IDs", ", ".join(_selected_case_ids(current)) or "None"),
        ("Created", metadata.created_at),
        ("Updated", metadata.updated_at),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="INVESTIGATION OVERVIEW",
        width=resolved,
        ansi=ansi,
    )


def render_investigation_state(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    investigation = current.investigation
    references = investigation.evidence_references
    selected = tuple(
        item for item in references if item.origin == "analyst_selection"
    )
    scope_count = sum(item.origin == "scope" for item in references)
    classifications = {
        name: sum(item.classification == name for item in selected)
        for name in ("supporting", "contradicting", "context")
    }
    hypothesis_counts = {
        state: sum(item.state == state for item in investigation.hypotheses)
        for state in ("open", "supported", "rejected", "inconclusive")
    }
    active_findings = sum(
        item.lifecycle_state == "active" for item in investigation.findings
    )
    historical_findings = sum(
        item.lifecycle_state == "superseded" for item in investigation.findings
    )
    if resolved < 72:
        rows = (
            ("Scope references", scope_count),
            ("Analyst-selected", len(selected)),
            ("Supporting", classifications["supporting"]),
            ("Contradicting", classifications["contradicting"]),
            ("Context", classifications["context"]),
            ("Hypotheses", len(investigation.hypotheses)),
            ("Open", hypothesis_counts["open"]),
            ("Supported", hypothesis_counts["supported"]),
            ("Rejected", hypothesis_counts["rejected"]),
            ("Inconclusive", hypothesis_counts["inconclusive"]),
            ("Findings", len(investigation.findings)),
            ("Active Findings", active_findings),
            ("Finding history", historical_findings),
            ("Decisions", len(investigation.decisions)),
            ("Annotations", len(investigation.annotations)),
        )
    else:
        rows = (
            ("Evidence", f"{scope_count} scope | {len(selected)} selected"),
            (
                "Evidence classes",
                f"{classifications['supporting']} supporting | "
                f"{classifications['contradicting']} contradicting | "
                f"{classifications['context']} context",
            ),
            (
                "Hypotheses",
                f"{len(investigation.hypotheses)} total | "
                f"{hypothesis_counts['open']} open | "
                f"{hypothesis_counts['supported']} supported",
            ),
            (
                "Hypothesis review",
                f"{hypothesis_counts['rejected']} rejected | "
                f"{hypothesis_counts['inconclusive']} inconclusive",
            ),
            (
                "Findings",
                f"{len(investigation.findings)} total | {active_findings} active | "
                f"{historical_findings} historical",
            ),
            ("Decisions", len(investigation.decisions)),
            ("Annotations", len(investigation.annotations)),
        )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="INVESTIGATION STATE",
        width=resolved,
        ansi=ansi,
    )


def render_investigation_workspace(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    return "\n\n".join(
        (
            render_breadcrumb(
                (
                    "SOC-FORGE",
                    "INVESTIGATIONS",
                    current.investigation.investigation_id,
                ),
                width=resolved,
                ansi=ansi,
            ),
            render_investigation_overview(current, width=resolved, ansi=ansi),
            render_investigation_state(current, width=resolved, ansi=ansi),
            render_grouped_menu(
                INVESTIGATION_WORKSPACE_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )
