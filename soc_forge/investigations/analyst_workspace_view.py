from __future__ import annotations

from textwrap import wrap
from typing import Iterable

from soc_forge.investigations.evidence_models import EvidenceCandidate
from soc_forge.investigations.models import (
    Decision,
    EvidenceReference,
    Hypothesis,
    InvestigationFinding,
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
    render_warning,
    resolve_terminal_width,
)


EVIDENCE_MENU_GROUPS = (
    (
        "EVIDENCE REVIEW",
        (
            ("1", "Browse Evidence Candidates"),
            ("2", "View Selected Evidence"),
            ("3", "Inspect Selected Evidence"),
        ),
    ),
    (
        "EVIDENCE MANAGEMENT",
        (
            ("4", "Update Selected Evidence"),
            ("5", "Remove Selected Evidence"),
        ),
    ),
)
REASONING_MENU_GROUPS = (
    (
        "REASONING REVIEW",
        (
            ("1", "View Reasoning Summary"),
            ("2", "List Hypotheses"),
            ("4", "Open Hypothesis"),
            ("5", "View Decisions"),
        ),
    ),
    (
        "REASONING AUTHORING",
        (
            ("3", "Create Hypothesis"),
            ("6", "Record Investigation Decision"),
        ),
    ),
)
FINDINGS_MENU_GROUPS = (
    (
        "FINDINGS REVIEW",
        (
            ("1", "List Findings"),
            ("3", "Open Finding"),
        ),
    ),
    ("FINDINGS AUTHORING", (("2", "Create Finding"),)),
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


def _breadcrumb(current: WorkspaceResult, leaf: str, width: int, ansi: bool | None) -> str:
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


def render_evidence_workspace(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    references = current.investigation.evidence_references
    selected = tuple(item for item in references if item.origin == "analyst_selection")
    rows = (
        ("Scope references", sum(item.origin == "scope" for item in references)),
        ("Selected evidence", len(selected)),
        ("Supporting", sum(item.classification == "supporting" for item in selected)),
        ("Contradicting", sum(item.classification == "contradicting" for item in selected)),
        ("Context", sum(item.classification == "context" for item in selected)),
    )
    return "\n\n".join(
        (
            _breadcrumb(current, "EVIDENCE", width=resolved, ansi=ansi),
            render_panel(
                render_metadata(rows, width=resolved - 4, ansi=ansi),
                title="EVIDENCE STATE",
                width=resolved,
                ansi=ansi,
            ),
            render_grouped_menu(
                EVIDENCE_MENU_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_evidence_candidate(
    number: int,
    candidate: EvidenceCandidate,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    body = list(
        render_metadata(
            (
                ("Candidate", number),
                ("Evidence ID", candidate.evidence_id),
                ("Type", candidate.evidence_type),
                ("Timestamp", candidate.timestamp or "Unknown"),
                ("Source identifier", candidate.source_id),
                ("Rule", candidate.rule_id or "None"),
                ("Related cases", ", ".join(candidate.case_ids) or "None"),
                (
                    "Sensitivity",
                    render_badge(
                        "sensitivity",
                        "sensitive" if candidate.sensitive_fields else "standard",
                        ansi=ansi,
                    ),
                ),
            ),
            width=resolved - 4,
            ansi=ansi,
        )
    )
    body.extend(_wrapped(f"Title: {candidate.title}", resolved - 4))
    if candidate.limitation_reason:
        body.extend(_wrapped(f"Limitation: {candidate.limitation_reason}", resolved - 4))
    return render_panel(body, width=resolved, ansi=ansi)


def render_selected_evidence(
    reference: EvidenceReference,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    sensitive = bool(
        reference.provenance_fields
        and any(
            token in reference.provenance_fields
            for token in ("command_line", "message", "raw_message")
        )
    )
    body = list(
        render_metadata(
            (
                ("Evidence ID", reference.reference_id),
                ("Type", reference.evidence_type or reference.source_type),
                ("Classification", render_badge("evidence", reference.classification or "context", ansi=ansi)),
                ("Sensitive", "YES" if sensitive else "NO"),
                ("Analyst", reference.selected_by or "Unknown"),
                ("Selected", reference.selected_at or "Unknown"),
                ("Updated", reference.selection_updated_at or "None"),
                ("Related cases", ", ".join(reference.scope_case_ids) or "None"),
                ("Source identifier", reference.source_id),
            ),
            width=resolved - 4,
            ansi=ansi,
        )
    )
    body.extend(_wrapped(f"Rationale: {reference.rationale or 'None'}", resolved - 4))
    return render_panel(body, width=resolved, ansi=ansi)


def render_reasoning_workspace(
    current: WorkspaceResult,
    summary: object | None,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    if summary is None:
        state = render_warning("Reasoning state is unavailable.", width=resolved, ansi=ansi)
    else:
        state = render_panel(
            render_metadata(
                (
                    ("Revision", current.revision),
                    ("Hypotheses", summary.total_hypotheses),
                    ("Open", summary.open),
                    ("Supported", summary.supported),
                    ("Rejected", summary.rejected),
                    ("Inconclusive", summary.inconclusive),
                    ("Decisions", summary.decision_count),
                ),
                width=resolved - 4,
                ansi=ansi,
            ),
            title="REASONING STATE",
            width=resolved,
            ansi=ansi,
        )
    return "\n\n".join(
        (
            _breadcrumb(current, "REASONING", width=resolved, ansi=ansi),
            render_warning(
                "Hypothesis states reflect analyst assessment, not machine certainty.",
                width=resolved,
                ansi=ansi,
            ),
            render_message_block("warning",
                "Terminal scrollback may retain analyst reasoning and evidence values.",
                width=resolved,
                ansi=ansi,
            ),
            state,
            render_grouped_menu(
                REASONING_MENU_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_hypothesis(
    current: WorkspaceResult,
    hypothesis: Hypothesis,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    related = tuple(
        item
        for item in current.investigation.decisions
        if hypothesis.hypothesis_id in item.hypothesis_ids
    )
    body = list(
        render_metadata(
            (
                ("Hypothesis ID", hypothesis.hypothesis_id),
                ("Analyst assessment", render_badge("hypothesis", hypothesis.state, ansi=ansi)),
                ("Analyst", hypothesis.author or "Unknown"),
                ("Created", hypothesis.created_at or "Unknown"),
                ("Updated", hypothesis.updated_at or "Unknown"),
                ("Supporting evidence", len(hypothesis.supporting_evidence_reference_ids)),
                ("Contradicting evidence", len(hypothesis.contradicting_evidence_reference_ids)),
                ("Assessment decisions", len(related)),
                ("Latest assessment", related[-1].decision_id if related else "None"),
            ),
            width=resolved - 4,
            ansi=ansi,
        )
    )
    body.extend(_wrapped(f"Statement: {hypothesis.statement}", resolved - 4))
    body.extend(
        _wrapped(
            "Supporting evidence IDs: "
            + (", ".join(hypothesis.supporting_evidence_reference_ids) or "None"),
            resolved - 4,
        )
    )
    body.extend(
        _wrapped(
            "Contradicting evidence IDs: "
            + (", ".join(hypothesis.contradicting_evidence_reference_ids) or "None"),
            resolved - 4,
        )
    )
    evidence_by_id = {
        item.reference_id: item for item in current.investigation.evidence_references
    }
    relationship_ids = (
        hypothesis.supporting_evidence_reference_ids
        + hypothesis.contradicting_evidence_reference_ids
    )
    for reference_id in relationship_ids:
        reference = evidence_by_id.get(reference_id)
        if reference is None:
            body.extend(_wrapped(f"{reference_id} | unavailable", resolved - 4))
            continue
        body.extend(
            _wrapped(
                f"{reference.reference_id} | "
                f"{reference.evidence_type or reference.source_type} | "
                f"{reference.classification}",
                resolved - 4,
            )
        )
        body.extend(_wrapped(f"Rationale: {reference.rationale or 'None'}", resolved - 4))
        body.extend(_wrapped(f"Source identifier: {reference.source_id}", resolved - 4))
    return render_panel(
        body,
        title="ANALYST HYPOTHESIS",
        width=resolved,
        ansi=ansi,
    )


def render_decision(
    decision: Decision,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    body = list(
        render_metadata(
            (
                ("Decision ID", decision.decision_id),
                ("Type", decision.decision_type),
                ("Outcome", decision.outcome),
                ("Analyst", decision.decided_by or "Unknown"),
                ("Timestamp", decision.decided_at or "Unknown"),
                ("Hypothesis IDs", ", ".join(decision.hypothesis_ids) or "None"),
                ("Evidence IDs", ", ".join(decision.evidence_reference_ids) or "None"),
            ),
            width=resolved - 4,
            ansi=ansi,
        )
    )
    body.extend(_wrapped(f"Rationale: {decision.rationale or 'None'}", resolved - 4))
    return render_panel(body, title="ANALYST DECISION", width=resolved, ansi=ansi)


def render_findings_workspace(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    findings = current.investigation.findings
    rows = (
        ("Revision", current.revision),
        ("Total", len(findings)),
        ("Active", sum(item.lifecycle_state == "active" for item in findings)),
        ("Historical", sum(item.lifecycle_state == "superseded" for item in findings)),
        ("Draft", sum(item.status == "draft" for item in findings)),
        ("Substantiated", sum(item.status == "substantiated" for item in findings)),
        ("Unsubstantiated", sum(item.status == "unsubstantiated" for item in findings)),
        ("Inconclusive", sum(item.status == "inconclusive" for item in findings)),
    )
    return "\n\n".join(
        (
            _breadcrumb(current, "FINDINGS", width=resolved, ansi=ansi),
            render_message_block("warning",
                "Findings are analyst-authored conclusions. Confidence is analyst assessment, not machine certainty.",
                width=resolved,
                ansi=ansi,
            ),
            render_panel(
                render_metadata(rows, width=resolved - 4, ansi=ansi),
                title="FINDINGS STATE",
                width=resolved,
                ansi=ansi,
            ),
            render_grouped_menu(
                FINDINGS_MENU_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_finding_list(
    findings: Iterable[InvestigationFinding],
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    values = tuple(findings)
    active = tuple(item for item in values if item.lifecycle_state == "active")
    historical = tuple(item for item in values if item.lifecycle_state == "superseded")
    parts = []
    for heading, items, accent in (
        ("ACTIVE FINDINGS", active, Colors.GREEN),
        ("HISTORICAL / SUPERSEDED FINDINGS", historical, Colors.GRAY),
    ):
        parts.append(heading)
        if not items:
            parts.append(render_empty_state(f"No {heading.lower()}.", width=resolved, ansi=ansi))
        for item in items:
            body = list(
                render_metadata(
                    (
                        ("Finding ID", item.finding_id),
                        ("Status", render_badge("finding_status", item.status, ansi=ansi)),
                        ("Lifecycle", render_badge("finding_lifecycle", item.lifecycle_state, ansi=ansi)),
                        ("Confidence", render_badge("confidence", item.confidence, ansi=ansi)),
                        ("Analyst", item.author),
                        ("Updated", item.updated_at),
                    ),
                    width=resolved - 4,
                    ansi=ansi,
                )
            )
            body.extend(_wrapped(f"Title: {item.title}", resolved - 4))
            parts.append(render_panel(body, width=resolved, ansi=ansi, accent=accent))
        parts.append("")
    return "\n".join(parts).rstrip()


def render_finding_detail(
    finding: InvestigationFinding,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = [
        ("Finding ID", finding.finding_id),
        ("Status", render_badge("finding_status", finding.status, ansi=ansi)),
        ("Lifecycle", render_badge("finding_lifecycle", finding.lifecycle_state, ansi=ansi)),
        ("Confidence", render_badge("confidence", finding.confidence, ansi=ansi)),
        ("Analyst", finding.author),
        ("Created", finding.created_at),
        ("Updated", finding.updated_at),
        ("Evidence IDs", ", ".join(finding.evidence_ids) or "None"),
        ("Hypothesis IDs", ", ".join(finding.hypothesis_ids) or "None"),
        ("Decision IDs", ", ".join(finding.decision_ids) or "None"),
        ("ATT&CK tactics", ", ".join(finding.attack_tactics) or "None"),
        ("ATT&CK techniques", ", ".join(finding.attack_techniques) or "None"),
        ("Supersedes", finding.supersedes_finding_id or "None"),
    ]
    if finding.lifecycle_state == "superseded":
        rows.extend(
            (
                ("Superseded by", finding.superseded_by_finding_id or "None"),
                ("Supersession reason", finding.supersession_reason or "None"),
                ("Supersession analyst", finding.supersession_author or "None"),
                ("Superseded at", finding.superseded_at or "None"),
            )
        )
    body = list(render_metadata(rows, width=resolved - 4, ansi=ansi))
    body.extend(_wrapped(f"Title: {finding.title}", resolved - 4))
    body.extend(_wrapped(f"Conclusion: {finding.conclusion}", resolved - 4))
    for limitation in finding.limitations:
        body.extend(_wrapped(f"Limitation: {limitation}", resolved - 4))
    if not finding.limitations:
        body.append("Limitations: None")
    return "\n".join(
        (
            render_warning(
                "Confidence reflects analyst assessment and does not represent machine certainty.",
                width=resolved,
                ansi=ansi,
            ),
            render_panel(
                body,
                title="ANALYST-AUTHORED FINDING",
                width=resolved,
                ansi=ansi,
                accent=Colors.GRAY if finding.lifecycle_state == "superseded" else Colors.GREEN,
            ),
        )
    )
