from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from soc_forge.investigations.operational_summary import OperationalSummary
from soc_forge.investigations.operations_prioritization import (
    PrioritizedOperationsItem,
)
from soc_forge.investigations.operations_queue import OperationsQueueSummary
from soc_forge.ui.terminal import (
    ansi_safe_truncate,
    render_application_header,
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_grouped_menu,
    render_metadata,
    render_panel,
    render_section_header,
    resolve_terminal_width,
)


COMMAND_CENTER_GROUPS = (
    (
        "OPERATIONS",
        (
            ("1", "Detection"),
            ("2", "Investigations"),
            ("3", "Analysis"),
            ("6", "Operations Queue"),
        ),
    ),
    (
        "OUTPUT & ADMINISTRATION",
        (
            ("4", "Reporting"),
            ("5", "System"),
        ),
    ),
)


EMPTY_QUEUE_SUMMARY = OperationsQueueSummary(*(0 for _ in range(10)))


def render_platform_overview(
    stats: Mapping[str, Any],
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = (
        ("System", render_badge("system", "online", ansi=ansi)),
        ("Alerts", stats["alerts"]),
        ("Cases", stats["cases"]),
        ("Open Inv.", stats["open"]),
        ("In Progress", stats["in_progress"]),
        ("Escalated", stats["escalated"]),
        ("High Severity", stats["high"]),
        ("Medium Severity", stats["medium"]),
        ("Low Severity", stats["low"]),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi),
        title="PLATFORM OVERVIEW",
        width=resolved,
        ansi=ansi,
    )


def render_recent_activity(
    recent: Iterable[Mapping[str, Any]],
    *,
    width: int | None = None,
    ansi: bool | None = None,
    limit: int = 3,
) -> str:
    resolved = resolve_terminal_width(width)
    lines = []
    for item in tuple(recent)[:limit]:
        timestamp = str(item.get("timestamp") or "Unknown time")
        severity = str(item.get("severity") or "unknown")
        title = str(item.get("title") or "Unknown Alert")
        badge = render_badge("severity", severity, ansi=ansi)
        prefix = f"{timestamp}  {badge}  "
        available = max(1, resolved - 4)
        lines.append(ansi_safe_truncate(prefix + title, available))
    if not lines:
        lines.append(
            render_empty_state(
                "No recent SOC activity.",
                width=max(1, resolved - 4),
                ansi=ansi,
            )
        )
    return (
        render_section_header("RECENT SOC ACTIVITY", width=resolved, ansi=ansi)
        + "\n"
        + "\n".join(lines)
    )


def render_operations_queue_summary(
    summary: OperationsQueueSummary,
    *,
    top_attention: PrioritizedOperationsItem | None = None,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    top_label = "None"
    if top_attention is not None:
        source = top_attention.queue_item
        top_label = (
            f"[{top_attention.priority_tier.upper()}] {source.source_id} — "
            f"{top_attention.priority_basis[-1]}"
        )
    rows = (
        ("Top Attention", top_label),
        ("Attention Items", summary.total_items),
        ("Critical / High", f"{summary.critical} / {summary.high}"),
        ("Medium / Low", f"{summary.medium} / {summary.low}"),
        ("Response Actions", summary.response_actions),
        ("Uncovered Findings", summary.uncovered_findings),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi, wrap_values=True),
        title="ANALYST QUEUE",
        width=resolved,
        ansi=ansi,
    )


def render_operations_overview(
    summary: OperationalSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    top_label = "None"
    if summary.top_item is not None:
        top_label = (
            f"[{summary.top_priority.upper()}] {summary.top_source_id}"
        )
    rows = (
        ("Top Attention", top_label),
        ("Attention Items", summary.total_attention_items),
        ("Investigations Represented", summary.investigations_represented),
        ("Critical", summary.critical_count),
        ("High", summary.high_count),
        ("Medium", summary.medium_count),
        ("Low", summary.low_count),
        ("Response Actions", summary.response_action_count),
        ("Uncovered Findings", summary.uncovered_finding_count),
        ("In Progress", summary.in_progress_count),
        ("Approved", summary.approved_count),
        ("Proposed", summary.proposed_count),
        *(
            (("Top Reason", summary.top_reason), ("Priority Basis", "; ".join(summary.top_item.priority_basis)))
            if summary.top_item is not None else ()
        ),
    )
    return render_panel(
        render_metadata(rows, width=resolved - 4, ansi=ansi, wrap_values=True),
        title="OPERATIONS OVERVIEW", width=resolved, ansi=ansi,
    )


def render_command_center(
    stats: Mapping[str, Any],
    recent: Iterable[Mapping[str, Any]],
    *,
    operational_summary: OperationalSummary | None = None,
    queue_summary: OperationsQueueSummary = EMPTY_QUEUE_SUMMARY,
    top_attention: PrioritizedOperationsItem | None = None,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    sections = (
        render_application_header(width=resolved, ansi=ansi),
        render_breadcrumb(
            ("SOC-FORGE", "COMMAND CENTER"),
            width=resolved,
            ansi=ansi,
        ),
        render_platform_overview(stats, width=resolved, ansi=ansi),
        render_recent_activity(recent, width=resolved, ansi=ansi),
        (
            render_operations_overview(
                operational_summary, width=resolved, ansi=ansi
            )
            if operational_summary is not None
            else render_operations_queue_summary(
                queue_summary, top_attention=top_attention,
                width=resolved, ansi=ansi,
            )
        ),
        render_grouped_menu(
            COMMAND_CENTER_GROUPS,
            back_option=("0", "Exit"),
            width=resolved,
            ansi=ansi,
        ),
    )
    return "\n\n".join(sections)


def show_dashboard(
    get_dashboard_stats: Callable[[], Mapping[str, Any]],
    get_recent_activity: Callable[[], Iterable[Mapping[str, Any]]],
    get_queue_summary: Callable[[], OperationsQueueSummary] | None = None,
    get_top_attention: Callable[[], PrioritizedOperationsItem | None] | None = None,
    get_operational_summary: Callable[[], OperationalSummary] | None = None,
) -> None:
    queue_summary = (
        EMPTY_QUEUE_SUMMARY if get_queue_summary is None else get_queue_summary()
    )
    print(
        render_command_center(
            get_dashboard_stats(),
            get_recent_activity(),
            queue_summary=queue_summary,
            operational_summary=(
                None if get_operational_summary is None else get_operational_summary()
            ),
            top_attention=None if get_top_attention is None else get_top_attention(),
        )
    )
