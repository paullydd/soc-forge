from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

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
        ("Open Cases", stats["open"]),
        ("Investigating", stats["investigating"]),
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


def render_command_center(
    stats: Mapping[str, Any],
    recent: Iterable[Mapping[str, Any]],
    *,
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
    box_row: object = None,
    color_status: object = None,
    color_severity: object = None,
) -> None:
    print(render_command_center(get_dashboard_stats(), get_recent_activity()))
