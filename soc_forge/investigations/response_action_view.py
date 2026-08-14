from __future__ import annotations

from soc_forge.investigations.models import ResponseAction
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.terminal import (
    render_badge,
    render_breadcrumb,
    render_grouped_menu,
    render_message_block,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


RESPONSE_ACTION_GROUPS = (
    (
        "RESPONSE ACTIONS",
        (
            ("1", "List Response Actions"),
            ("2", "Create Response Action"),
            ("3", "Open Response Action"),
        ),
    ),
)


def render_response_actions_workspace(
    current: WorkspaceResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    actions = current.investigation.response_actions
    counts = {
        status: sum(item.status == status for item in actions)
        for status in ("proposed", "approved", "in_progress", "completed", "dismissed")
    }
    state = render_panel(
        render_metadata(
            (
                ("Total", len(actions)),
                ("Proposed", counts["proposed"]),
                ("Approved", counts["approved"]),
                ("In Progress", counts["in_progress"]),
                ("Completed", counts["completed"]),
                ("Dismissed", counts["dismissed"]),
            ),
            width=resolved - 4,
            ansi=ansi,
        ),
        title="RESPONSE STATE",
        width=resolved,
        ansi=ansi,
    )
    return "\n\n".join(
        (
            render_breadcrumb(
                (
                    "SOC-FORGE",
                    "INVESTIGATIONS",
                    current.investigation.investigation_id,
                    "RESPONSE",
                ),
                width=resolved,
                ansi=ansi,
            ),
            state,
            render_message_block(
                "info",
                "SOC-Forge records analyst response workflow. "
                "SOC-Forge does not execute remediation.",
                width=resolved,
                ansi=ansi,
            ),
            render_grouped_menu(
                RESPONSE_ACTION_GROUPS,
                back_option=("0", "Back"),
                width=resolved,
                ansi=ansi,
            ),
        )
    )


def render_response_action_list(
    actions: tuple[ResponseAction, ...],
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    if not actions:
        return render_message_block(
            "info", "No response actions recorded.", width=resolved, ansi=ansi
        )
    sections = []
    for heading, statuses in (
        ("OPEN ACTIONS", {"proposed", "approved", "in_progress"}),
        ("TERMINAL ACTIONS", {"completed", "dismissed"}),
    ):
        matching = tuple(item for item in actions if item.status in statuses)
        if not matching:
            continue
        cards = []
        for action in matching:
            cards.append(
                render_panel(
                    render_metadata(
                        (
                            ("Action ID", action.action_id),
                            ("Title", action.title),
                            ("Type", action.action_type),
                            ("Priority", render_badge("priority", action.priority, ansi=ansi)),
                            ("Status", render_badge("status", action.status, ansi=ansi)),
                            ("Owner", action.owner),
                            ("Updated", action.updated_at),
                            ("Findings", len(action.finding_ids)),
                        ),
                        width=resolved - 4,
                        ansi=ansi,
                    ),
                    width=resolved,
                    ansi=ansi,
                )
            )
        sections.append(heading + "\n" + "\n".join(cards))
    return "\n\n".join(sections)


def render_response_action_detail(
    action: ResponseAction,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    details = render_panel(
        render_metadata(
            (
                ("Action ID", action.action_id),
                ("Investigation ID", action.investigation_id),
                ("Title", action.title),
                ("Description", action.description),
                ("Type", action.action_type),
                ("Priority", render_badge("priority", action.priority, ansi=ansi)),
                ("Status", render_badge("status", action.status, ansi=ansi)),
                ("Rationale", action.rationale),
                ("Owner", action.owner),
                ("Created by", action.created_by),
                ("Created", action.created_at),
                ("Updated", action.updated_at),
                ("Finding IDs", ", ".join(action.finding_ids)),
            ),
            width=resolved - 4,
            ansi=ansi,
            wrap_values=True,
        ),
        title="RESPONSE ACTION",
        width=resolved,
        ansi=ansi,
    )
    if action.transition_history:
        history_rows = []
        for item in action.transition_history:
            history_rows.extend(
                (
                    ("Transition ID", item.transition_id),
                    ("Status", f"{item.from_status} -> {item.to_status}"),
                    ("Author", item.author),
                    ("Timestamp", item.timestamp),
                    ("Rationale", item.rationale),
                )
            )
        history = render_panel(
            render_metadata(
                tuple(history_rows),
                width=resolved - 4,
                ansi=ansi,
                wrap_values=True,
            ),
            title="TRANSITION HISTORY",
            width=resolved,
            ansi=ansi,
        )
    else:
        history = render_panel(
            "No lifecycle transitions recorded.",
            title="TRANSITION HISTORY",
            width=resolved,
            ansi=ansi,
        )
    notice = render_message_block(
        "warning",
        "RESPONSE ACTIONS RECORD ANALYST-CONTROLLED WORK. "
        "SOC-FORGE DOES NOT EXECUTE THIS ACTION.",
        width=resolved,
        ansi=ansi,
    )
    return "\n\n".join((details, history, notice))