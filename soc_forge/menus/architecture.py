from __future__ import annotations

from typing import Iterable

from soc_forge.ui.screen import begin_screen
from soc_forge.ui.terminal import (
    render_breadcrumb,
    render_message,
    render_panel,
    resolve_terminal_width,
)


def render_architecture_notice(
    area: str,
    title: str,
    summary: str,
    *,
    planned_scope: Iterable[str] = (),
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    body = [
        render_message("info", summary, width=resolved - 4, ansi=ansi),
        "No independent state is created or modified by this screen.",
    ]
    scope = tuple(planned_scope)
    if scope:
        body.extend(("", "Planned scope:"))
        body.extend(f"- {item}" for item in scope)
    return "\n".join(
        (
            render_breadcrumb(
                ("SOC-FORGE", area, title),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                body, title=title.upper(), width=resolved, ansi=ansi, unicode=unicode
            ),
        )
    )


def show_architecture_notice(area, title, summary, pause, planned_scope=()):
    begin_screen(title.upper())
    print(render_architecture_notice(area, title, summary, planned_scope=planned_scope))
    pause()
