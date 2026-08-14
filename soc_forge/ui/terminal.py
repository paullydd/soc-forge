from __future__ import annotations

import os
import re
import shutil
from textwrap import wrap
from typing import Iterable, Tuple

from soc_forge.ui.colors import Colors


ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DEFAULT_TERMINAL_WIDTH = 80
MIN_TERMINAL_WIDTH = 24
MAX_TERMINAL_WIDTH = 100
MAX_CONTENT_LENGTH = 500

_BADGES = {
    "system": {"online": Colors.GREEN},
    "summary_mode": {"full": Colors.GREEN, "offline": Colors.YELLOW},
    "investigation": {"open": Colors.CYAN, "in_progress": Colors.YELLOW, "closed": Colors.GRAY},
    "evidence": {"supporting": Colors.GREEN, "contradicting": Colors.RED, "context": Colors.CYAN},
    "hypothesis": {"open": Colors.CYAN, "supported": Colors.GREEN, "rejected": Colors.RED, "inconclusive": Colors.YELLOW},
    "finding_status": {"draft": Colors.GRAY, "substantiated": Colors.GREEN, "unsubstantiated": Colors.RED, "inconclusive": Colors.YELLOW},
    "finding_lifecycle": {"active": Colors.GREEN, "superseded": Colors.GRAY},
    "status": {
        "proposed": Colors.YELLOW,
        "approved": Colors.CYAN,
        "in_progress": Colors.CYAN,
        "completed": Colors.GREEN,
        "dismissed": Colors.GRAY,
    },
    "priority": {
        "low": Colors.GREEN,
        "medium": Colors.YELLOW,
        "high": Colors.RED,
        "critical": Colors.RED + Colors.BOLD,
    },
    "confidence": {"low": Colors.GREEN, "medium": Colors.YELLOW, "high": Colors.RED},
    "severity": {"informational": Colors.CYAN, "low": Colors.GREEN, "medium": Colors.YELLOW, "high": Colors.RED, "critical": Colors.RED + Colors.BOLD},
    "availability": {
        "online": Colors.GREEN,
        "available": Colors.GREEN,
        "full": Colors.GREEN,
        "offline": Colors.YELLOW,
        "missing": Colors.RED,
        "optional": Colors.GRAY,
    },
    "activity_origin": {"machine": Colors.GRAY, "analyst": Colors.CYAN},
    "validation": {"valid": Colors.GREEN, "invalid": Colors.RED},
    "readiness": {"ready": Colors.GREEN},
}
_MESSAGES = {
    "success": ("OK", Colors.GREEN), "info": ("INFO", Colors.CYAN),
    "warning": ("WARNING", Colors.YELLOW), "error": ("ERROR", Colors.RED),
    "empty": ("EMPTY", Colors.GRAY),
}


def strip_ansi(value: object) -> str:
    return ANSI_PATTERN.sub("", str(value))


def visible_length(value: object) -> int:
    return len(strip_ansi(value))


def ansi_safe_truncate(value: object, width: int, suffix: str = "...") -> str:
    text = str(value)
    if width <= 0:
        return ""
    if visible_length(text) <= width:
        return text
    suffix = suffix[:width]
    target = width - len(suffix)
    if target <= 0:
        return suffix
    output, visible, position, styled = [], 0, 0, False
    for match in ANSI_PATTERN.finditer(text):
        plain = text[position:match.start()]
        remaining = target - visible
        if remaining <= len(plain):
            output.append(plain[:remaining])
            break
        output.extend((plain, match.group(0)))
        visible += len(plain)
        position = match.end()
        styled = True
    else:
        output.append(text[position:position + max(0, target - visible)])
    result = "".join(output) + suffix
    return result + Colors.RESET if styled and not result.endswith(Colors.RESET) else result


def resolve_terminal_width(width: int | None = None) -> int:
    if width is None:
        try:
            width = shutil.get_terminal_size(fallback=(DEFAULT_TERMINAL_WIDTH, 24)).columns
        except OSError:
            width = DEFAULT_TERMINAL_WIDTH
    try:
        resolved = int(width)
    except (TypeError, ValueError):
        resolved = DEFAULT_TERMINAL_WIDTH
    return max(MIN_TERMINAL_WIDTH, min(MAX_TERMINAL_WIDTH, resolved))


def color_enabled(enabled: bool | None = None) -> bool:
    if enabled is not None:
        return enabled
    return "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def _bound(value: object, limit: int = MAX_CONTENT_LENGTH) -> str:
    text = " ".join(str(value).splitlines()).strip()
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _style(text: str, color: str, enabled: bool | None) -> str:
    return f"{color}{text}{Colors.RESET}" if color_enabled(enabled) else text


def render_panel(body: Iterable[object], *, title: object | None = None,
                 width: int | None = None, ansi: bool | None = None,
                 unicode: bool = True, accent: str = Colors.CYAN) -> str:
    resolved, inner = resolve_terminal_width(width), resolve_terminal_width(width) - 2
    chars = ("┌", "┐", "└", "┘", "─", "│") if unicode else ("+", "+", "+", "+", "-", "|")
    tl, tr, bl, br, horizontal, vertical = chars
    heading = _bound(title, 80) if title is not None else ""
    if heading:
        heading = ansi_safe_truncate(heading, max(1, inner - 3))
        top = f"{tl}{horizontal} {heading} {horizontal * max(0, inner - visible_length(heading) - 3)}{tr}"
    else:
        top = f"{tl}{horizontal * inner}{tr}"
    lines = [_style(top, accent, ansi)]
    for raw in tuple(body) or ("",):
        content = ansi_safe_truncate(_bound(raw), inner - 2)
        padding = " " * max(0, inner - 2 - visible_length(content))
        lines.append(_style(f"{vertical} {content}{padding} {vertical}", accent, ansi))
    lines.append(_style(f"{bl}{horizontal * inner}{br}", accent, ansi))
    return "\n".join(lines)


def render_application_header(**kwargs: object) -> str:
    return render_panel(("SOC-FORGE", "Security Operations Platform"), **kwargs)


def render_screen_title(title: object, *, width: int | None = None,
                        ansi: bool | None = None) -> str:
    return _style(ansi_safe_truncate(_bound(title, 160).upper(), resolve_terminal_width(width)), Colors.BOLD, ansi)


def render_breadcrumb(segments: Iterable[object], *, width: int | None = None,
                      ansi: bool | None = None, unicode: bool = True) -> str:
    separator = " › " if unicode else " > "
    values = [ansi_safe_truncate(_bound(item, 40), 40) for item in segments if str(item).strip()]
    text = ansi_safe_truncate(separator.join(values) or "SOC-FORGE", resolve_terminal_width(width))
    return _style(text, Colors.GRAY, ansi)


def render_divider(*, width: int | None = None, ansi: bool | None = None,
                   unicode: bool = True) -> str:
    return _style(("─" if unicode else "-") * resolve_terminal_width(width), Colors.GRAY, ansi)


def render_section_header(title: object, **kwargs: object) -> str:
    return f"{render_screen_title(title, width=kwargs.get('width'), ansi=kwargs.get('ansi'))}\n{render_divider(**kwargs)}"


def render_metadata(rows: Iterable[Tuple[object, object]], *, width: int | None = None,
                    ansi: bool | None = None,
                    wrap_values: bool = False) -> Tuple[str, ...]:
    resolved = resolve_terminal_width(width)
    values = [(_bound(key, 40), _bound(value)) for key, value in rows]
    if not values:
        return ()
    longest_key = max(visible_length(key) for key, _ in values)
    # Labels may use up to 40% of a normal-width row, bounded so values retain
    # useful scan space and narrow terminals continue using stacked rows.
    label_budget = max(18, min(28, (resolved * 2) // 5))
    key_width = min(longest_key, label_budget)
    lines = []
    for key, value in values:
        if resolved < 40:
            lines.append(ansi_safe_truncate(f"{key}: {value}", resolved))
        else:
            label = ansi_safe_truncate(key, key_width)
            padding = " " * max(0, key_width - visible_length(label))
            value_width = resolved - key_width - 2
            if wrap_values and visible_length(value) > value_width and not ANSI_PATTERN.search(value):
                chunks = wrap(
                    value,
                    width=max(1, value_width),
                    break_long_words=True,
                    break_on_hyphens=False,
                ) or [""]
                lines.append(f"{label}{padding}  {chunks[0]}")
                continuation = " " * (key_width + 2)
                lines.extend(f"{continuation}{chunk}" for chunk in chunks[1:])
            else:
                rendered_value = ansi_safe_truncate(value, value_width)
                lines.append(f"{label}{padding}  {rendered_value}")
    return tuple(lines)


def render_badge(family: str, value: object, *, ansi: bool | None = None) -> str:
    family = str(family).strip().lower()
    state = str(value).strip().lower().replace(" ", "_")
    label = ansi_safe_truncate(state.replace("_", " ").upper() or "UNKNOWN", 24)
    return _style(f"[{label}]", _BADGES.get(family, {}).get(state, Colors.GRAY), ansi)


def render_message(kind: str, message: object, *, width: int | None = None,
                   ansi: bool | None = None) -> str:
    indicator, color = _MESSAGES.get(str(kind).lower(), ("INFO", Colors.CYAN))
    text = ansi_safe_truncate(f"{indicator}: {_bound(message)}", resolve_terminal_width(width))
    return _style(text, color, ansi)


def render_message_block(
    kind: str,
    message: object,
    *,
    width: int | None = None,
    ansi: bool | None = None,
) -> str:
    resolved = resolve_terminal_width(width)
    indicator, color = _MESSAGES.get(str(kind).lower(), ("INFO", Colors.CYAN))
    prefix = f"{indicator}: "
    content_width = max(1, resolved - visible_length(prefix))
    fragments = wrap(
        _bound(message),
        width=content_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    continuation = " " * visible_length(prefix)
    return "\n".join(
        _style((prefix if index == 0 else continuation) + fragment, color, ansi)
        for index, fragment in enumerate(fragments)
    )


def render_success(message: object, **kwargs: object) -> str:
    return render_message("success", message, **kwargs)


def render_info(message: object, **kwargs: object) -> str:
    return render_message("info", message, **kwargs)


def render_warning(message: object, **kwargs: object) -> str:
    return render_message("warning", message, **kwargs)


def render_error(message: object, **kwargs: object) -> str:
    return render_message("error", message, **kwargs)


def render_empty_state(message: object, **kwargs: object) -> str:
    return render_message("empty", message, **kwargs)


def render_grouped_menu(groups: Iterable[Tuple[object, Iterable[Tuple[object, object]]]],
                        *, back_option: Tuple[object, object] | None = ("0", "Back"),
                        width: int | None = None, ansi: bool | None = None) -> str:
    resolved, lines = resolve_terminal_width(width), []
    for heading, options in groups:
        if lines:
            lines.append("")
        lines.append(_style(ansi_safe_truncate(_bound(heading, 80).upper(), resolved), Colors.CYAN, ansi))
        for number, label in options:
            prefix = f"  [{_bound(number, 8)}] "
            lines.append(_style(prefix, Colors.BOLD, ansi) + ansi_safe_truncate(_bound(label, 120), resolved - visible_length(prefix)))
    if back_option is not None:
        if lines:
            lines.append("")
        number, label = back_option
        prefix = f"  [{_bound(number, 8)}] "
        lines.append(_style(prefix, Colors.BOLD, ansi) + ansi_safe_truncate(_bound(label, 120), resolved - visible_length(prefix)))
    return "\n".join(lines)
