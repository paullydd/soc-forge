from typing import Any, List, Tuple
from soc_forge.ui.colors import Colors
import re 

def visible_len(text: str) -> int:
    ansi_escape = re.compile(r"\033\[[0-9;]*m")
    clean_text = ansi_escape.sub("", str(text))
    return len(clean_text)

def header(title: str, width: int = 64) -> None:
    print()
    print(Colors.RED + "┏" + "━" * (width - 2) + "┓" + Colors.RESET)
    print(Colors.RED + "┃" + Colors.BOLD + title.center(width - 2) + Colors.RESET + Colors.RED + "┃" + Colors.RESET)
    print(Colors.RED + "┗" + "━" * (width - 2) + "┛" + Colors.RESET)


def section(title: str, width: int = 64) -> None:
    print()
    print(Colors.BOLD + title + Colors.RESET)
    print(Colors.GRAY + "─" * width + Colors.RESET)


def divider(width: int = 64) -> None:
    print(Colors.GRAY + "─" * width + Colors.RESET)


def info_panel(title: str, rows: List[Tuple[str, Any]], width: int = 64) -> None:
    print()
    print(Colors.CYAN + "╔" + "═" * (width - 2) + "╗" + Colors.RESET)
    print(
        Colors.CYAN
        + "║"
        + Colors.BOLD
        + title.center(width - 2)
        + Colors.RESET
        + Colors.CYAN
        + "║"
        + Colors.RESET
    )
    print(Colors.CYAN + "╠" + "═" * (width - 2) + "╣" + Colors.RESET)

    for label, value in rows:
        label_text = str(label)
        value_text = str(value)

        line = f" {label_text:<16} {value_text}"
        padding = (width - 2) - visible_len(line)

        if padding < 0:
            line = line[: width - 5] + "..."
            padding = 0

        print(Colors.CYAN + "║" + line + (" " * padding) + "║" + Colors.RESET)

    print(Colors.CYAN + "╚" + "═" * (width - 2) + "╝" + Colors.RESET)

def progress_bar_line(label: str, percent: int, width: int = 30) -> None:
    percent = max(0, min(100, int(percent)))
    filled = int(width * percent / 100)
    empty = width - filled

    bar = "█" * filled + "░" * empty
    print(f"{label:<14} {Colors.GREEN}{bar}{Colors.RESET} {percent}%")


def menu_option(number: str, label: str) -> None:
    print(f"{Colors.BOLD}[{number}]{Colors.RESET} {label}")


def warning(message: str) -> None:
    print(Colors.YELLOW + message + Colors.RESET)


def error(message: str) -> None:
    print(Colors.RED + message + Colors.RESET)


def success(message: str) -> None:
    print(Colors.GREEN + message + Colors.RESET)

def menu_group(title: str) -> None:
    print()
    print(Colors.CYAN + title + Colors.RESET)
    print(Colors.GRAY + "─" * 50 + Colors.RESET)

def status_card(title: str, rows: List[Tuple[str, Any]], width: int = 64) -> None:
    info_panel(title, rows, width)


def metric_card(label: str, value: Any, icon: str = "", width: int = 24) -> None:
    value_text = str(value)
    title = f"{icon} {label}".strip()

    print()
    print(Colors.CYAN + "╔" + "═" * (width - 2) + "╗" + Colors.RESET)
    print(Colors.CYAN + "║" + Colors.BOLD + title.center(width - 2) + Colors.RESET + Colors.CYAN + "║" + Colors.RESET)
    print(Colors.CYAN + "╠" + "═" * (width - 2) + "╣" + Colors.RESET)
    print(Colors.CYAN + "║" + Colors.BOLD + value_text.center(width - 2) + Colors.RESET + Colors.CYAN + "║" + Colors.RESET)
    print(Colors.CYAN + "╚" + "═" * (width - 2) + "╝" + Colors.RESET)


def activity_feed(title: str, items: List[Any], width: int = 64, limit: int = 5) -> None:
    section(title, width)

    if not items:
        warning("No activity found.")
        return

    for item in items[:limit]:
        if isinstance(item, dict):
            timestamp = item.get("timestamp", "Unknown")
            name = item.get("title", item.get("description", "Activity"))
            severity = item.get("severity", "")

            if severity:
                print(f"{Colors.GRAY}{timestamp}{Colors.RESET} | {severity} | {name}")
            else:
                print(f"{Colors.GRAY}{timestamp}{Colors.RESET} | {name}")
        else:
            print(f"- {item}")


def footer(message: str = "0 Back | Ctrl+C Exit", width: int = 64) -> None:
    print()
    print(Colors.GRAY + "─" * width + Colors.RESET)
    print(Colors.GRAY + message.center(width) + Colors.RESET)