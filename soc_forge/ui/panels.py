from typing import Any, List, Tuple
from soc_forge.ui.colors import Colors


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
    print(Colors.CYAN + "║" + Colors.BOLD + title.center(width - 2) + Colors.RESET + Colors.CYAN + "║" + Colors.RESET)
    print(Colors.CYAN + "╠" + "═" * (width - 2) + "╣" + Colors.RESET)

    for label, value in rows:
        line = f" {str(label):<16} {str(value)}"
        print(Colors.CYAN + "║" + line[:width - 2].ljust(width - 2) + "║" + Colors.RESET)

    print(Colors.CYAN + "╚" + "═" * (width - 2) + "╝" + Colors.RESET)


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