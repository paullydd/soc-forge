import time

from soc_forge import __version__
from soc_forge.ui.colors import Colors


def typewriter(text: str, delay: float = 0.01, color: str = "") -> None:
    if color:
        print(color, end="")

    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)

    if color:
        print(Colors.RESET, end="")


def progress_bar(label: str, percent: int = 100, width: int = 28) -> None:
    filled = int(width * percent / 100)
    empty = width - filled

    bar = "█" * filled + "░" * empty
    print(
        f"{Colors.CYAN}{label:<28}{Colors.RESET} "
        f"{Colors.GREEN}{bar}{Colors.RESET} {percent}%"
    )


def startup_screen(clear_func=None, version: str | None = None) -> None:
    if clear_func:
        clear_func()

    logo = r"""
 ███████╗ ██████╗  ██████╗
 ██╔════╝██╔═══██╗██╔════╝
 ███████╗██║   ██║██║
 ╚════██║██║   ██║██║
 ███████║╚██████╔╝╚██████╗
 ╚══════╝ ╚═════╝  ╚═════╝
"""

    print(Colors.CYAN, end="")
    typewriter(logo, 0.0005)
    print(Colors.RESET, end="")

    typewriter("       SOC-FORGE ", 0.03, Colors.YELLOW)
    typewriter("Security Operations Platform\n", 0.015, Colors.CYAN)

    display_version = version or __version__
    if not display_version.startswith("v"):
        display_version = f"v{display_version}"
    typewriter(
        f"       {display_version} | Investigation Workspace Edition\n\n",
        0.01,
        Colors.GRAY,
    )

    readiness_items = (
        "Runtime",
        "Detection Rules",
        "Investigation Workspace",
        "Analysis Snapshots",
        "Analyst Services",
    )

    print(Colors.BOLD + "INITIALIZING PLATFORM\n" + Colors.RESET)
    for item in readiness_items:
        print(Colors.GREEN + "[READY]" + Colors.RESET + f" {item}")
        time.sleep(0.08)

    print()
    print("Platform Status: " + Colors.GREEN + "READY" + Colors.RESET)
    print(Colors.CYAN + "Entering Analyst Console..." + Colors.RESET)

    time.sleep(1.2)

    if clear_func:
        clear_func()
