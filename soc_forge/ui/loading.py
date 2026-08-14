import time

from soc_forge import __version__
from soc_forge.ui.colors import Colors
from soc_forge.ui.terminal import color_enabled, render_badge


def typewriter(text: str, delay: float = 0.01, color: str = "") -> None:
    styled = bool(color and color_enabled())
    if styled:
        print(color, end="")

    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)

    if styled:
        print(Colors.RESET, end="")


def progress_bar(label: str, percent: int = 100, width: int = 28) -> None:
    filled = int(width * percent / 100)
    empty = width - filled

    bar = "█" * filled + "░" * empty
    if color_enabled():
        print(
            f"{Colors.CYAN}{label:<28}{Colors.RESET} "
            f"{Colors.GREEN}{bar}{Colors.RESET} {percent}%"
        )
    else:
        print(f"{label:<28} {bar} {percent}%")


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

    styled = color_enabled()
    print(Colors.CYAN if styled else "", end="")
    typewriter(logo, 0.0005)
    print(Colors.RESET if styled else "", end="")

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

    bold = Colors.BOLD if styled else ""
    reset = Colors.RESET if styled else ""
    print(bold + "INITIALIZING PLATFORM\n" + reset)
    for item in readiness_items:
        print(render_badge("readiness", "ready") + f" {item}")
        time.sleep(0.08)

    print()
    green = Colors.GREEN if styled else ""
    cyan = Colors.CYAN if styled else ""
    print("Platform Status: " + green + "READY" + reset)
    print(cyan + "Entering Analyst Console..." + reset)

    time.sleep(1.2)

    if clear_func:
        clear_func()
