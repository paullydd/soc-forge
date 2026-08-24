import time

from soc_forge import __version__
from soc_forge.ui.colors import Colors
from soc_forge.ui.terminal import color_enabled, render_badge
from soc_forge.system_workspace import startup_platform_status


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

    status = startup_platform_status()
    by_id = {row.component_id: row for row in status.components}
    readiness_items = (
        ("Runtime", by_id.get("runtime")),
        ("Detection Rules", by_id.get("detection_rules")),
        ("Investigation Workspace", by_id.get("investigation_repository")),
        ("Analysis Snapshots", by_id.get("analysis_services")),
        ("Analyst Services", by_id.get("analyst_services")),
    )

    bold = Colors.BOLD if styled else ""
    reset = Colors.RESET if styled else ""
    print(bold + "INITIALIZING PLATFORM\n" + reset)
    for title, component in readiness_items:
        state = component.state if component is not None else "unknown"
        print(render_badge("readiness", state) + f" {title}")
        time.sleep(0.08)

    print()
    green = Colors.GREEN if styled and status.overall_state == "ready" else ""
    cyan = Colors.CYAN if styled else ""
    print("Platform Status: " + green + status.overall_state.upper() + reset)
    print(cyan + "Entering Analyst Console..." + reset)

    time.sleep(1.2)

    if clear_func:
        clear_func()
