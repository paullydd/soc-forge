import time
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
    print(f"{Colors.CYAN}{label:<28}{Colors.RESET} {Colors.GREEN}{bar}{Colors.RESET} {percent}%")


def startup_screen(clear_func=None, version: str = "v1.8.0-dev") -> None:
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
    typewriter(f"       {version} | Investigation Workspace Edition\n\n", 0.01, Colors.GRAY)

    boot_items = [
        "Detection Engine",
        "Correlation Engine",
        "Attack Reconstruction",
        "Case Management",
        "Investigation Workspace",
        "IOC Explorer",
        "MITRE ATT&CK Mapping",
        "Reporting Engine",
    ]

    print(Colors.BOLD + "Initializing Platform...\n" + Colors.RESET)

    for item in boot_items:
        print(Colors.GREEN + "[✓] " + Colors.RESET + f"{item:<30} Loaded")
        time.sleep(0.08)

    print()
    progress_bar("Loading Command Center", 100)

    print()
    print(Colors.GREEN + "[+] SOC-FORGE READY" + Colors.RESET)

    time.sleep(1.2)

    if clear_func:
        clear_func()