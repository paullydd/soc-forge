from soc_forge.ui.panels import header, footer


_active_clear_screen = None


def set_clear_screen(clear_screen_func):
    global _active_clear_screen
    _active_clear_screen = clear_screen_func


def clear():
    if _active_clear_screen:
        _active_clear_screen()


def begin_screen(title: str) -> None:
    clear()
    header(title)


def end_screen(message: str = "Press Enter to return...") -> None:
    footer()
    input(f"\n{message}")