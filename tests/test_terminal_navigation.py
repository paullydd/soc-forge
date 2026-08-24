import os

from soc_forge.menus.cross_investigation import (
    CrossInvestigationConsoleController,
)
from soc_forge.ui.screen import screen_output, set_clear_screen
from test_cross_investigation import entity, service


def teardown_function():
    set_clear_screen(None)


def test_complete_rendered_screen_uses_shared_clear_once_without_splitting_sections():
    calls, output = [], []
    set_clear_screen(lambda: calls.append("clear"))
    rendered = "HEADER\nSECTION ONE\nSECTION TWO\n" + ("row\n" * 200)
    screen_output(output.append)(rendered)
    assert calls == ["clear"]
    assert output == [rendered]
    assert "SECTION ONE" in output[0] and "SECTION TWO" in output[0]
    assert output[0].count("row") == 200


def test_child_result_and_return_to_parent_each_clear_once():
    calls, output = [], []
    set_clear_screen(lambda: calls.append("clear"))
    projection = service((
        entity("host", "host-1", "INV-1", "E1"),
        entity("host", "host-1", "INV-2", "E2"),
    ))
    inputs = iter(("1", "", "0"))
    CrossInvestigationConsoleController(
        projection, input_func=lambda _prompt="": next(inputs),
        output_func=output.append,
    ).run()
    assert calls == ["clear", "clear", "clear"]
    assert "CROSS-INVESTIGATION ANALYSIS" in output[0]
    assert "CROSS-INVESTIGATION STATE" in output[1]
    assert "CROSS-INVESTIGATION ANALYSIS" in output[2]


def test_clear_screen_is_suppressed_for_capture_and_term_dumb(monkeypatch):
    import analyst_console

    calls = []
    monkeypatch.setattr(os, "system", calls.append)
    monkeypatch.setattr(analyst_console.sys.stdout, "isatty", lambda: False)
    analyst_console.clear_screen()
    assert calls == []

    monkeypatch.setattr(analyst_console.sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("TERM", "dumb")
    analyst_console.clear_screen()
    assert calls == []
