from pathlib import Path

import pytest

from soc_forge.menus.architecture import render_architecture_notice
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


def _callbacks(calls):
    return {
        name: (lambda selected=name: calls.append(selected))
        for name in ("analyze", "simulate", "view", "rules", "search")
    }


@pytest.mark.parametrize(
    ("inputs", "expected"),
    [
        (("3", "1", "0", "0"), "analyze"),
        (("3", "2", "0", "0"), "simulate"),
        (("3", "3", "0", "0"), "rules"),
        (("7", "1", "0", "0"), "view"),
        (("7", "2", "0", "0"), "search"),
    ],
)
def test_detection_legacy_capabilities_remain_reachable(monkeypatch, inputs, expected):
    from soc_forge.menus import detection

    calls = []
    handlers = _callbacks(calls)
    choices = iter(inputs)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda _title: None)
    monkeypatch.setattr(detection, "menu_option", lambda *_args: None)

    detection.detection_menu(
        lambda: calls.append("pause"),
        handlers["analyze"],
        handlers["simulate"],
        handlers["view"],
        handlers["rules"],
        handlers["search"],
    )

    assert calls == [expected]


def test_detection_menu_has_target_architecture_and_no_stale_labels(monkeypatch):
    from soc_forge.menus import detection

    entries = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": "0")
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda title: entries.append(("group", title)))
    monkeypatch.setattr(
        detection, "menu_option", lambda number, label: entries.append((number, label))
    )
    detection.detection_menu(*(lambda: None for _ in range(6)))

    assert ("group", "DETECTION ENGINEERING") in entries
    assert ("group", "DETECTION RESULTS") in entries
    assert ("3", "Detection Lab") in entries
    assert ("7", "Alert Explorer") in entries
    assert all("Coming Soon" not in label for _, label in entries)


def test_analysis_menu_is_honest_and_legacy_reconstruction_remains_in_investigations(
    monkeypatch,
):
    from soc_forge.menus import analysis

    entries, calls = [], []
    monkeypatch.setattr("builtins.input", lambda _prompt="": "0")
    monkeypatch.setattr(analysis, "begin_screen", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_group", lambda title: entries.append(("group", title)))
    monkeypatch.setattr(
        analysis, "menu_option", lambda number, label: entries.append((number, label))
    )
    analysis.analysis_menu(
        lambda: calls.append("pause"),
    )

    labels = {label for _, label in entries}
    assert "Threat Activity Overview" in labels
    assert "Temporal Analysis" in labels
    assert "Timeline Viewer Coming Soon" not in labels
    assert "SOC Statistics Coming Soon" not in labels
    assert calls == []
    workspace_view = (
        Path(__file__).parents[1] / "soc_forge/investigations/workspace_view.py"
    ).read_text()
    assert '"Investigation Replay (Read Only)"' in workspace_view
    assert '"Entity Relationship Explorer (Read Only)"' in workspace_view


def test_reporting_preserves_handlers_without_duplicate_handoff(monkeypatch):
    from soc_forge.menus import reporting

    calls, entries = [], []
    choices = iter(("1", "2", "3", "4", "0"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(reporting, "begin_screen", lambda _title: None)
    monkeypatch.setattr(reporting, "menu_group", lambda _title: None)
    monkeypatch.setattr(
        reporting, "menu_option", lambda number, label: entries.append((number, label))
    )
    controller = type("Controller", (), {
        "report_center_run": lambda self: calls.append("report_center"),
        "investigation_report_run": lambda self: calls.append("investigation_report"),
        "executive_run": lambda self: calls.append("executive_summary"),
        "export_run": lambda self: calls.append("export_center"),
    })()
    reporting.reporting_menu(
        lambda: calls.append("pause"),
        controller,
    )

    assert calls == [
        "report_center", "investigation_report", "executive_summary", "export_center"
    ]
    assert entries == [
        ("1", "Report Center"),
        ("2", "Investigation Report"),
        ("3", "Executive Summary"),
        ("4", "Export Center"),
        ("0", "Back"),
    ] * 5
    assert all("ATT&CK Coverage" not in label for _, label in entries)


def test_system_removes_demo_from_primary_navigation_and_preserves_about(monkeypatch):
    from soc_forge.menus import system

    calls, entries = [], []
    choices = iter(("6", "0"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(system, "begin_screen", lambda _title: None)
    monkeypatch.setattr(system, "menu_group", lambda _title: None)
    monkeypatch.setattr(
        system, "menu_option", lambda number, label: entries.append((number, label))
    )
    monkeypatch.setattr(system, "show_about", lambda: calls.append("about"))
    system.system_menu(
        lambda: calls.append("pause"),
    )

    assert calls == ["about", "pause"]
    assert ("1", "Platform Status") in entries
    assert ("6", "About SOC-Forge") in entries
    assert all("Demo" not in label and "Coming Soon" not in label for _, label in entries)


def test_informational_screen_is_bounded_read_only_and_color_independent(
    monkeypatch, tmp_path
):
    artifact = tmp_path / "state.json"
    artifact.write_bytes(b"unchanged")
    for width in (100, 80, 60, 10):
        rendered = render_architecture_notice(
            "ANALYSIS",
            "Entity Explorer",
            "Cross-investigation entity analysis is not implemented in this slice.",
            planned_scope=("host", "user", "IP", "process"),
            width=width,
            ansi=False,
        )
        assert "ENTITY EXPLORER" in rendered
        assert "No independent" in rendered
        assert all(
            len(line) <= resolve_terminal_width(width)
            for line in rendered.splitlines()
        )
    monkeypatch.setenv("NO_COLOR", "1")
    no_color = render_architecture_notice(
        "SYSTEM", "Environment", "Environment inspection is deferred."
    )
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    dumb = render_architecture_notice(
        "SYSTEM", "Environment", "Environment inspection is deferred."
    )
    ascii_output = render_architecture_notice(
        "SYSTEM",
        "Environment",
        "Environment inspection is deferred.",
        ansi=False,
        unicode=False,
    )
    assert strip_ansi(no_color) == no_color
    assert strip_ansi(dumb) == dumb
    assert "+" in ascii_output and "|" in ascii_output
    assert artifact.read_bytes() == b"unchanged"


def test_no_production_submenu_contains_coming_soon():
    root = Path(__file__).parents[1] / "soc_forge/menus"
    for name in ("detection.py", "analysis.py", "reporting.py", "system.py"):
        assert "Coming Soon" not in (root / name).read_text()
