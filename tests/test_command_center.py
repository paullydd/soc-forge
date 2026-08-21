from copy import deepcopy
from pathlib import Path

import pytest

from soc_forge.dashboard.dashboard import (
    COMMAND_CENTER_GROUPS,
    render_command_center,
    render_recent_activity,
    show_dashboard,
)
from soc_forge.investigations.operational_summary import OperationalSummaryService
from soc_forge.investigations.operations_prioritization import (
    OperationsPrioritizationService,
)
from soc_forge.investigations.operations_queue import OperationsQueueItem
from soc_forge.ui.terminal import strip_ansi, visible_length


def dashboard_stats():
    return {
        "alerts": 19,
        "cases": 3,
        "high": 15,
        "medium": 0,
        "low": 0,
        "open": 0,
        "investigating": 2,
        "closed": 1,
    }


def recent_activity():
    return [
        {"timestamp": "2026-08-10T18:52:20Z", "severity": "high", "title": "Browser credential store access"},
        {"timestamp": "2026-08-10T18:51:20Z", "severity": "medium", "title": "Suspicious process execution"},
        {"timestamp": "2026-08-10T18:50:20Z", "severity": "low", "title": "Additional review context"},
        {"timestamp": "2026-08-10T18:49:20Z", "severity": "high", "title": "Outside current item policy"},
    ]


@pytest.mark.parametrize("width", [100, 80, 60, 10])
def test_command_center_is_width_safe_and_preserves_authoritative_counts(width):
    rendered = render_command_center(
        dashboard_stats(), recent_activity(), width=width, ansi=False
    )
    expected_width = max(24, width)
    assert all(visible_length(line) <= expected_width for line in rendered.splitlines())
    if width >= 60:
        assert "SOC-FORGE \u203a COMMAND CENTER" in rendered
    else:
        assert any(line.startswith("SOC-FORGE") and line.endswith("...") for line in rendered.splitlines())
    assert "PLATFORM OVERVIEW" in rendered
    assert "[ONLINE]" in rendered
    for label, value in (
        ("Alerts", 19), ("Cases", 3), ("Open Cases", 0),
        ("Investigating", 2), ("High Severity", 15),
        ("Medium Severity", 0), ("Low Severity", 0),
    ):
        assert label in rendered
        assert str(value) in rendered


def test_recent_activity_order_badges_limit_and_long_title_truncation():
    items = recent_activity()
    items[0]["title"] = "Sensitive-looking but bounded title " + "X" * 300
    rendered = render_recent_activity(items, width=60, ansi=False)
    assert rendered.index("2026-08-10T18:52:20Z") < rendered.index("2026-08-10T18:51:20Z")
    assert rendered.index("2026-08-10T18:51:20Z") < rendered.index("2026-08-10T18:50:20Z")
    assert "[HIGH]" in rendered
    assert "[MEDIUM]" in rendered
    assert "[LOW]" in rendered
    assert "Outside current item policy" not in rendered
    assert "..." in rendered
    assert all(visible_length(line) <= 60 for line in rendered.splitlines())


def test_recent_activity_empty_state_is_explicit_and_no_color_safe(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    rendered = render_recent_activity((), width=60)
    assert "EMPTY: No recent SOC activity." in rendered
    assert "\x1b" not in rendered


def test_grouped_navigation_keeps_exact_numbers_and_labels():
    assert COMMAND_CENTER_GROUPS == (
        (
            "OPERATIONS",
            (
                ("1", "Detection"),
                ("2", "Investigations"),
                ("3", "Analysis"),
                ("6", "Operations Queue"),
            ),
        ),
        ("OUTPUT & ADMINISTRATION", (("4", "Reporting"), ("5", "System"))),
    )
    rendered = render_command_center(dashboard_stats(), (), width=80, ansi=False)
    for number, label in (
        ("1", "Detection"), ("2", "Investigations"), ("3", "Analysis"),
        ("4", "Reporting"), ("5", "System"), ("0", "Exit"),
    ):
        assert f"[{number}] {label}" in rendered


def test_command_center_shows_shared_top_attention_and_empty_state():
    source = OperationsQueueItem(
        queue_item_id="OPQ:INV-001:response_action:ACT-001",
        investigation_id="INV-001",
        investigation_title="Credential review",
        item_type="response_action",
        priority="high",
        reason="Response Action ACT-001 is currently in progress.",
        source_id="ACT-001",
        source_type="response_action",
        source_status="in_progress",
        created_at="2026-08-20T10:00:00Z",
        updated_at="2026-08-20T11:00:00Z",
    )
    top = OperationsPrioritizationService.prioritize_item(source)
    summary = OperationalSummaryService(None).summarize((top,))
    empty_summary = OperationalSummaryService(None).summarize(())

    rendered = render_command_center(
        dashboard_stats(), (), operational_summary=summary, width=60, ansi=False
    )
    empty = render_command_center(
        dashboard_stats(), (), operational_summary=empty_summary, width=60, ansi=False
    )

    assert "Top Attention" in rendered
    assert "[HIGH] ACT-001" in rendered
    assert "Action is currently" in rendered
    assert "in progress" in rendered
    assert "Top Attention" in empty
    assert "None" in empty
    assert all(visible_length(line) <= 60 for line in rendered.splitlines())


def test_dashboard_reads_each_existing_projection_once_without_mutation(capsys):
    stats, recent = dashboard_stats(), recent_activity()
    before = (deepcopy(stats), deepcopy(recent))
    calls = []

    show_dashboard(
        lambda: calls.append("stats") or stats,
        lambda: calls.append("recent") or recent,
        None,
        None,
        None,
    )

    output = strip_ansi(capsys.readouterr().out)
    assert calls == ["stats", "recent"]
    assert (stats, recent) == before
    assert "PLATFORM OVERVIEW" in output


@pytest.mark.parametrize(
    ("module_name", "function_name", "title", "inputs", "expected_numbers"),
    [
        ("detection", "detection_menu", "DETECTION", (None,) * 7, ("1", "2", "3", "4", "5", "6", "7", "0")),
        ("investigations", "investigations_menu", "INVESTIGATIONS", (None,) * 8, ("1", "2", "3", "4", "5", "6", "0")),
        ("analysis", "analysis_menu", "ANALYSIS", (None,) * 3, ("1", "2", "3", "4", "5", "6", "0")),
        ("reporting", "reporting_menu", "REPORTING", (None,) * 4, ("1", "2", "0")),
        ("system", "system_menu", "SYSTEM", (None,) * 3, ("1", "2", "3", "4", "5", "6", "0")),
    ],
)
def test_top_level_menu_breadcrumb_and_numbers_are_presentation_only(
    monkeypatch, capsys, module_name, function_name, title, inputs, expected_numbers
):
    module = __import__(f"soc_forge.menus.{module_name}", fromlist=[function_name])
    screens, numbers = [], []
    monkeypatch.setattr("builtins.input", lambda _prompt="": "0")
    monkeypatch.setattr(module, "begin_screen", screens.append)
    monkeypatch.setattr(module, "menu_option", lambda number, _label: numbers.append(number))
    args = tuple((lambda: None) if value is None else value for value in inputs)

    getattr(module, function_name)(*args)

    assert screens == [title]
    assert tuple(numbers) == expected_numbers
    assert f"SOC-FORGE › {title}" in strip_ansi(capsys.readouterr().out)


@pytest.mark.parametrize(
    ("choice", "target"),
    [("1", "detection_menu"), ("2", "investigations_menu"),
     ("3", "analysis_menu"), ("4", "reporting_menu"), ("5", "system_menu")],
)
def test_main_menu_returns_from_each_target_without_extra_input_or_pause(
    monkeypatch, choice, target, tmp_path
):
    import analyst_console

    active = object()
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b"unchanged")
    inputs = iter((choice, "0"))
    input_calls, renders, dispatches, pauses = [], [], [], []
    monkeypatch.setattr(analyst_console, "_current_analysis_result", active)
    monkeypatch.setattr("builtins.input", lambda _prompt="": input_calls.append("input") or next(inputs))
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "show_dashboard", lambda *_args: renders.append("render"))
    monkeypatch.setattr(analyst_console, "build_investigation_console_controller", lambda: object())
    monkeypatch.setattr(
        analyst_console,
        "build_threat_activity_controller",
        lambda _workspace: object(),
    )
    monkeypatch.setattr(
        analyst_console,
        "build_entity_explorer_controller",
        lambda _workspace: object(),
    )
    monkeypatch.setattr(
        analyst_console,
        "build_attack_activity_controller",
        lambda _workspace: object(),
    )
    monkeypatch.setattr(
        analyst_console,
        "build_cross_investigation_controller",
        lambda _workspace: object(),
    )
    queue_controller = type("QueueController", (), {"run": lambda self: None})()
    queue_controller.queue_service = type(
        "QueueService", (), {"summarize": lambda self: None}
    )()
    monkeypatch.setattr(
        analyst_console,
        "build_operations_queue_controller",
        lambda _workspace: queue_controller,
    )
    monkeypatch.setattr(analyst_console, "pause", lambda: pauses.append("pause"))
    monkeypatch.setattr(analyst_console, target, lambda *_args: dispatches.append(target))

    with pytest.raises(SystemExit) as raised:
        analyst_console.main_menu()

    assert raised.value.code == 0
    assert dispatches == [target]
    assert input_calls == ["input", "input"]
    assert renders == ["render", "render"]
    assert pauses == []
    assert analyst_console.get_current_analysis_result() is active
    assert artifact.read_bytes() == b"unchanged"
