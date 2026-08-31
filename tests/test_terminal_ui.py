import pytest

from soc_forge.ui.colors import Colors
from soc_forge.ui.terminal import (
    ansi_safe_truncate,
    render_application_header,
    render_badge,
    render_breadcrumb,
    render_divider,
    render_empty_state,
    render_error,
    render_grouped_menu,
    render_info,
    render_message_block,
    render_metadata,
    render_panel,
    render_screen_title,
    render_section_header,
    render_success,
    render_warning,
    resolve_terminal_width,
    strip_ansi,
    visible_length,
)


def assert_bounded(rendered, width):
    assert all(visible_length(line) <= width for line in rendered.splitlines())


def test_application_header_and_screen_components_are_deterministic():
    first = render_application_header(width=60, ansi=False)
    assert first == render_application_header(width=60, ansi=False)
    assert "SOC-FORGE" in first
    assert "Security Operations Platform" in first
    assert render_screen_title("Investigation Summary", width=60, ansi=False) == "INVESTIGATION SUMMARY"
    assert render_section_header("Evidence", width=24, ansi=False).splitlines()[1] == "─" * 24
    assert render_divider(width=24, ansi=False, unicode=False) == "-" * 24


def test_breadcrumb_bounds_segments_and_narrow_terminals():
    normal = render_breadcrumb(("SOC-FORGE", "INVESTIGATIONS", "INV-TEST-001", "FINDINGS"), width=80, ansi=False)
    assert normal == "SOC-FORGE › INVESTIGATIONS › INV-TEST-001 › FINDINGS"
    long = render_breadcrumb(("SOC-FORGE", "X" * 100, "FINDINGS"), width=60, ansi=False)
    narrow = render_breadcrumb(("SOC-FORGE", "INVESTIGATIONS", "INV-TEST-001"), width=10, ansi=False)
    assert "..." in long
    assert_bounded(long, 60)
    assert_bounded(narrow, 24)


def test_panel_handles_long_content_narrow_width_and_ascii_fallback():
    panel = render_panel(("ID INV-001", "X" * 200), title="INVESTIGATION", width=60, ansi=False)
    narrow = render_panel(("X" * 200,), title="LONG TITLE" * 20, width=10, ansi=False)
    portable = render_panel(("Content",), title="PANEL", width=40, ansi=False, unicode=False)
    assert "INVESTIGATION" in panel
    assert "..." in panel
    assert_bounded(panel, 60)
    assert_bounded(narrow, 24)
    assert portable.startswith("+- PANEL")
    assert portable.endswith("+")


def test_metadata_alignment_long_values_and_narrow_fallback():
    rows = (("Investigation", "INV-TEST-001"), ("Status", "OPEN"))
    normal = render_metadata(rows, width=60, ansi=False)
    assert normal[0].index("INV-TEST-001") == normal[1].index("OPEN")
    assert render_metadata((), width=60, ansi=False) == ()
    assert visible_length(render_metadata((("Owner", "X" * 200),), width=60, ansi=False)[0]) <= 60
    assert all(visible_length(line) <= 24 for line in render_metadata(rows, width=24, ansi=False))


def test_metadata_uses_available_width_without_unnecessary_label_truncation():
    rows = (
        ("Supporting evidence", "12"),
        ("Contradicting evidence", "3"),
        ("Superseded by analyst", "Analyst"),
    )
    wide = render_metadata(rows, width=76, ansi=False)
    narrow = render_metadata(rows, width=24, ansi=False)

    assert "Supporting evidence" in wide[0] and "..." not in wide[0]
    assert "Contradicting evidence" in wide[1] and "..." not in wide[1]
    assert "Superseded by analyst" in wide[2] and "..." not in wide[2]
    value_columns = [line.index(value) for line, value in zip(wide, ("12", "3", "Analyst"))]
    assert len(set(value_columns)) == 1
    assert all(visible_length(line) <= 24 for line in narrow)


def test_metadata_wraps_exact_long_paths_when_requested():
    path = (
        "/home/analyst/investigations/INV-TEST-001/"
        "handoffs/INV-TEST-001/manifest.json"
    )
    rendered = render_metadata(
        (("Manifest path", path),),
        width=60,
        ansi=False,
        wrap_values=True,
    )

    assert "Manifest path" in rendered[0]
    assert "".join(line.strip() for line in rendered).endswith("manifest.json")
    assert "..." not in "\n".join(rendered)
    assert all(visible_length(line) <= 60 for line in rendered)


def test_wrapped_message_uses_consistent_prefix_and_preserves_content():
    message = "Sensitive telemetry and analyst-authored rationale must be reviewed before sharing."
    rendered = render_message_block("warning", message, width=32, ansi=False)

    lines = rendered.splitlines()
    assert lines[0].startswith("WARNING: ")
    assert all(line.startswith(" " * len("WARNING: ")) for line in lines[1:])
    content = [lines[0].removeprefix("WARNING: ")]
    content.extend(line.strip() for line in lines[1:])
    assert " ".join(content) == message
    assert_bounded(rendered, 32)


def test_grouped_menu_spacing_has_one_blank_line_between_sections():
    rendered = render_grouped_menu(
        (
            ("Review", (("1", "Summary"),)),
            ("Output", (("2", "Export"),)),
        ),
        width=60,
        ansi=False,
    )
    assert "  [1] Summary\n\nOUTPUT\n  [2] Export" in rendered
    assert "  [2] Export\n\n  [0] Back" in rendered
    assert "\n\n\n" not in rendered


@pytest.mark.parametrize(
    ("family", "states"),
    [
        ("investigation", ("open", "in_progress", "closed")),
        ("evidence", ("supporting", "contradicting", "context")),
        ("hypothesis", ("open", "supported", "rejected", "inconclusive")),
        ("finding_status", ("draft", "substantiated", "unsubstantiated", "inconclusive")),
        ("finding_lifecycle", ("active", "superseded")),
        ("confidence", ("low", "medium", "high")),
        ("severity", ("informational", "low", "medium", "high", "critical")),
        ("availability", ("online", "available", "full", "offline", "missing", "optional")),
        ("activity_origin", ("machine", "analyst")),
        ("validation", ("valid", "invalid")),
        ("readiness", ("ready",)),
    ],
)
def test_supported_badge_families_retain_text_without_ansi(family, states):
    for state in states:
        assert render_badge(family, state, ansi=False) == f"[{state.replace('_', ' ').upper()}]"


def test_unknown_badge_is_safe_and_bounded():
    badge = render_badge("unknown-family", "unexpected-state" * 10, ansi=False)
    assert badge.startswith("[") and badge.endswith("]")
    assert visible_length(badge) <= 26


def test_ansi_strip_visible_length_and_safe_truncation():
    colored = Colors.GREEN + "ACTIVE FINDING" + Colors.RESET
    assert strip_ansi(colored) == "ACTIVE FINDING"
    assert visible_length(colored) == len("ACTIVE FINDING")
    truncated = ansi_safe_truncate(colored, 9)
    assert strip_ansi(truncated) == "ACTIVE..."
    assert truncated.endswith(Colors.RESET)
    assert visible_length(truncated) == 9


def test_messages_include_semantic_indicators_without_color():
    assert render_success("Saved", ansi=False).startswith("OK:")
    assert render_info("Ready", ansi=False).startswith("INFO:")
    assert render_warning("Unavailable", ansi=False).startswith("WARNING:")
    assert render_error("Failed", ansi=False).startswith("ERROR:")
    assert render_empty_state("No findings", ansi=False).startswith("EMPTY:")
    assert_bounded(render_warning("X" * 500, width=24, ansi=False), 24)


def test_grouped_menu_is_passive_bounded_and_preserves_numbers():
    groups = (("Investigation", (("1", "Summary"), ("2", "Timeline & Pivot"))), ("Output", (("14", "Handoff"), ("15", "X" * 200))))
    rendered = render_grouped_menu(groups, width=60, ansi=False)
    narrow = render_grouped_menu(groups, width=24, ansi=False)
    assert "[1] Summary" in rendered
    assert "[14] Handoff" in rendered
    assert "[0] Back" in rendered
    assert "..." in rendered
    assert_bounded(narrow, 24)


def test_width_policy_clamps_detected_and_explicit_values(monkeypatch):
    monkeypatch.setattr("shutil.get_terminal_size", lambda fallback: type("Size", (), {"columns": 140})())
    assert resolve_terminal_width() == 100
    assert resolve_terminal_width(80) == 80
    assert resolve_terminal_width(2) == 24


def test_no_color_environment_disables_ansi(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in render_badge("severity", "critical")
    assert "\x1b" not in render_application_header(width=60)


def test_renderers_do_not_read_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_args: pytest.fail("renderer read input"))
    render_application_header(width=60, ansi=False)
    render_grouped_menu((("Group", (("1", "Action"),)),), width=60, ansi=False)


def test_command_center_header_does_not_change_exit_input_count(monkeypatch, capsys):
    import analyst_console

    calls = []
    stub_controller = type("StubController", (), {"workspace_service": None})()
    monkeypatch.setattr(
        analyst_console, "build_investigation_console_controller", lambda: stub_controller
    )
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(
        analyst_console,
        "get_dashboard_stats",
        lambda _workspace_service=None: {
            "alerts": 0, "cases": 0, "high": 0, "medium": 0, "low": 0,
            "open": 0, "in_progress": 0, "escalated": 0, "closed": 0,
        },
    )
    monkeypatch.setattr(analyst_console, "get_recent_activity", lambda: ())

    def select_exit(_prompt):
        calls.append("input")
        return "0"

    monkeypatch.setattr("builtins.input", select_exit)
    with pytest.raises(SystemExit) as raised:
        analyst_console.main_menu()

    output = strip_ansi(capsys.readouterr().out)
    assert raised.value.code == 0
    assert calls == ["input"]
    assert "SOC-FORGE" in output
    assert "Security Operations Platform" in output
