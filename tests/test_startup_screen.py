from soc_forge.ui import loading
from soc_forge.ui.terminal import strip_ansi


def test_existing_branded_startup_uses_authoritative_version_and_readiness_order(
    monkeypatch, capsys
):
    clears = []
    monkeypatch.setattr(loading, "__version__", "3.2.0-test")
    monkeypatch.setattr(loading.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(
        "builtins.input",
        lambda *_args: (_ for _ in ()).throw(AssertionError("startup read input")),
    )

    loading.startup_screen(lambda: clears.append("clear"))

    output = strip_ansi(capsys.readouterr().out)
    assert "███████╗ ██████╗  ██████╗" in output
    assert "SOC-FORGE Security Operations Platform" in output
    assert "v3.2.0-test | Investigation Workspace Edition" in output
    expected = (
        "INITIALIZING PLATFORM",
        "[READY] Runtime",
        "[READY] Detection Rules",
        "[READY] Investigation Workspace",
        "[READY] Analysis Snapshots",
        "[READY] Analyst Services",
        "Platform Status: READY",
        "Entering Analyst Console...",
    )
    positions = [output.index(value) for value in expected]
    assert positions == sorted(positions)
    assert clears == ["clear", "clear"]
    assert "v1.8.0-dev" not in output
    assert "Loading Command Center" not in output


def test_startup_preserves_explicit_version_override_without_double_prefix(
    monkeypatch, capsys
):
    monkeypatch.setattr(loading.time, "sleep", lambda _delay: None)

    loading.startup_screen(version="v9.9.9")

    output = strip_ansi(capsys.readouterr().out)
    assert "v9.9.9 | Investigation Workspace Edition" in output
    assert "vv9.9.9" not in output

def test_startup_respects_no_color_without_changing_readiness_content(
    monkeypatch, capsys
):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(loading.time, "sleep", lambda _delay: None)

    loading.startup_screen(version="3.2.0")

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "SOC-FORGE Security Operations Platform" in output
    assert "[READY] Runtime" in output
    assert "Platform Status: READY" in output

def test_progress_bar_respects_term_dumb(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")

    loading.progress_bar("Runtime", percent=50, width=4)

    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "Runtime" in output
    assert "50%" in output


def test_startup_uses_shared_authoritative_status_states(monkeypatch, capsys):
    from soc_forge.system_workspace import PlatformComponentStatus, PlatformStatus

    rows = (
        PlatformComponentStatus("runtime", "Runtime", "ready", "ok"),
        PlatformComponentStatus("detection_rules", "Detection Rules", "ready", "ok"),
        PlatformComponentStatus("investigation_repository", "Repository", "degraded", "read-only"),
        PlatformComponentStatus("analysis_services", "Analysis", "unknown", "unknown"),
        PlatformComponentStatus("analyst_services", "Analyst", "ready", "ok"),
    )
    monkeypatch.setattr(loading, "startup_platform_status", lambda: PlatformStatus("unknown", rows))
    monkeypatch.setattr(loading.time, "sleep", lambda _delay: None)

    loading.startup_screen(version="3.5.0")

    output = strip_ansi(capsys.readouterr().out)
    assert "[DEGRADED] Investigation Workspace" in output
    assert "[UNKNOWN] Analysis Snapshots" in output
    assert "Platform Status: UNKNOWN" in output