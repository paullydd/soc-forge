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
