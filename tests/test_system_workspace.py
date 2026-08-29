from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from soc_forge.menus.system import (
    SystemConsoleController, render_about, render_configuration, render_environment,
    render_platform_status, render_rule_asset_health, render_storage, system_menu,
)
from soc_forge.system_workspace import (
    ConfigurationStatus, EnvironmentStatus, PlatformComponentStatus, PlatformStatus,
    RuleAssetHealth, StorageStatus, SystemWorkspaceService, derive_overall_status,
)
from soc_forge.ui.screen import set_clear_screen
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi, visible_length


class RepositoryStub:
    def __init__(self, root, rows=()):
        self.storage_root = Path(root)
        self.rows = tuple(rows)

    def list_investigations(self):
        return list(self.rows)


def build_service(tmp_path, **kwargs):
    repo_root = tmp_path / "workspace"
    repo_root.mkdir(parents=True)
    output = tmp_path / "out"
    output.mkdir()
    return SystemWorkspaceService(
        RepositoryStub(repo_root), output_path=output,
        config_path=tmp_path / "config.yml", **kwargs,
    )


def component(component_id, state, required=True):
    return PlatformComponentStatus(component_id, component_id, state, "detail", required=required)


def test_overall_status_policy_all_ready_degraded_unavailable_and_unknown():
    assert derive_overall_status((component("runtime", "ready"), component("web", "ready", False))) == "ready"
    assert derive_overall_status((component("runtime", "ready"), component("web", "unavailable", False))) == "degraded"
    assert derive_overall_status((component("runtime", "unavailable"), component("web", "ready", False))) == "unavailable"
    assert derive_overall_status((component("runtime", "unknown"),)) == "unknown"
    assert derive_overall_status(()) == "unknown"


def test_platform_status_uses_real_checks_and_is_read_only(tmp_path):
    service = build_service(tmp_path)
    before = tuple(sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")))
    first = service.platform_status()
    second = service.platform_status()
    after = tuple(sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")))
    assert first == second
    assert first.overall_state == "ready"
    assert {row.component_id for row in first.components} >= {
        "runtime", "detection_rules", "investigation_repository",
        "analysis_services", "analyst_services", "reporting_assets", "web_assets",
    }
    assert before == after


def test_platform_required_and_optional_failures_are_distinct(tmp_path):
    optional = build_service(tmp_path, web_assets_path=tmp_path / "missing-web")
    assert optional.platform_status().overall_state == "degraded"
    required = build_service(tmp_path / "required", rules_path=tmp_path / "missing-rules")
    assert required.platform_status().overall_state == "unavailable"


def test_configuration_loaded_values_missing_defaults_and_bounded_error(tmp_path):
    path = tmp_path / "config.yml"
    path.write_text("detections:\n  brute_force:\n    threshold: 12\n", encoding="utf-8")
    service = SystemWorkspaceService(RepositoryStub(tmp_path), config_path=path, output_path=tmp_path)
    loaded = service.configuration()
    assert loaded.loaded is True
    assert loaded.source == str(path)
    assert ("detections.brute_force.threshold", "12") in loaded.values
    before = path.read_bytes()
    assert service.configuration() == loaded
    assert path.read_bytes() == before

    missing = SystemWorkspaceService(RepositoryStub(tmp_path), config_path=tmp_path / "missing.yml", output_path=tmp_path)
    assert missing.configuration().loaded is False
    assert "effective defaults" in missing.configuration().detail

    broken = SystemWorkspaceService(RepositoryStub(tmp_path), config_path=path, output_path=tmp_path, config_loader=lambda _path: (_ for _ in ()).throw(ValueError("bad\nsecret detail")))
    status = broken.configuration()
    assert status.loaded is False
    assert status.values == ()
    assert "bad" in status.detail and "secret detail" not in status.detail


def test_rule_asset_health_counts_loads_malformed_and_preserves_assets(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text("rules: not-a-list\n", encoding="utf-8")
    web = tmp_path / "web"
    web.mkdir()
    for name in ("index.html", "styles.css", "app.js"):
        (web / name).write_text(name, encoding="utf-8")
    report = tmp_path / "html_report.py"
    report.write_text("# asset\n", encoding="utf-8")
    before = {p: p.read_bytes() for p in (rules / "bad.yml", report, *(web.iterdir()))}
    health = SystemWorkspaceService(RepositoryStub(tmp_path), rules_path=rules, web_assets_path=web, report_asset_path=report, output_path=tmp_path).rule_asset_health()
    assert health.rules_discovered == 1
    assert health.rules_loaded == 0
    assert len(health.parse_failures) == 1
    assert health.web_assets_state == health.report_assets_state == "ready"
    assert all(path.read_bytes() == value for path, value in before.items())
    rendered = render_rule_asset_health(health, ansi=False)
    assert "Detection Coverage remains owned by Detection" in rendered
    assert "tactic" not in rendered.lower() and "technique" not in rendered.lower()


def test_rule_asset_health_missing_optional_asset_is_unavailable(tmp_path):
    health = build_service(tmp_path, web_assets_path=tmp_path / "missing").rule_asset_health()
    assert health.web_assets_state == "unavailable"


def test_storage_inspection_paths_count_capabilities_and_no_creation(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    (output / "report.html").write_text("report", encoding="utf-8")
    service = SystemWorkspaceService(RepositoryStub(root, (object(), object())), output_path=output)
    before = tuple(sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")))
    status = service.storage()
    after = tuple(sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")))
    assert status.repository_path == str(root)
    assert status.repository_readable and status.repository_writable
    assert status.investigation_count == 2
    assert status.output_path == str(output)
    assert status.analysis_report_count == 1
    assert status.snapshot_exists is False
    assert before == after


def test_storage_missing_paths_are_inspected_without_write_probe(tmp_path):
    service = SystemWorkspaceService(RepositoryStub(tmp_path / "missing-repository"), output_path=tmp_path / "missing-output")
    status = service.storage()
    assert status.repository_exists is False
    assert status.output_exists is False
    assert list(tmp_path.iterdir()) == []


def test_environment_runtime_cross_platform_fields_and_terminal(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("soc_forge.system_workspace.platform.system", lambda: "Darwin")
    monkeypatch.setattr("soc_forge.system_workspace.platform.machine", lambda: "arm64")
    stdin = type("Input", (), {"isatty": lambda self: True})()
    status = build_service(tmp_path / "service").environment(stdin=stdin)
    assert status.platform_name == "Darwin"
    assert status.architecture == "arm64"
    assert status.python_version
    assert status.executable
    assert status.working_directory == str(tmp_path)
    assert status.terminal == "interactive"
    assert status.virtual_environment in {"Active", "Not detected"}
    assert status.color in {"enabled", "disabled"}


def test_inspection_has_no_shell_dependency(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("shell used")))
    service = build_service(tmp_path)
    service.platform_status(); service.configuration(); service.rule_asset_health(); service.storage(); service.environment()


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_all_system_renderers_are_width_safe_ascii_and_no_color(width):
    status = PlatformStatus("unknown", (component("runtime", "unknown"),))
    views = (
        render_platform_status(status, width=width, ansi=False, unicode=False),
        render_configuration(ConfigurationStatus("config.yml", False, "defaults", (("key", "value"),)), width=width, ansi=False, unicode=False),
        render_rule_asset_health(RuleAssetHealth("rules", 21, 21, (), "ready", "ready"), width=width, ansi=False, unicode=False),
        render_storage(StorageStatus("repo", True, True, True, 0, "out", True, True, True, "snapshots", False, 0, "ready"), width=width, ansi=False, unicode=False),
        render_environment(EnvironmentStatus("3.0.0", "3.14", "Windows", "AMD64", "python.exe", "work", "Active", "non-interactive", "disabled"), width=width, ansi=False, unicode=False),
        render_about(width=width, ansi=False, unicode=False),
    )
    for view in views:
        assert "\x1b" not in view
        assert all(visible_length(line) <= resolve_terminal_width(width) for line in view.splitlines())


def test_about_current_capabilities_and_no_remediation_boundary():
    rendered = strip_ansi(render_about(ansi=False))
    for value in ("Detection Engineering", "Investigations", "hypotheses", "Findings", "Response Actions", "Operations Queue", "Security Analysis", "Reporting", "Handoff", "Terminal", "web"):
        assert value in rendered
    assert "does not execute remediation" in rendered
    assert "mini detection engine" not in rendered.lower()


def test_system_menu_structure_dispatch_and_back(monkeypatch):
    from soc_forge.menus import system
    calls, entries, groups = [], [], []
    choices = iter(("1", "2", "3", "4", "5", "6", "0"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(system, "begin_screen", lambda _title: None)
    monkeypatch.setattr(system, "menu_group", groups.append)
    monkeypatch.setattr(system, "menu_option", lambda number, label: entries.append((number, label)))
    controller = type("Controller", (), {
        "platform_status_run": lambda self: calls.append("status"),
        "configuration_run": lambda self: calls.append("config"),
        "rule_asset_health_run": lambda self: calls.append("assets"),
        "storage_run": lambda self: calls.append("storage"),
        "environment_run": lambda self: calls.append("environment"),
        "about_run": lambda self: calls.append("about"),
    })()
    system_menu(lambda: calls.append("pause"), controller=controller)
    assert calls == ["status", "config", "assets", "storage", "environment", "about"]
    assert entries[:7] == [("1", "Platform Status"), ("2", "Configuration"), ("3", "Rule / Asset Health"), ("4", "Repository & Storage"), ("5", "Environment"), ("6", "About SOC-Forge"), ("0", "Back")]
    assert groups[:2] == ["PLATFORM", "INFORMATION"]
    assert all("Demo" not in label for _, label in entries)


def test_controller_uses_shared_clear_and_back_prompt(tmp_path):
    clears, outputs, inputs = [], [], []
    set_clear_screen(lambda: clears.append("clear"))
    try:
        controller = SystemConsoleController(build_service(tmp_path), input_func=lambda prompt: inputs.append(prompt) or "", output_func=outputs.append)
        controller.platform_status_run()
    finally:
        set_clear_screen(None)
    assert clears == ["clear"]
    assert len(outputs) == 1 and "PLATFORM STATUS" in outputs[0]
    assert inputs == ["\nPress Enter to go back..."]

@pytest.mark.parametrize(
    ("system_name", "machine"),
    (("Windows", "AMD64"), ("Linux", "x86_64"), ("Darwin", "arm64")),
)
def test_environment_normalizes_standard_cross_platform_values(
    monkeypatch, tmp_path, system_name, machine
):
    monkeypatch.setattr(
        "soc_forge.system_workspace.platform.system", lambda: system_name
    )
    monkeypatch.setattr(
        "soc_forge.system_workspace.platform.machine", lambda: machine
    )
    stdin = type("Input", (), {"isatty": lambda self: False})()

    status = build_service(tmp_path).environment(stdin=stdin)

    assert status.platform_name == system_name
    assert status.architecture == machine
    assert status.terminal == "non-interactive"


def test_system_rendering_respects_no_color_and_term_dumb(monkeypatch):
    status = PlatformStatus("ready", (component("runtime", "ready"),))
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in render_platform_status(status)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert "\x1b" not in render_about()