from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import sys
from typing import Callable

import yaml

from soc_forge import __version__
from soc_forge.config import SocForgeConfig, load_config
from soc_forge.investigations.repository import (
    InvestigationRepository, InvestigationRepositoryError,
)
from soc_forge.investigations.snapshots import SNAPSHOT_DIRECTORY
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import load_rules

STATUS_STATES = frozenset({"ready", "degraded", "unavailable", "unknown"})
SENSITIVE_KEY_PARTS = ("password", "secret", "token", "credential", "api_key", "private_key")
REQUIRED_WEB_ASSETS = ("index.html", "styles.css", "app.js")


@dataclass(frozen=True)
class PlatformComponentStatus:
    component_id: str
    title: str
    state: str
    detail: str
    optional_path: str | None = None
    required: bool = True

    def __post_init__(self):
        if self.state not in STATUS_STATES:
            raise ValueError(f"Unsupported platform state: {self.state}")


@dataclass(frozen=True)
class PlatformStatus:
    overall_state: str
    components: tuple[PlatformComponentStatus, ...]

    def __post_init__(self):
        if self.overall_state not in STATUS_STATES:
            raise ValueError(f"Unsupported overall platform state: {self.overall_state}")


@dataclass(frozen=True)
class ConfigurationStatus:
    source: str
    loaded: bool
    detail: str
    values: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RuleAssetHealth:
    rules_path: str
    rules_discovered: int
    rules_loaded: int
    parse_failures: tuple[str, ...]
    web_assets_state: str
    report_assets_state: str


@dataclass(frozen=True)
class StorageStatus:
    repository_path: str
    repository_exists: bool
    repository_readable: bool
    repository_writable: bool
    investigation_count: int | None
    output_path: str
    output_exists: bool
    output_readable: bool
    output_writable: bool
    snapshot_path: str
    snapshot_exists: bool
    analysis_report_count: int
    detail: str


@dataclass(frozen=True)
class EnvironmentStatus:
    soc_forge_version: str
    python_version: str
    platform_name: str
    architecture: str
    executable: str
    working_directory: str
    virtual_environment: str
    terminal: str
    color: str


def derive_overall_status(components):
    rows = tuple(components)
    if not rows:
        return "unknown"
    required = tuple(row for row in rows if row.required)
    if any(row.state == "unavailable" for row in required):
        return "unavailable"
    if any(row.state == "unknown" for row in required):
        return "unknown"
    if any(row.state == "degraded" for row in required):
        return "degraded"
    if any(row.state in {"degraded", "unavailable"} for row in rows if not row.required):
        return "degraded"
    if all(row.state == "unknown" for row in rows):
        return "unknown"
    return "ready"


def _capability(path: Path):
    try:
        exists = path.exists()
        target = path if exists else path.parent
        while not target.exists() and target != target.parent:
            target = target.parent
        readable = target.exists() and os.access(target, os.R_OK)
        writable = target.exists() and os.access(target, os.W_OK)
        return exists, readable, writable
    except OSError:
        return False, False, False


def _safe_value(key, value):
    lowered = key.lower()
    if any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "[MASKED]"
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if isinstance(value, (tuple, list)):
        return f"{len(value)} configured values"
    return str(value)


class SystemWorkspaceService:
    def __init__(
        self,
        repository: InvestigationRepository,
        *,
        config_path: Path | str = Path("config.yml"),
        output_path: Path | str = Path("out"),
        rules_path: Path | str = BUILTIN_RULES_PATH,
        web_assets_path: Path | str | None = None,
        report_asset_path: Path | str | None = None,
        config_loader: Callable[[str | None], SocForgeConfig] = load_config,
        rule_loader: Callable = load_rules,
        version: str = __version__,
    ):
        package_root = Path(__file__).resolve().parent
        self.repository = repository
        self.config_path = Path(config_path)
        self.output_path = Path(output_path)
        self.rules_path = Path(rules_path)
        self.web_assets_path = Path(web_assets_path or package_root / "web" / "static")
        self.report_asset_path = Path(report_asset_path or package_root / "report" / "html_report.py")
        self.snapshot_path = self.output_path / SNAPSHOT_DIRECTORY
        self.config_loader = config_loader
        self.rule_loader = rule_loader
        self.version = version

    def platform_status(self):
        components = (
            self._runtime_status(),
            self._rules_status(),
            self._repository_status(),
            self._analysis_status(),
            PlatformComponentStatus("analyst_services", "Analyst Services", "ready", "Console services are importable."),
            self._reporting_status(),
            self._web_status(),
        )
        return PlatformStatus(derive_overall_status(components), components)

    def _runtime_status(self):
        state = "ready" if sys.version_info >= (3, 10) else "unavailable"
        return PlatformComponentStatus("runtime", "Runtime", state, f"Python {platform.python_version()}", sys.executable)

    def _rules_status(self):
        try:
            rules = self.rule_loader([str(self.rules_path)])
            state, detail = "ready", f"{len(rules)} rules loaded."
        except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
            state, detail = "unavailable", f"Rule loading failed: {str(exc).splitlines()[0][:160]}"
        return PlatformComponentStatus("detection_rules", "Detection Rules", state, detail, str(self.rules_path))

    def _repository_status(self):
        root = self.repository.storage_root
        _exists, readable, writable = _capability(root)
        if readable and writable:
            state, detail = "ready", "Repository location is accessible."
        elif readable:
            state, detail = "degraded", "Repository is readable but not writable."
        else:
            state, detail = "unavailable", "Repository location is unavailable."
        return PlatformComponentStatus("investigation_repository", "Investigation Repository", state, detail, str(root))

    def _analysis_status(self):
        _exists, readable, writable = _capability(self.snapshot_path)
        state = "ready" if readable and writable else "degraded" if readable else "unavailable"
        detail = "Snapshot storage capability is available." if state == "ready" else "Snapshot storage capability is partial or unavailable."
        return PlatformComponentStatus("analysis_services", "Analysis Services", state, detail, str(self.snapshot_path))

    def _reporting_status(self):
        ready = self.report_asset_path.is_file()
        return PlatformComponentStatus("reporting_assets", "Reporting Assets", "ready" if ready else "unavailable", "HTML report renderer is present." if ready else "HTML report renderer is missing.", str(self.report_asset_path), False)

    def _web_status(self):
        try:
            missing = [name for name in REQUIRED_WEB_ASSETS if not (self.web_assets_path / name).is_file()]
            state = "ready" if not missing else "unavailable"
            detail = "Required packaged web assets are present." if not missing else "Missing web assets: " + ", ".join(missing)
        except OSError:
            state, detail = "unknown", "Web asset state could not be determined."
        return PlatformComponentStatus("web_assets", "Web Assets", state, detail, str(self.web_assets_path), False)

    def configuration(self):
        loaded = self.config_path.is_file()
        try:
            cfg = self.config_loader(str(self.config_path))
            values = (
                ("output.alerts_json", _safe_value("output.alerts_json", cfg.output.alerts_json)),
                ("output.report_html", _safe_value("output.report_html", cfg.output.report_html)),
                ("detections.brute_force.threshold", _safe_value("threshold", cfg.bruteforce.threshold)),
                ("detections.brute_force.window_minutes", _safe_value("window_minutes", cfg.bruteforce.window_minutes)),
                ("detections.brute_force.severity", _safe_value("severity", cfg.bruteforce.severity)),
                ("correlation.window_minutes", _safe_value("window_minutes", cfg.correlation.window_minutes)),
                ("correlation.bruteforce_lockout", _safe_value("enabled", cfg.correlation.bruteforce_lockout_enabled)),
                ("correlation.rdp_schtask", _safe_value("enabled", cfg.correlation.rdp_schtask_enabled)),
                ("correlation.rdp_new_admin", _safe_value("enabled", cfg.correlation.rdp_new_admin_enabled)),
            )
            detail = "Configuration loaded." if loaded else "Configuration file missing; effective defaults are shown."
        except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
            values, detail = (), f"Configuration unavailable: {str(exc).splitlines()[0][:160]}"
            loaded = False
        return ConfigurationStatus(str(self.config_path), loaded, detail, values)

    def rule_asset_health(self):
        files = tuple(sorted((*self.rules_path.glob("*.yml"), *self.rules_path.glob("*.yaml")))) if self.rules_path.is_dir() else ((self.rules_path,) if self.rules_path.is_file() else ())
        loaded = 0
        failures = []
        for path in files:
            try:
                loaded += len(self.rule_loader([str(path)]))
            except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
                failures.append(f"{path.name}: {str(exc).splitlines()[0][:120]}")
        if not failures:
            try:
                self.rule_loader([str(self.rules_path)])
            except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
                failures.append(f"Rule set: {str(exc).splitlines()[0][:120]}")
        web = self._web_status().state
        report = self._reporting_status().state
        return RuleAssetHealth(str(self.rules_path), len(files), loaded, tuple(failures[:10]), web, report)

    def storage(self):
        repo = self.repository.storage_root
        repo_exists, repo_readable, repo_writable = _capability(repo)
        output_exists, output_readable, output_writable = _capability(self.output_path)
        try:
            count = len(self.repository.list_investigations())
            detail = "Repository records inspected successfully."
        except (OSError, ValueError, InvestigationRepositoryError) as exc:
            count = None
            detail = f"Repository inspection unavailable: {str(exc).splitlines()[0][:160]}"
        try:
            report_count = sum(1 for name in ("brute_force_report.html", "password_spray_report.html", "privilege_escalation_report.html", "report.html") if (self.output_path / name).is_file())
        except OSError:
            report_count = 0
        return StorageStatus(str(repo), repo_exists, repo_readable, repo_writable, count, str(self.output_path), output_exists, output_readable, output_writable, str(self.snapshot_path), self.snapshot_path.is_dir(), report_count, detail)

    def environment(self, *, stdin=None):
        stdin = sys.stdin if stdin is None else stdin
        base_prefix = getattr(sys, "base_prefix", sys.prefix)
        virtual = "Active" if sys.prefix != base_prefix or hasattr(sys, "real_prefix") else "Not detected"
        interactive = bool(getattr(stdin, "isatty", lambda: False)())
        from soc_forge.ui.terminal import color_enabled
        return EnvironmentStatus(self.version, platform.python_version(), platform.system() or "Unknown", platform.machine() or "Unknown", sys.executable, str(Path.cwd()), virtual, "interactive" if interactive else "non-interactive", "enabled" if color_enabled() else "disabled")


def default_system_workspace(*, output_path=Path("out")):
    from soc_forge.investigations.paths import resolve_workspace_root
    output = Path(output_path)
    return SystemWorkspaceService(InvestigationRepository(resolve_workspace_root(output)), output_path=output)


def startup_platform_status():
    return default_system_workspace().platform_status()
