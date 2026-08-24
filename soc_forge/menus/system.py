from __future__ import annotations

from soc_forge import __version__
from soc_forge.ui.panels import error, menu_group, menu_option
from soc_forge.ui.screen import begin_screen, screen_output
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb, render_message_block,
    render_metadata, render_panel, resolve_terminal_width,
)


def _screen(panels, section, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=width, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "SYSTEM", section), width=width, ansi=ansi, unicode=unicode),
        *panels,
    ))


def render_platform_status(status, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    rows = []
    for row in status.components:
        rows.extend(render_metadata(((row.title, render_badge("readiness", row.state, ansi=ansi)),), width=width - 4, ansi=ansi))
        rows.extend(render_message_block("info", row.detail, width=width - 4, ansi=ansi).splitlines())
        if row.optional_path:
            rows.extend(render_metadata((("Path", row.optional_path),), width=width - 4, ansi=ansi, wrap_values=True))
    overall = render_panel((f"Overall  {render_badge('readiness', status.overall_state, ansi=ansi)}",), title="OVERALL", width=width, ansi=ansi, unicode=unicode)
    return _screen((render_panel(rows, title="PLATFORM STATUS", width=width, ansi=ansi, unicode=unicode), overall), "PLATFORM STATUS", width=width, ansi=ansi, unicode=unicode)


def render_configuration(config, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    header = render_metadata((("Source", config.source), ("Loaded", "Yes" if config.loaded else "No"), ("Status", config.detail)), width=width - 4, ansi=ansi, wrap_values=True)
    values = render_metadata(config.values or (("Effective Values", "Unavailable"),), width=width - 4, ansi=ansi, wrap_values=True)
    return _screen((render_panel(header, title="CONFIGURATION SOURCE", width=width, ansi=ansi, unicode=unicode), render_panel(values, title="EFFECTIVE VALUES (READ-ONLY)", width=width, ansi=ansi, unicode=unicode)), "CONFIGURATION", width=width, ansi=ansi, unicode=unicode)


def render_rule_asset_health(health, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    summary = render_metadata((("Rule Path", health.rules_path), ("Rules Discovered", health.rules_discovered), ("Rules Loaded", health.rules_loaded), ("Rule Parse Failures", len(health.parse_failures)), ("Web Static Assets", render_badge("readiness", health.web_assets_state, ansi=ansi)), ("Report Assets", render_badge("readiness", health.report_assets_state, ansi=ansi))), width=width - 4, ansi=ansi, wrap_values=True)
    failures = health.parse_failures or ("No rule parse failures.",)
    boundary = ("Asset health verifies loadability and packaged resources.", "Detection Coverage remains owned by Detection.")
    return _screen((render_panel(summary, title="RULE / ASSET HEALTH", width=width, ansi=ansi, unicode=unicode), render_panel(failures, title="VALIDATION", width=width, ansi=ansi, unicode=unicode), render_panel(boundary, title="BOUNDARY", width=width, ansi=ansi, unicode=unicode)), "RULE / ASSET HEALTH", width=width, ansi=ansi, unicode=unicode)


def render_storage(storage, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    rows = render_metadata((("Repository Path", storage.repository_path), ("Repository Exists", storage.repository_exists), ("Repository Readable", storage.repository_readable), ("Repository Writable", storage.repository_writable), ("Investigations", storage.investigation_count if storage.investigation_count is not None else "Unknown"), ("Output Path", storage.output_path), ("Output Exists", storage.output_exists), ("Output Readable", storage.output_readable), ("Output Writable", storage.output_writable), ("Snapshot Path", storage.snapshot_path), ("Snapshot Location Exists", storage.snapshot_exists), ("Known Analysis Reports", storage.analysis_report_count), ("Status", storage.detail)), width=width - 4, ansi=ansi, wrap_values=True)
    return _screen((render_panel(rows, title="REPOSITORY & STORAGE", width=width, ansi=ansi, unicode=unicode),), "REPOSITORY & STORAGE", width=width, ansi=ansi, unicode=unicode)


def render_environment(environment, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    rows = render_metadata((("SOC-Forge Version", environment.soc_forge_version), ("Python", environment.python_version), ("Platform", environment.platform_name), ("Architecture", environment.architecture), ("Executable", environment.executable), ("Working Directory", environment.working_directory), ("Virtual Environment", environment.virtual_environment), ("Terminal", environment.terminal), ("Color", environment.color)), width=width - 4, ansi=ansi, wrap_values=True)
    return _screen((render_panel(rows, title="ENVIRONMENT", width=width, ansi=ansi, unicode=unicode),), "ENVIRONMENT", width=width, ansi=ansi, unicode=unicode)


def render_about(*, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    capabilities = (
        "Detection, correlation, alerts, and Detection Engineering",
        "Investigations with evidence, hypotheses, decisions, and Findings",
        "Analyst-controlled Response Actions and Operations Queue prioritization",
        "Security Analysis, Reporting, and Investigation Handoff",
        "Terminal analyst console and local web interface",
    )
    boundary = ("SOC-Forge records analyst-controlled response work.", "It does not execute remediation.", "It is a local portfolio and analyst workflow platform, not a production monitoring service.")
    return _screen((render_panel((f"SOC-Forge {__version__}", *capabilities), title="ABOUT SOC-FORGE", width=width, ansi=ansi, unicode=unicode), render_panel(boundary, title="SAFETY BOUNDARY", width=width, ansi=ansi, unicode=unicode)), "ABOUT SOC-FORGE", width=width, ansi=ansi, unicode=unicode)


class SystemConsoleController:
    def __init__(self, service, *, input_func=input, output_func=print):
        self.service = service
        self.input = input_func
        self.output = screen_output(output_func)

    def _show(self, rendered):
        self.output(rendered)
        self.input("\nPress Enter to go back...")

    def platform_status_run(self): self._show(render_platform_status(self.service.platform_status()))
    def configuration_run(self): self._show(render_configuration(self.service.configuration()))
    def rule_asset_health_run(self): self._show(render_rule_asset_health(self.service.rule_asset_health()))
    def storage_run(self): self._show(render_storage(self.service.storage()))
    def environment_run(self): self._show(render_environment(self.service.environment()))
    def about_run(self): self._show(render_about())


def show_about():
    print(render_about())


def system_menu(clear_screen, pause, create_demo_case=None, controller=None):
    while True:
        begin_screen("SYSTEM")
        print(render_breadcrumb(("SOC-FORGE", "SYSTEM")))
        menu_group("PLATFORM")
        menu_option("1", "Platform Status")
        menu_option("2", "Configuration")
        menu_option("3", "Rule / Asset Health")
        menu_option("4", "Repository & Storage")
        menu_option("5", "Environment")
        menu_group("INFORMATION")
        menu_option("6", "About SOC-Forge")
        menu_option("0", "Back")
        choice = input("\nSelect option: ").strip()
        if choice == "0":
            return
        if controller is None:
            if choice == "6":
                show_about(); pause()
            else:
                error("System workspace is unavailable."); pause()
        elif choice == "1": controller.platform_status_run()
        elif choice == "2": controller.configuration_run()
        elif choice == "3": controller.rule_asset_health_run()
        elif choice == "4": controller.storage_run()
        elif choice == "5": controller.environment_run()
        elif choice == "6": controller.about_run()
        else:
            error("Invalid option."); pause()
