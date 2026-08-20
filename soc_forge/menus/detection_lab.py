from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.detection_lab import DetectionLabResult, DetectionLabService
from soc_forge.menus.rule_explainability import render_rule_explanation
from soc_forge.rule_explainability import RuleExplanationService
from soc_forge.ui.terminal import (
    render_application_header,
    render_breadcrumb,
    render_empty_state,
    render_error,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def render_detection_lab_menu(
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    return "\n".join(
        (
            render_application_header(
                width=resolved, ansi=ansi, unicode=unicode
            ),
            render_breadcrumb(
                ("SOC-FORGE", "DETECTION", "DETECTION LAB"),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                (
                    "[1] Analyze Telemetry File",
                    "[2] Run Attack Simulation",
                    "[3] Evaluate Rules Only",
                    "[4] View Last Lab Result",
                    "[0] Back",
                ),
                title="DETECTION LAB",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
        )
    )


def render_simulation_menu(
    scenarios: Iterable[str],
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = tuple(
        f"[{index}] {_label(scenario)}"
        for index, scenario in enumerate(scenarios, start=1)
    )
    return "\n".join(
        (
            render_application_header(
                width=resolved, ansi=ansi, unicode=unicode
            ),
            render_breadcrumb(
                (
                    "SOC-FORGE",
                    "DETECTION",
                    "DETECTION LAB",
                    "ATTACK SIMULATION",
                ),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                rows,
                title="AUTHORITATIVE SCENARIOS",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
        )
    )


def render_detection_lab_result(
    result: DetectionLabResult,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    inner = resolved - 4
    rows = [
        ("Run Type", result.run_type),
        ("Source", result.source),
    ]
    if result.scenario:
        rows.append(("Scenario", _label(result.scenario)))
    rows.extend(
        (
            ("Mode", "RULES ONLY" if result.rules_only else "NORMAL"),
            ("Events", result.event_count),
            ("Rules Evaluated", result.rule_count),
            ("Triggered Rules", result.triggered_rule_count),
            ("Alerts", result.alert_count),
            ("Cases", result.case_count),
            ("Correlations", result.correlation_count),
            ("Hunts", result.hunt_count),
            ("Reconstructions", result.reconstruction_count),
        )
    )
    triggered = tuple(
        f"[{index}] Explain {rule_id} - {title}"
        for index, (rule_id, title) in enumerate(
            result.triggered_rules, start=1
        )
    )
    attack = tuple(result.attack_tactics) + tuple(result.attack_techniques)
    sections = [
        render_application_header(
            width=resolved, ansi=ansi, unicode=unicode
        ),
        render_breadcrumb(
            (
                "SOC-FORGE",
                "DETECTION",
                "DETECTION LAB",
                "RESULT",
            ),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            render_metadata(
                rows,
                width=inner,
                ansi=ansi,
                wrap_values=True,
            ),
            title="DETECTION LAB RESULT",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            triggered
            or (
                render_empty_state(
                    "No configured rules triggered.",
                    width=inner,
                    ansi=ansi,
                ),
            ),
            title="TRIGGERED RULES",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            attack
            or (
                render_empty_state(
                    "No explicit ATT&CK mappings observed.",
                    width=inner,
                    ansi=ansi,
                ),
            ),
            title="ATT&CK OBSERVED",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
    ]
    if result.artifacts:
        sections.append(
            render_panel(
                render_metadata(
                    result.artifacts,
                    width=inner,
                    ansi=ansi,
                    wrap_values=True,
                ),
                title="EXISTING PIPELINE ARTIFACTS",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            )
        )
    if result.warnings:
        sections.append(
            render_panel(
                result.warnings,
                title="WARNINGS",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            )
        )
    return "\n".join(sections)


class DetectionLabConsoleController:
    def __init__(
        self,
        service: DetectionLabService,
        explanation_service: RuleExplanationService,
        *,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[], None] = lambda: None,
        pause_func: Callable[[], None] = lambda: None,
    ):
        self.service = service
        self.explanation_service = explanation_service
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func
        self.last_result: DetectionLabResult | None = None

    def run(self) -> None:
        while True:
            self.screen()
            self.output(render_detection_lab_menu())
            choice = self.input("Select option: ").strip()
            if choice == "0":
                return
            if choice == "1":
                self._analyze_telemetry()
            elif choice == "2":
                self._run_simulation()
            elif choice == "3":
                self._evaluate_rules_only()
            elif choice == "4":
                self._view_last_result()
            else:
                self.output(render_error("Invalid Detection Lab selection."))
                self.pause()

    def _analyze_telemetry(self) -> None:
        path = self.input("Input path (blank to return): ").strip()
        if not path:
            return
        report = self.input("Generate HTML report? (y/n): ").strip().lower()
        self._execute(
            lambda: self.service.analyze_telemetry(
                path, write_report=report == "y"
            )
        )

    def _run_simulation(self) -> None:
        scenarios = self.service.scenarios
        self.screen()
        self.output(render_simulation_menu(scenarios))
        choice = self.input("Select scenario (blank to return): ").strip()
        if choice == "":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(scenarios):
            self.output(render_error("Invalid simulation selection."))
            self.pause()
            return
        self._execute(
            lambda: self.service.run_simulation(
                scenarios[int(choice) - 1]
            )
        )

    def _evaluate_rules_only(self) -> None:
        path = self.input("Input path (blank to return): ").strip()
        if not path:
            return
        self._execute(lambda: self.service.evaluate_rules_only(path))

    def _execute(
        self, operation: Callable[[], DetectionLabResult]
    ) -> None:
        try:
            result = operation()
        except Exception as exc:
            self.output(render_error(f"Detection Lab run failed: {exc}"))
            self.pause()
            return
        self.last_result = result
        self._show_result(result)

    def _view_last_result(self) -> None:
        if self.last_result is None:
            self.output(
                render_empty_state(
                    "No Detection Lab result is available in this session."
                )
            )
            self.pause()
            return
        self._show_result(self.last_result)

    def _show_result(self, result: DetectionLabResult) -> None:
        while True:
            self.screen()
            self.output(render_detection_lab_result(result))
            choice = self.input("[0] Back or rule number to explain: ").strip()
            if choice == "0":
                return
            if (
                not choice.isdigit()
                or not 1 <= int(choice) <= len(result.triggered_rules)
            ):
                self.output(render_error("Invalid result selection."))
                self.pause()
                continue
            rule_id = result.triggered_rules[int(choice) - 1][0]
            try:
                explanation = self.explanation_service.explanation_for(rule_id)
            except (OSError, ValueError) as exc:
                self.output(
                    render_error(f"Rule Explainability unavailable: {exc}")
                )
                self.pause()
                continue
            while True:
                self.screen()
                self.output(render_rule_explanation(explanation))
                back = self.input("[0] Back: ").strip()
                if back == "0":
                    break
                self.output(render_error("Invalid option."))
                self.pause()
