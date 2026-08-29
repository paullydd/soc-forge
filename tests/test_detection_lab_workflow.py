from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from soc_forge.detection_lab import DetectionLabResult, DetectionLabService
from soc_forge.menus.detection_lab import (
    DetectionLabConsoleController,
    render_detection_lab_menu,
    render_detection_lab_result,
    render_simulation_menu,
)
from soc_forge.pipeline import AnalysisOptions, run_analysis, run_analysis_for_events
from soc_forge.rule_explainability import RuleExplanationService
from soc_forge.simulator import generate_scenario, write_events_jsonl
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


def _result(**changes):
    values = {
        "run_type": "Attack Simulation",
        "source": "out/password_spray_events.jsonl",
        "scenario": "password_spray",
        "rules_only": False,
        "event_count": 8,
        "rule_count": 21,
        "triggered_rule_count": 1,
        "triggered_rules": (("SOCF-010", "Password spray suspected"),),
        "alert_count": 1,
        "case_count": 1,
        "correlation_count": 0,
        "hunt_count": 0,
        "reconstruction_count": 1,
        "attack_tactics": ("Credential Access",),
        "attack_techniques": (
            "T1110.003 - Brute Force: Password Spraying",
        ),
        "artifacts": (("alerts", "out/alerts.json"),),
        "warnings": (),
    }
    values.update(changes)
    return DetectionLabResult(**values)


def test_authoritative_scenario_menu_lists_every_existing_scenario():
    service = DetectionLabService()

    assert service.scenarios == (
        "brute_force",
        "password_spray",
        "privilege_escalation",
        "mixed",
        "attack_chain",
        "detection_lab",
    )
    rendered = render_simulation_menu(service.scenarios, ansi=False)
    for label in (
        "Brute Force",
        "Password Spray",
        "Privilege Escalation",
        "Mixed",
        "Attack Chain",
        "Detection Lab",
    ):
        assert label in rendered


@pytest.mark.parametrize(
    "scenario",
    (
        "brute_force",
        "password_spray",
        "privilege_escalation",
        "mixed",
    ),
)
def test_simulation_reuses_generator_pipeline_and_projects_actual_counts(
    tmp_path, scenario
):
    service = DetectionLabService(output_dir=tmp_path)

    result = service.run_simulation(scenario)

    assert result.run_type == "Attack Simulation"
    assert result.scenario == scenario
    assert result.event_count == len(generate_scenario(scenario))
    assert result.rule_count > 0
    assert result.triggered_rule_count == len(result.triggered_rules)
    assert result.alert_count >= result.triggered_rule_count
    assert Path(result.source) == tmp_path / f"{scenario}_events.jsonl"
    assert (tmp_path / f"{scenario}_events.jsonl").exists()
    assert (tmp_path / f"{scenario}_report.html").exists()


def test_telemetry_analysis_reuses_analysis_options_and_preserves_report_choice(
    tmp_path,
):
    events_path = write_events_jsonl(
        generate_scenario("password_spray"), tmp_path / "input.jsonl"
    )
    captured = []

    def runner(options):
        captured.append(options)
        return run_analysis(options)

    result = DetectionLabService(
        output_dir=tmp_path / "out",
        analysis_runner=runner,
    ).analyze_telemetry(events_path, write_report=False)

    assert len(captured) == 1
    assert captured[0].input_path == events_path
    assert captured[0].write_report is False
    assert result.run_type == "Telemetry Analysis"
    assert result.event_count == len(generate_scenario("password_spray"))
    assert not (tmp_path / "out" / "report.html").exists()


def test_rules_only_uses_existing_pipeline_semantics_and_actual_downstream_counts(
    tmp_path,
):
    events = generate_scenario("password_spray")
    events_path = write_events_jsonl(events, tmp_path / "input.jsonl")
    captured = []

    def runner(options):
        captured.append(options)
        return run_analysis(options)

    result = DetectionLabService(
        output_dir=tmp_path / "out",
        analysis_runner=runner,
    ).evaluate_rules_only(events_path)

    assert captured[0].rules_only is True
    assert result.run_type == "Rules Only"
    assert result.rules_only is True
    assert result.event_count == len(events)
    assert result.rule_count > 0
    assert result.alert_count >= 1
    assert result.case_count >= 0
    assert result.correlation_count >= 0
    assert result.hunt_count >= 0
    assert result.reconstruction_count >= 0


def test_projection_counts_distinct_yaml_rules_and_explicit_attack_only(tmp_path):
    analysis = run_analysis_for_events(
        AnalysisOptions(
            events=generate_scenario("detection_lab"),
            input_name="detection_lab.jsonl",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
        )
    )

    result = DetectionLabService.project(
        analysis,
        run_type="Telemetry Analysis",
        source="detection_lab.jsonl",
    )

    expected_ids = sorted(
        {
            alert["rule_id"]
            for alert in analysis.yaml_alerts
            if alert.get("rule_id")
        }
    )
    assert [item[0] for item in result.triggered_rules] == expected_ids
    assert result.triggered_rule_count == len(expected_ids)
    assert result.alert_count == len(analysis.alerts)
    assert result.correlation_count == analysis.correlations["total"]
    assert result.attack_tactics == tuple(sorted(result.attack_tactics))
    assert result.attack_techniques == tuple(sorted(result.attack_techniques))


def test_result_is_immutable_deterministic_and_view_model_is_read_only(tmp_path):
    analysis = run_analysis_for_events(
        AnalysisOptions(
            events=generate_scenario("password_spray"),
            input_name="events",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
        )
    )

    first = DetectionLabService.project(
        analysis, run_type="Rules Only", source="events", rules_only=True
    )
    second = DetectionLabService.project(
        analysis, run_type="Rules Only", source="events", rules_only=True
    )

    assert first == second
    with pytest.raises(FrozenInstanceError):
        first.alert_count = 99


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_lab_renderers_are_width_safe(width):
    outputs = (
        render_detection_lab_menu(width=width, ansi=False),
        render_simulation_menu(
            DetectionLabService().scenarios, width=width, ansi=False
        ),
        render_detection_lab_result(_result(), width=width, ansi=False),
    )

    assert all(
        len(line) <= resolve_terminal_width(width)
        for output in outputs
        for line in output.splitlines()
    )


def test_lab_rendering_supports_no_color_term_dumb_and_ascii(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    output = render_detection_lab_result(_result(), unicode=False)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    menu = render_detection_lab_menu()

    assert strip_ansi(output) == output
    assert strip_ansi(menu) == menu
    assert "+" in output and "|" in output
    assert "Rules Evaluated" in output
    assert "ATT&CK OBSERVED" in output


def test_empty_last_result_is_bounded_and_consumes_exact_menu_inputs():
    choices = iter(("4", "0"))
    inputs, outputs, pauses = [], [], []
    controller = DetectionLabConsoleController(
        DetectionLabService(),
        RuleExplanationService(),
        input_func=lambda prompt: inputs.append(prompt) or next(choices),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run()

    assert len(inputs) == 2
    assert pauses == ["pause"]
    assert any(
        "No Detection Lab result is available in this session" in output
        for output in outputs
    )


def test_last_result_is_replaced_after_each_successful_run():
    first = _result(run_type="Telemetry Analysis", scenario="")
    second = _result(run_type="Attack Simulation", scenario="mixed")

    class Service:
        scenarios = ("mixed",)

        def analyze_telemetry(self, _path, *, write_report):
            assert write_report is False
            return first

        def run_simulation(self, scenario):
            assert scenario == "mixed"
            return second

    choices = iter(
        (
            "1",
            "events.jsonl",
            "n",
            "0",
            "2",
            "1",
            "0",
            "0",
        )
    )
    controller = DetectionLabConsoleController(
        Service(),
        RuleExplanationService(),
        input_func=lambda _prompt: next(choices),
        output_func=lambda _output: None,
    )

    controller.run()

    assert controller.last_result is second


def test_viewing_last_result_does_not_execute_or_mutate_files(tmp_path):
    marker = tmp_path / "marker.txt"
    marker.write_text("unchanged", encoding="utf-8")
    calls = []

    class Service:
        scenarios = ()

        def analyze_telemetry(self, *_args, **_kwargs):
            calls.append("run")
            raise AssertionError

    choices = iter(("4", "0", "0"))
    controller = DetectionLabConsoleController(
        Service(),
        RuleExplanationService(),
        input_func=lambda _prompt: next(choices),
        output_func=lambda _output: None,
    )
    controller.last_result = _result()
    before = marker.read_bytes()

    controller.run()

    assert calls == []
    assert marker.read_bytes() == before


def test_triggered_rule_drilldown_reuses_explainability_without_rerun():
    calls = []

    class ExplanationService:
        def explanation_for(self, rule_id):
            calls.append(rule_id)
            return RuleExplanationService().explanation_for(rule_id)

    choices = iter(("1", "0", "0"))
    outputs = []
    controller = DetectionLabConsoleController(
        DetectionLabService(),
        ExplanationService(),
        input_func=lambda _prompt: next(choices),
        output_func=outputs.append,
    )

    controller._show_result(
        _result(
            triggered_rules=(
                ("SOCF-010", "Password spray suspected"),
            )
        )
    )

    assert calls == ["SOCF-010"]
    assert any("RULE LOGIC" in strip_ansi(output) for output in outputs)
    assert sum("DETECTION LAB RESULT" in output for output in outputs) == 2


def test_invalid_simulation_and_pipeline_errors_are_bounded():
    class Service:
        scenarios = ("mixed",)

        def analyze_telemetry(self, *_args, **_kwargs):
            raise FileNotFoundError("missing.jsonl")

    choices = iter(("2", "9", "1", "missing.jsonl", "n", "0"))
    outputs, pauses = [], []
    controller = DetectionLabConsoleController(
        Service(),
        RuleExplanationService(),
        input_func=lambda _prompt: next(choices),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run()

    plain = "\n".join(strip_ansi(output) for output in outputs)
    assert "Invalid simulation selection" in plain
    assert "Detection Lab run failed: missing.jsonl" in plain
    assert pauses == ["pause", "pause"]


def test_detection_menu_dispatches_real_lab_controller(monkeypatch):
    from soc_forge.menus import detection

    class Controller:
        calls = 0

        def run(self):
            self.calls += 1

    controller = Controller()
    choices = iter(("3", "0"))
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda _title: None)
    monkeypatch.setattr(detection, "menu_option", lambda *_args: None)

    detection.detection_menu(
        *(lambda: None for _ in range(6)),
        lambda: None,
        lambda: None,
        lambda: None,
        controller,
    )

    assert controller.calls == 1
