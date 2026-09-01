from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from soc_forge.detection_coverage import (
    DetectionCoverageService,
    DetectionGapService,
)
from soc_forge.detection_engineering import DetectionEngineeringService
from soc_forge.menus.detection_coverage import (
    DetectionCoverageConsoleController,
    render_coverage_menu,
    render_coverage_summary,
    render_gaps,
    render_gaps_menu,
    render_tactic_coverage,
    render_technique_coverage,
    render_unmapped_rules,
)
from soc_forge.rule_explainability import RuleExplanationService
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


def _rule(rule_id, *, enabled=True, mitre=None):
    return Rule(
        id=rule_id,
        enabled=enabled,
        title=f"Rule {rule_id}",
        severity="high",
        score=70,
        mitre=list(mitre or []),
        match={"field": "event_id", "op": "eq", "value": 1},
        emit={},
        score_modifiers=[],
        aggregate={},
        description="",
        author="",
        created="",
        logsource="",
        tags=[],
    )


def _rules():
    shared = {
        "tactic": "Credential Access",
        "technique": "Password Spraying",
        "technique_id": "T1110.003",
    }
    return [
        _rule("SOCF-003"),
        _rule("SOCF-001", mitre=[shared]),
        _rule("SOCF-002", enabled=False, mitre=[shared]),
        _rule(
            "SOCF-004",
            enabled=False,
            mitre=[
                {
                    "tactic": "Persistence",
                    "technique": "Scheduled Task/Job",
                    "id": "T1053",
                }
            ],
        ),
    ]


def test_coverage_summary_counts_and_groups_explicit_metadata():
    summary = DetectionCoverageService.project(_rules())

    assert summary.total_rules == 4
    assert summary.enabled_rules == 2
    assert summary.disabled_rules == 2
    assert summary.rules_with_attack_mapping == 3
    assert summary.rules_without_attack_mapping == 1
    assert [item.tactic for item in summary.tactics] == [
        "Credential Access",
        "Persistence",
    ]
    assert [item.technique_key for item in summary.techniques] == [
        "T1053",
        "T1110.003",
    ]


def test_tactic_and_technique_grouping_preserves_multiple_rule_states():
    summary = DetectionCoverageService.project(_rules())
    credential = summary.tactics[0]
    password_spray = summary.techniques[1]

    assert credential.technique_keys == ("T1110.003",)
    assert credential.rule_ids == ("SOCF-001", "SOCF-002")
    assert password_spray.technique_name == "Password Spraying"
    assert password_spray.tactics == ("Credential Access",)
    assert password_spray.rule_ids == ("SOCF-001", "SOCF-002")
    assert password_spray.enabled_rule_ids == ("SOCF-001",)
    assert password_spray.disabled_rule_ids == ("SOCF-002",)


def test_coverage_projection_is_deterministic_immutable_and_non_mutating():
    rules = _rules()
    before = deepcopy(rules)

    first = DetectionCoverageService.project(reversed(rules))
    second = DetectionCoverageService.project(rules)

    assert first == second
    assert rules == before
    with pytest.raises(FrozenInstanceError):
        first.total_rules = 99


def test_coverage_loads_authoritative_rules_once_without_execution():
    calls = []
    service = DetectionCoverageService(
        rule_loader=lambda paths: calls.append(tuple(paths)) or _rules()
    )

    summary = service.summarize()

    assert summary.total_rules == 4
    assert calls == [(str(BUILTIN_RULES_PATH),)]


def test_builtin_coverage_leaves_rule_files_unchanged():
    before = {
        path.name: path.read_bytes()
        for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    }

    summary = DetectionCoverageService().summarize()

    assert summary.total_rules == len(before)
    assert {
        path.name: path.read_bytes()
        for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    } == before


def test_unmapped_rule_produces_only_deterministic_unmapped_gap():
    coverage = DetectionCoverageService.project(_rules())
    gaps = DetectionGapService(
        DetectionCoverageService(rule_loader=lambda _paths: [])
    ).summarize(coverage)
    unmapped = tuple(
        gap for gap in gaps.gaps if gap.gap_type == "UNMAPPED_RULE"
    )

    assert len(unmapped) == 1
    assert unmapped[0].gap_id == "DGAP:UNMAPPED:SOCF-003"
    assert unmapped[0].related_rule_ids == ("SOCF-003",)
    assert all("SOCF-001" not in gap.gap_id for gap in unmapped)


def test_disabled_only_technique_produces_enabled_availability_gap():
    coverage = DetectionCoverageService.project(_rules())
    gaps = DetectionGapService(
        DetectionCoverageService(rule_loader=lambda _paths: [])
    ).summarize(coverage)
    disabled = tuple(
        gap
        for gap in gaps.gaps
        if gap.gap_type == "DISABLED_COVERAGE"
    )

    assert len(disabled) == 1
    assert disabled[0].gap_id == "DGAP:DISABLED_COVERAGE:T1053"
    assert disabled[0].related_rule_ids == ("SOCF-004",)
    assert disabled[0].related_tactics == ("Persistence",)
    assert disabled[0].related_techniques == ("T1053",)


def test_gap_order_and_no_expected_baseline_policy_are_deterministic():
    coverage = DetectionCoverageService.project(reversed(_rules()))
    service = DetectionGapService(
        DetectionCoverageService(rule_loader=lambda _paths: [])
    )

    first = service.summarize(coverage)
    second = service.summarize(coverage)

    assert first == second
    assert [gap.gap_type for gap in first.gaps] == [
        "DISABLED_COVERAGE",
        "UNMAPPED_RULE",
    ]
    assert first.expected_baseline_configured is False
    assert "No expected ATT&CK baseline is configured" in first.scope_note
    assert not any(
        gap.gap_type == "ATTACK_REFERENCE_GAP"
        for gap in first.gaps
    )


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_coverage_and_gap_renderers_are_width_safe(width):
    coverage = DetectionCoverageService.project(_rules())
    gap_summary = DetectionGapService(
        DetectionCoverageService(rule_loader=lambda _paths: [])
    ).summarize(coverage)
    tactic, _ = render_tactic_coverage(
        coverage, width=width, ansi=False
    )
    technique, _ = render_technique_coverage(
        coverage, width=width, ansi=False
    )
    unmapped, _ = render_unmapped_rules(
        coverage, width=width, ansi=False
    )
    gaps, _ = render_gaps(
        gap_summary, width=width, ansi=False
    )
    outputs = (
        render_coverage_menu(width=width, ansi=False),
        render_coverage_summary(coverage, width=width, ansi=False),
        tactic,
        technique,
        unmapped,
        render_gaps_menu(width=width, ansi=False),
        gaps,
    )

    assert all(
        len(line) <= resolve_terminal_width(width)
        for output in outputs
        for line in output.splitlines()
    )


def test_terminal_copy_has_no_fake_percentage_coming_soon_or_health_claims(
    monkeypatch,
):
    coverage = DetectionCoverageService.project(_rules())
    gaps = DetectionGapService(
        DetectionCoverageService(rule_loader=lambda _paths: [])
    ).summarize(coverage)
    monkeypatch.setenv("NO_COLOR", "1")
    summary = render_coverage_summary(coverage, unicode=False)
    gap_output, _ = render_gaps(gaps, unicode=False)

    combined = summary + gap_output
    assert strip_ansi(combined) == combined
    assert "%" not in combined
    assert "Coming Soon" not in combined
    assert "telemetry is available" not in combined
    assert "sensor" not in combined.lower()
    assert "No expected ATT&CK baseline is configured" in " ".join(
        combined.replace("|", " ").split()
    )


def _controller(choices, outputs):
    rules = _rules()
    coverage_service = DetectionCoverageService(
        rule_loader=lambda _paths: rules
    )
    return DetectionCoverageConsoleController(
        coverage_service,
        DetectionGapService(coverage_service),
        DetectionEngineeringService(
            rule_loader=lambda _paths: rules
        ),
        RuleExplanationService(
            rule_loader=lambda _paths: rules
        ),
        input_func=lambda _prompt: next(choices),
        output_func=outputs.append,
    )


def test_coverage_menu_summary_and_exact_back_behavior():
    outputs = []
    controller = _controller(iter(("1", "0", "0")), outputs)

    controller.run_coverage()

    plain = "\n".join(strip_ansi(output) for output in outputs)
    assert "DETECTION COVERAGE" in plain
    assert "COVERAGE SUMMARY" in plain


def test_coverage_rule_drilldown_reuses_catalog_detail():
    outputs = []
    choices = iter(("2", "1", "0", "0", "0"))
    controller = _controller(choices, outputs)

    controller.run_coverage()

    assert any("RULE DETAIL" in strip_ansi(output) for output in outputs)


def test_gaps_menu_filters_and_returns_exactly_one_level():
    outputs = []
    controller = _controller(iter(("2", "0", "0")), outputs)

    controller.run_gaps()

    plain = "\n".join(strip_ansi(output) for output in outputs)
    assert "DETECTION GAPS" in plain
    assert "DGAP:UNMAPPED:SOCF-003" in plain
    assert "DGAP:DISABLED_COVERAGE" not in plain


def test_detection_menu_dispatches_real_coverage_and_gaps(monkeypatch):
    from soc_forge.menus import detection

    choices = iter(("4", "6", "0"))
    calls = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda _title: None)
    monkeypatch.setattr(detection, "menu_option", lambda *_args: None)

    detection.detection_menu(
        *(lambda: None for _ in range(3)),
        lambda: None,
        lambda: None,
        lambda: None,
        None,
        lambda: calls.append("coverage"),
        lambda: calls.append("gaps"),
    )

    assert calls == ["coverage", "gaps"]


def test_overview_attack_counts_match_authoritative_coverage_projection():
    from soc_forge.detection_engineering import DetectionEngineeringService

    coverage = DetectionCoverageService().summarize()
    overview = DetectionEngineeringService(
        alert_loader=lambda: ()
    ).overview()

    assert overview.total_rules == coverage.total_rules
    assert overview.enabled_rules == coverage.enabled_rules
    assert overview.disabled_rules == coverage.disabled_rules
    assert overview.tactics_count == len(coverage.tactics)
    assert overview.techniques_count == len(coverage.techniques)


def test_coverage_drilldown_reuses_rule_explainability():
    outputs = []
    choices = iter(("2", "1", "1", "0", "0", "0", "0"))
    controller = _controller(choices, outputs)

    controller.run_coverage()

    assert any("RULE LOGIC" in strip_ansi(output) for output in outputs)


def test_controller_loads_rules_once_for_coverage_and_catalog_projection():
    calls = []
    rules = _rules()
    coverage_service = DetectionCoverageService(
        rule_loader=lambda paths: calls.append(tuple(paths)) or rules
    )
    controller = DetectionCoverageConsoleController(
        coverage_service,
        DetectionGapService(coverage_service),
        DetectionEngineeringService(
            rule_loader=lambda _paths: pytest.fail(
                "catalog attempted a second rule load"
            )
        ),
        RuleExplanationService(
            rule_loader=lambda _paths: pytest.fail(
                "explanation attempted a second rule load"
            )
        ),
        input_func=lambda _prompt, choices=iter(("1", "0", "0")): next(
            choices
        ),
        output_func=lambda _output: None,
    )

    controller.run_coverage()

    assert calls == [(str(BUILTIN_RULES_PATH),)]
