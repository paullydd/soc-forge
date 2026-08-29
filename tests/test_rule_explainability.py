from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from soc_forge.detection_engineering import DetectionEngineeringService
from soc_forge.menus.detection_engineering import (
    DetectionEngineeringConsoleController,
)
from soc_forge.menus.rule_explainability import (
    render_rule_explanation,
    render_rule_explanation_catalog,
)
from soc_forge.rule_explainability import RuleExplanationService
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule, run_rules
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


def _rule(**changes):
    values = {
        "id": "SOCF-EXPLAIN-001",
        "enabled": True,
        "title": "Explainable aggregate rule",
        "severity": "high",
        "score": 70,
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique": "Password Spraying",
                "technique_id": "T1110.003",
            }
        ],
        "match": {
            "all": [
                {"field": "event_id", "op": "eq", "value": 4625},
                {
                    "any": [
                        {
                            "field": "message",
                            "op": "contains",
                            "value": "failed",
                        },
                        {
                            "field": "source_ip",
                            "op": "exists",
                        },
                    ]
                },
            ]
        },
        "emit": {
            "summary": "Multiple usernames failed.",
            "details": {
                "host": "${host}",
                "source_ip": "${source_ip}",
                "username": "${username}",
                "constant": True,
            },
        },
        "score_modifiers": [
            {
                "when": {
                    "field": "username",
                    "op": "regex",
                    "value": "(?i)admin",
                },
                "add": 10,
                "bump_severity": True,
                "set_details": {"privileged": True},
                "reason": "Privileged account name",
            }
        ],
        "aggregate": {
            "group_by": ["source_ip"],
            "window_minutes": 10,
            "distinct_count": {"field": "username", "gte": 5},
        },
        "description": "Detects configured password spray behavior.",
        "author": "SOC-Forge",
        "created": "2026-08-20",
        "logsource": "windows-security",
        "tags": ["identity", "windows", "identity"],
    }
    values.update(changes)
    return Rule(**values)


def test_explanation_projects_identity_logic_fields_and_metadata():
    explanation = RuleExplanationService.explain(_rule())

    assert explanation.rule_id == "SOCF-EXPLAIN-001"
    assert explanation.title == "Explainable aggregate rule"
    assert explanation.summary == "Detects configured password spray behavior."
    assert explanation.enabled is True
    assert explanation.severity == "high"
    assert explanation.description == explanation.summary
    assert explanation.operators == ("eq", "contains", "regex", "exists")
    assert tuple(item.operator for item in explanation.match_conditions) == (
        "eq",
        "contains",
        "exists",
    )
    assert explanation.match_logic == (
        "All of:",
        "  - event_id equals 4625",
        "  Any of:",
        '    - message contains "failed"',
        "    - source_ip exists",
    )
    assert explanation.referenced_fields == (
        "event_id",
        "host",
        "message",
        "source_ip",
        "timestamp",
        "username",
    )
    assert explanation.tags == ("identity", "windows")
    assert explanation.logsource == "windows-security"
    assert explanation.author == "SOC-Forge"
    assert explanation.created == "2026-08-20"


def test_explanation_projects_aggregation_emit_modifiers_and_attack():
    explanation = RuleExplanationService.explain(_rule())

    assert explanation.aggregate_behavior == "Distinct count"
    assert explanation.grouping_fields == ("source_ip",)
    assert explanation.aggregate_field == "username"
    assert explanation.threshold == 5
    assert explanation.time_window_minutes == 10
    assert explanation.emit_summary == "Multiple usernames failed."
    assert explanation.emit_fields == (
        "constant",
        "host",
        "source_ip",
        "username",
    )
    assert explanation.emit_source_fields == ("host", "source_ip", "username")
    modifier = explanation.score_modifiers[0]
    assert modifier.logic == ('- username matches regular expression "(?i)admin"',)
    assert modifier.score_addition == 10
    assert modifier.bumps_severity is True
    assert modifier.detail_updates == (("privileged", "true"),)
    assert modifier.reason == "Privileged account name"
    assert explanation.attack_tactics == ("Credential Access",)
    assert explanation.attack_techniques == (
        "T1110.003 - Password Spraying",
    )
    assert explanation.attack_mappings[0].presentation == (
        "Credential Access | T1110.003 - Password Spraying"
    )


def test_absent_optional_metadata_stays_absent_without_fabrication():
    explanation = RuleExplanationService.explain(
        _rule(
            description="",
            enabled=False,
            emit={},
            aggregate={},
            score_modifiers=[],
            mitre=[],
            logsource="",
            tags=[],
            author="",
            created="",
        )
    )

    assert explanation.summary == ""
    assert explanation.enabled is False
    assert explanation.aggregate_behavior == ""
    assert explanation.grouping_fields == ()
    assert explanation.aggregate_field == ""
    assert explanation.threshold is None
    assert explanation.time_window_minutes is None
    assert explanation.emit_summary == ""
    assert explanation.emit_fields == ()
    assert explanation.emit_source_fields == ()
    assert explanation.score_modifiers == ()
    assert explanation.attack_mappings == ()
    assert explanation.limitations == ()
    assert explanation.assumptions == ()


def test_explanation_is_immutable_deterministic_and_does_not_mutate_rule():
    rule = _rule()
    before = deepcopy(rule)

    first = RuleExplanationService.explain(rule)
    second = RuleExplanationService.explain(rule)

    assert first == second
    assert rule == before
    with pytest.raises(FrozenInstanceError):
        first.title = "Changed"


def test_explanation_read_does_not_execute_or_change_detection_results():
    rule = _rule(
        aggregate={},
        match={"field": "event_id", "op": "eq", "value": 4625},
    )
    event = {
        "event_id": 4625,
        "timestamp": "2026-08-20T12:00:00Z",
        "host": "WIN-01",
        "source_ip": "192.0.2.1",
        "username": "analyst",
        "message": "failed",
    }
    expected = run_rules([deepcopy(event)], [rule])
    calls = []
    service = RuleExplanationService(
        rule_loader=lambda paths: calls.append(tuple(paths)) or [rule]
    )

    service.explanations()
    actual = run_rules([deepcopy(event)], [rule])

    assert calls == [(str(BUILTIN_RULES_PATH),)]
    assert actual == expected


def test_builtin_explanations_are_sorted_and_leave_rule_files_unchanged():
    before = {
        path.name: path.read_bytes()
        for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    }

    explanations = RuleExplanationService().explanations()

    assert explanations
    assert [item.rule_id for item in explanations] == sorted(
        item.rule_id for item in explanations
    )
    assert {
        path.name: path.read_bytes()
        for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    } == before


@pytest.mark.parametrize("width", [100, 80, 60, 10])
def test_explanation_rendering_is_width_safe(width):
    explanation = RuleExplanationService.explain(_rule())
    outputs = (
        render_rule_explanation_catalog(
            (explanation,), width=width, ansi=False
        ),
        render_rule_explanation(explanation, width=width, ansi=False),
    )

    for output in outputs:
        assert all(
            len(line) <= resolve_terminal_width(width)
            for line in output.splitlines()
        )
    assert "RULE LOGIC" in outputs[1] or width < len("RULE LOGIC")


def test_explanation_rendering_has_sections_no_color_and_ascii(monkeypatch):
    explanation = RuleExplanationService.explain(_rule())
    monkeypatch.setenv("NO_COLOR", "1")
    output = render_rule_explanation(explanation, unicode=False)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    dumb_catalog = render_rule_explanation_catalog((explanation,))

    assert strip_ansi(output) == output
    assert strip_ansi(dumb_catalog) == dumb_catalog
    assert "+" in output and "|" in output
    for heading in (
        "OVERVIEW",
        "RULE LOGIC",
        "REFERENCED FIELDS",
        "AGGREGATION",
        "SCORE MODIFIERS",
        "MITRE ATT&CK",
        "OUTPUT",
        "LIMITATIONS",
    ):
        assert heading in output
    assert "does not establish detection completeness" in " ".join(output.replace("|", " ").split())


def test_explainability_controller_selection_and_exact_back_inputs():
    service = DetectionEngineeringService(rule_loader=lambda _paths: [_rule()])
    choices = iter(("1", "0", ""))
    inputs, outputs, pauses = [], [], []
    controller = DetectionEngineeringConsoleController(
        service,
        input_func=lambda prompt: inputs.append(prompt) or next(choices),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run_rule_explainability()

    assert len(inputs) == 3
    assert inputs[1] == "[0] Back: "
    assert pauses == []
    assert "SELECT RULE" in strip_ansi(outputs[0])
    assert "RULE LOGIC" in strip_ansi(outputs[1])


def test_rule_catalog_reuses_explanation_service():
    service = DetectionEngineeringService(rule_loader=lambda _paths: [_rule()])
    choices = iter(("1", "1", "0", "", ""))
    inputs, outputs = [], []
    controller = DetectionEngineeringConsoleController(
        service,
        input_func=lambda prompt: inputs.append(prompt) or next(choices),
        output_func=outputs.append,
    )

    controller.run_rule_catalog()

    assert len(inputs) == 5
    assert "RULE DETAIL" in strip_ansi(outputs[1])
    assert "RULE LOGIC" in strip_ansi(outputs[2])
    assert "RULE DETAIL" in strip_ansi(outputs[3])


def test_explainability_loader_error_is_bounded_without_selection_input():
    service = DetectionEngineeringService(rule_loader=lambda _paths: [])
    explanation_service = RuleExplanationService(
        rule_loader=lambda _paths: (_ for _ in ()).throw(
            ValueError("Rule validation failed: invalid match")
        )
    )
    outputs, pauses = [], []
    controller = DetectionEngineeringConsoleController(
        service,
        explanation_service=explanation_service,
        input_func=lambda _prompt: pytest.fail("input requested after load error"),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run_rule_explainability()

    assert pauses == ["pause"]
    assert "Rule Explainability unavailable" in strip_ansi(outputs[0])


def test_detection_menu_dispatches_rule_explainability(monkeypatch):
    from soc_forge.menus import detection

    choices = iter(("5", "0"))
    calls = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda _title: None)
    monkeypatch.setattr(detection, "menu_option", lambda *_args: None)
    detection.detection_menu(
        *(lambda: None for _ in range(6)),
        lambda: None,
        lambda: None,
        lambda: calls.append("explainability"),
    )

    assert calls == ["explainability"]
