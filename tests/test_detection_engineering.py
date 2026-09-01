from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from soc_forge.detection_engineering import DetectionEngineeringService
from soc_forge.menus.detection_engineering import (
    DetectionEngineeringConsoleController,
    render_detection_overview,
    render_rule_catalog,
    render_rule_detail,
)
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


def _rule(rule_id="SOCF-002", **changes):
    values = {
        "id": rule_id,
        "enabled": True,
        "title": "Account lockout",
        "severity": "high",
        "score": 60,
        "mitre": [
            {
                "tactic": "Credential Access",
                "technique": "Brute Force",
                "technique_id": "T1110",
            }
        ],
        "match": {"all": [{"field": "event_id", "op": "eq", "value": 4740}]},
        "emit": {"summary": "Account locked."},
        "score_modifiers": [],
        "aggregate": {"window_minutes": 10},
        "description": "Detects account lockouts.",
        "author": "SOC-Forge",
        "created": "2026-01-01",
        "logsource": "windows-security",
        "tags": ["identity", "windows"],
    }
    values.update(changes)
    return Rule(**values)


def test_overview_projects_rule_and_recent_alert_state_deterministically():
    rules = [
        _rule("SOCF-010", mitre=[
            {"tactic": "Credential Access", "technique": "Password Spraying", "technique_id": "T1110.003"},
            {"tactic": "Credential Access", "technique": "Password Spraying", "technique_id": "T1110.003"},
        ]),
        _rule(
            "SOCF-002",
            enabled=False,
            mitre=[{"tactic": "Impact", "technique": "Account Access Removal", "technique_id": "T1531"}],
        ),
    ]
    alerts = [
        {"rule_id": "SOCF-002", "title": "Older", "severity": "high", "timestamp": "2026-01-01T00:00:00Z"},
        {"rule_id": "SOCF-010", "title": "Newest", "severity": "high", "timestamp": "2026-01-02T00:00:00Z"},
        {"rule_id": "SOCF-010", "title": "Repeat", "severity": "high", "timestamp": "2026-01-01T12:00:00Z"},
    ]
    service = DetectionEngineeringService(
        rule_loader=lambda _paths: rules,
        alert_loader=lambda: alerts,
    )

    first = service.overview()
    second = service.overview()

    assert first == second
    assert (first.total_rules, first.enabled_rules, first.disabled_rules) == (2, 1, 1)
    assert (first.tactics_count, first.techniques_count) == (2, 2)
    assert first.recent_alert_count == 3
    assert first.recently_triggered_rule_count == 2
    assert first.recently_triggered_rules == ("SOCF-002", "SOCF-010")
    assert [item.title for item in first.recent_detections] == [
        "Newest", "Repeat", "Older",
    ]
    assert first.last_detection_timestamp == "2026-01-02T00:00:00Z"


def test_overview_empty_alerts_does_not_run_detection_or_mutate_inputs():
    rules = [_rule()]
    before = deepcopy(rules)
    calls = []
    service = DetectionEngineeringService(
        rule_loader=lambda paths: calls.append(("load_rules", tuple(paths))) or rules,
        alert_loader=lambda: calls.append(("load_alerts",)) or (),
    )

    overview = service.overview()

    assert overview.recent_alert_count == 0
    assert overview.recent_detections == ()
    assert overview.last_detection_timestamp is None
    assert [call[0] for call in calls] == ["load_rules", "load_alerts"]
    assert rules == before
    with pytest.raises(FrozenInstanceError):
        overview.total_rules = 99


def test_builtin_catalog_lists_every_loaded_rule_in_rule_id_order_without_mutation():
    before = {
        path.name: path.read_bytes() for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    }
    service = DetectionEngineeringService()
    catalog = service.rule_catalog()

    assert catalog
    assert [entry.rule_id for entry in catalog] == sorted(
        entry.rule_id for entry in catalog
    )
    assert len(catalog) == len(before)
    assert all(entry.rule_id and entry.title for entry in catalog)
    assert all(isinstance(entry.enabled, bool) and entry.severity for entry in catalog)
    assert {
        path.name: path.read_bytes() for path in BUILTIN_RULES_PATH.glob("SOCF-*.yml")
    } == before


def test_rule_catalog_normalizes_explicit_attack_metadata_and_detail_fields():
    rule = _rule(
        tags=["windows", "identity", "windows"],
        mitre=[
            {"tactic": "Credential Access", "technique": "Brute Force", "technique_id": "T1110"},
            {"tactic": "Credential Access", "technique": "Brute Force", "technique_id": "T1110"},
        ],
    )
    entry = DetectionEngineeringService(
        rule_loader=lambda _paths: [rule]
    ).rule_catalog()[0]

    assert entry.tags == ("identity", "windows")
    assert len(entry.attack_mappings) == 1
    assert entry.attack_mappings[0].presentation == (
        "Credential Access | T1110 - Brute Force"
    )
    assert '"event_id"' in entry.match_metadata
    assert '"summary"' in entry.emit_metadata
    assert '"window_minutes"' in entry.aggregate_metadata
    detail = strip_ansi(render_rule_detail(entry, width=100, ansi=False))
    for value in (
        "SOCF-002", "Account lockout", "Detects account lockouts.",
        "identity, windows", "windows-security", "SOC-Forge", "Match metadata",
        "Emit metadata", "Aggregate metadata",
    ):
        assert value in detail


@pytest.mark.parametrize("width", [100, 80, 60, 10])
def test_overview_and_catalog_are_width_safe(width):
    service = DetectionEngineeringService(
        rule_loader=lambda _paths: [_rule()],
        alert_loader=lambda: (),
    )
    catalog = service.rule_catalog()
    overview = service.overview(catalog)
    outputs = (
        render_detection_overview(overview, width=width, ansi=False),
        render_rule_catalog(catalog, width=width, ansi=False),
        render_rule_detail(catalog[0], width=width, ansi=False),
    )
    for output in outputs:
        assert all(
            len(line) <= resolve_terminal_width(width)
            for line in output.splitlines()
        )
    assert "[ENABLED]" in outputs[1] or width < len("[ENABLED]")
    assert "No recent" in outputs[0]


def test_detection_rendering_supports_no_color_term_dumb_and_ascii(monkeypatch):
    service = DetectionEngineeringService(rule_loader=lambda _paths: [_rule()])
    overview = service.overview()
    monkeypatch.setenv("NO_COLOR", "1")
    no_color = render_detection_overview(overview)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    dumb = render_rule_catalog(service.rule_catalog())
    ascii_output = render_rule_detail(
        service.rule_catalog()[0], ansi=False, unicode=False
    )
    assert strip_ansi(no_color) == no_color
    assert strip_ansi(dumb) == dumb
    assert "+" in ascii_output and "|" in ascii_output


def test_rule_catalog_controller_detail_and_blank_back_exact_input():
    service = DetectionEngineeringService(rule_loader=lambda _paths: [_rule()])
    choices = iter(("1", "", ""))
    inputs, outputs, pauses = [], [], []
    controller = DetectionEngineeringConsoleController(
        service,
        input_func=lambda prompt: inputs.append(prompt) or next(choices),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run_rule_catalog()

    assert len(inputs) == 3
    assert pauses == []
    assert "RULE CATALOG" in strip_ansi(outputs[0])
    assert "RULE DETAIL" in strip_ansi(outputs[1])


def test_loader_error_is_bounded_and_does_not_enter_catalog_input():
    service = DetectionEngineeringService(
        rule_loader=lambda _paths: (_ for _ in ()).throw(
            ValueError("Rule validation failed: bad op")
        )
    )
    outputs, pauses = [], []
    controller = DetectionEngineeringConsoleController(
        service,
        input_func=lambda _prompt: pytest.fail("catalog requested input after load error"),
        output_func=outputs.append,
        pause_func=lambda: pauses.append("pause"),
    )

    controller.run_rule_catalog()

    assert pauses == ["pause"]
    assert "Rule Catalog unavailable" in strip_ansi(outputs[0])
    assert all(len(line) <= 80 for line in outputs[0].splitlines())


def test_detection_menu_dispatches_real_overview_and_catalog(monkeypatch):
    from soc_forge.menus import detection

    choices = iter(("1", "2", "0"))
    calls = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(detection, "begin_screen", lambda _title: None)
    monkeypatch.setattr(detection, "menu_group", lambda _title: None)
    monkeypatch.setattr(detection, "menu_option", lambda *_args: None)
    detection.detection_menu(
        *(lambda: None for _ in range(3)),
        lambda: calls.append("overview"),
        lambda: calls.append("catalog"),
    )
    assert calls == ["overview", "catalog"]
