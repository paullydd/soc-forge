from copy import deepcopy
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from soc_forge.hunt_workspace import HuntWorkspaceService
from soc_forge.menus.hunt_workspace import (
    HuntWorkspaceConsoleController, render_existing_hunts, render_hunt_detail,
    render_hunt_menu, render_technique_hunt,
)
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_temporal_analysis import analysis, repository


class Entity:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def search(self, kind, value):
        self.calls.append((kind, value))
        return self.result


class Attack:
    def __init__(self, summary):
        self.summary = summary

    def summarize(self):
        return self.summary


class Temporal:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def analyze(self, **kwargs):
        self.calls.append(kwargs)
        return self.result


def service(tmp_path, *, full=True, limit=25):
    current = analysis()
    current.hunt_findings = [{
        "hunt_id": "HUNT-001", "title": "Suspicious Command Execution",
        "severity": "high", "category": "execution",
        "summary": "Structured pipeline Hunt finding.", "confidence": "high",
        "entities": {"host": "host-1", "username": "alice"},
        "evidence": [{"timestamp": "2026-08-21T10:00:00Z"}],
        "first_seen": "2026-08-21T10:00:00Z",
        "last_seen": "2026-08-21T10:00:00Z",
        "mitre": ["T1059"],
    }]
    temporal_result = SimpleNamespace(
        mode="offline", timed_entry_count=0, untimed_entry_count=0,
        first_timestamp=None, last_timestamp=None, investigations_represented=0,
        machine_entry_count=0, analyst_entry_count=0, entries=(),
        untimed_entries=(),
    )
    entity_result = SimpleNamespace(
        entity_type="host", query="host-1", normalized_query="host-1",
        mode="full", observation_count=0, alert_count=0,
        investigation_count=0, finding_count=0, response_action_count=0,
        case_count=0, observations=(), related_entities=(),
        attack_tactics=(), attack_techniques=(), investigation_ids=(),
    )
    technique = SimpleNamespace(
        technique_key="T1059", observation_count=2,
        machine_observation_count=1, analyst_observation_count=1,
        investigation_count=2, investigation_ids=("INV-1", "INV-2"),
        technique_id="T1059",
    )
    attack_summary = SimpleNamespace(mode="full", techniques=(technique,))
    provider = (lambda: current) if full else (lambda: None)
    return HuntWorkspaceService(
        Entity(entity_result), Attack(attack_summary),
        Temporal(temporal_result), provider, result_limit=limit,
    ), current


def test_existing_hunts_authoritative_full_projection_and_immutable(tmp_path):
    workspace, _analysis = service(tmp_path)
    summary = workspace.summarize()
    assert summary.mode == "full"
    assert summary.hunt_count == summary.result_count == 1
    hunt = summary.hunts[0]
    assert hunt.hunt_id == "HUNT-001"
    assert hunt.title == "Suspicious Command Execution"
    assert hunt.techniques == ("T1059",)
    assert hunt.evidence_count == 1
    with pytest.raises(FrozenInstanceError):
        summary.mode = "offline"


def test_offline_hunt_availability_is_unknown_not_zero(tmp_path):
    workspace, _analysis = service(tmp_path, full=False)
    summary = workspace.summarize()
    assert summary.mode == "offline"
    assert summary.hunt_count is None and summary.result_count is None
    assert summary.hunts == ()
    assert not summary.machine_context_available
    assert "unavailable in OFFLINE mode" in render_existing_hunts(
        summary, ansi=False
    )


def test_empty_full_hunt_state(tmp_path):
    workspace, current = service(tmp_path)
    current.hunt_findings = []
    summary = workspace.summarize()
    assert summary.hunt_count == 0
    assert "No existing Hunt findings" in render_existing_hunts(
        summary, ansi=False
    )


def test_projection_does_not_mutate_analysis(tmp_path):
    workspace, current = service(tmp_path)
    before = deepcopy(current)
    workspace.summarize()
    assert current == before


@pytest.mark.parametrize(("kind", "value"), (
    ("host", "HOST-1"), ("user", "Alice"), ("ip", "192.0.2.1"),
    ("process", "PowerShell.EXE"),
))
def test_entity_hunt_delegates_exactly_to_entity_explorer(tmp_path, kind, value):
    workspace, _analysis = service(tmp_path)
    result = workspace.entity_hunt(kind, value)
    assert workspace.entity_explorer.calls == [(kind, value)]
    assert result.mode == "full"


def test_attack_hunt_reuses_explicit_attack_activity(tmp_path):
    workspace, _analysis = service(tmp_path)
    mode, rows = workspace.technique_hunt("t1059")
    assert mode == "full"
    assert rows[0].technique_id == "T1059"
    assert rows[0].machine_observation_count == rows[0].analyst_observation_count == 1
    assert workspace.technique_hunt("T9999")[1] == ()


def test_investigation_hunt_delegates_to_temporal_filter(tmp_path):
    workspace, _analysis = service(tmp_path)
    workspace.investigation_hunt("INV-1")
    assert workspace.temporal_analysis.calls == [
        {"investigation_id": "INV-1"}
    ]


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_terminal_width_no_color_ascii_caution_and_detail(tmp_path, width, monkeypatch):
    workspace, _analysis = service(tmp_path)
    summary = workspace.summarize()
    monkeypatch.setenv("NO_COLOR", "1")
    views = (
        render_hunt_menu(summary, width=width),
        render_existing_hunts(summary, width=width),
        render_hunt_detail(summary.hunts[0], width=width),
        render_technique_hunt("full", workspace.technique_hunt("T1059")[1],
                              "T1059", width=width),
        render_hunt_menu(summary, width=width, unicode=False, ansi=False),
    )
    for rendered in views:
        assert strip_ansi(rendered) == rendered
        assert all(len(line) <= resolve_terminal_width(width)
                   for line in rendered.splitlines())
    if width >= 80:
        joined = "\n".join(views)
        assert "HUNT STATE" in joined and "HUNT DETAIL" in joined
        assert "[MACHINE]" in joined and "[ANALYST]" in joined
        assert "does not establish" in joined
        assert "shared" in joined
        assert "campaign, incident, or cause." in joined


def test_controller_all_views_and_back(tmp_path):
    workspace, _analysis = service(tmp_path)
    inputs = iter(("1", "1", "", "2", "host", "host-1", "",
                   "3", "T1059", "", "4", "INV-1", "", "0"))
    output = []
    HuntWorkspaceConsoleController(
        workspace, input_func=lambda _prompt="": next(inputs),
        output_func=output.append,
    ).run()
    joined = "\n".join(output)
    assert "HUNT DETAIL" in joined
    assert "ENTITY EXPLORER" in joined
    assert "ATT&CK TECHNIQUE HUNT" in joined
    assert "Hunt view filtered to INV-1" in joined


def test_analysis_option_six_dispatches_controller(monkeypatch):
    from soc_forge.menus import analysis as menu
    calls = []
    choices = iter(("6", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("hunt")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(menu, "begin_screen", lambda _title: None)
    monkeypatch.setattr(menu, "menu_group", lambda _title: None)
    monkeypatch.setattr(menu, "menu_option", lambda *_args: None)
    menu.analysis_menu(
        lambda: None, lambda: None, lambda: None,
        None, None, None, None, None, controller,
    )
    assert calls == ["hunt"]
