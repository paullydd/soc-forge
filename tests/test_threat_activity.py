from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from soc_forge.investigations.models import (
    InvestigationFinding, ResponseAction, ResponseActionTransition,
)
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.menus.threat_activity import (
    ThreatActivityConsoleController, render_threat_activity_overview,
)
from soc_forge.pipeline import AnalysisResult
from soc_forge.threat_activity import ThreatActivityOverviewService
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_investigation_repository import build_investigation


def _analysis(alerts=()):
    root = Path("out")
    return AnalysisResult(
        "events.jsonl", None, root, None, None, None, None, None, None,
        0, [], list(alerts), [], [], {}, [], {}, [{"case_id": "CASE-1"}],
        [{"case_id": "CASE-1"}], [], {}, [], 1,
    )


def _finding(**changes):
    values = dict(
        finding_id="FIND-1", investigation_id="INV-1", title="Password spray",
        conclusion="Observed.", status="substantiated", confidence="high",
        author="analyst", created_at="2026-08-20T10:00:00Z",
        updated_at="2026-08-20T11:00:00Z", decision_ids=("DECISION-001",),
        attack_tactics=("Credential Access",),
        attack_techniques=("T1110.003 - Password Spraying",),
    )
    values.update(changes)
    return InvestigationFinding(**values)


def _action():
    transition = ResponseActionTransition(
        "TRANS-1", "proposed", "approved", "analyst", "Ready.",
        "2026-08-20T12:00:00Z",
    )
    return ResponseAction(
        "ACT-1", "INV-1", ("FIND-1",), "Reset account", "Reset it.",
        "credential_action", "high", "approved", "Contain risk.", "analyst",
        "analyst", "2026-08-20T11:30:00Z", "2026-08-20T12:00:00Z",
        (transition,),
    )


def _repository(tmp_path, *, include_activity=True):
    repository = InvestigationRepository(tmp_path / "workspace")
    investigation = build_investigation("INV-1")
    if include_activity:
        investigation = replace(
            investigation, findings=(_finding(),),
            response_actions=(_action(),), handoff_manifest=None,
        )
    repository.save(investigation)
    return repository


def test_empty_overview_is_offline_and_machine_counts_are_unavailable(tmp_path):
    overview = ThreatActivityOverviewService(
        InvestigationRepository(tmp_path / "workspace")
    ).summarize()
    assert overview.mode == "offline"
    assert overview.investigation_count == 0
    assert overview.alert_count is None
    assert overview.tactics == overview.techniques == overview.recent_activity == ()


def test_durable_counts_attack_activity_recent_entries_and_immutability(tmp_path):
    overview = ThreatActivityOverviewService(_repository(tmp_path)).summarize()
    assert (overview.investigation_count, overview.active_finding_count,
            overview.historical_finding_count, overview.open_response_action_count) == (1, 1, 0, 1)
    assert overview.tactics[0].value == "Credential Access"
    assert overview.tactics[0].analyst_observations == 1
    assert [row.source_type for row in overview.recent_activity] == [
        "response_action", "finding"
    ]
    assert all(row.origin == "analyst" for row in overview.recent_activity)
    with pytest.raises(FrozenInstanceError):
        overview.mode = "full"


def test_historical_finding_is_counted_separately(tmp_path):
    repository = _repository(tmp_path, include_activity=False)
    investigation = repository.load_record("INV-1")
    historical = _finding(
        lifecycle_state="superseded", superseded_by_finding_id="FIND-2",
        supersession_reason="Refined.", supersession_author="analyst",
        superseded_at="2026-08-20T12:00:00Z",
    )
    replacement = _finding(finding_id="FIND-2", supersedes_finding_id="FIND-1")
    repository.save(replace(investigation.investigation, findings=(historical, replacement),
                            handoff_manifest=None),
                    expected_revision=investigation.revision)
    overview = ThreatActivityOverviewService(repository).summarize()
    assert (overview.active_finding_count, overview.historical_finding_count) == (1, 1)


def test_full_mode_uses_current_machine_counts_and_explicit_alert_mappings(tmp_path):
    alert = {
        "rule_id": "SOCF-010", "title": "Password spray",
        "timestamp": "2026-08-20T13:00:00Z",
        "mitre": [
            {"tactic": "Credential Access", "technique_id": "T1110.003",
             "technique": "Password Spraying"},
            {"tactic": "Credential Access", "technique_id": "T1110.003",
             "technique": "Password Spraying"},
        ],
    }
    overview = ThreatActivityOverviewService(
        _repository(tmp_path), lambda: _analysis((alert,))
    ).summarize()
    assert overview.mode == "full"
    assert (overview.alert_count, overview.case_count, overview.hunt_count,
            overview.reconstruction_count) == (1, 1, 0, 1)
    tactic = overview.tactics[0]
    assert (tactic.observation_count, tactic.machine_observations,
            tactic.analyst_observations) == (2, 1, 1)
    assert overview.techniques[0].value == "T1110.003 - Password Spraying"
    assert overview.recent_activity[0].origin == "machine"


def test_no_mapping_is_fabricated_and_coverage_is_not_consulted(tmp_path):
    overview = ThreatActivityOverviewService(
        _repository(tmp_path, include_activity=False),
        lambda: _analysis(({"rule_id": "SOCF-010", "timestamp": ""},)),
    ).summarize()
    assert overview.tactics == ()
    assert overview.techniques == ()


def test_recent_activity_is_bounded_deterministic_and_read_only(tmp_path):
    repository = _repository(tmp_path)
    before = tuple((path, path.read_bytes()) for path in
                   sorted(repository.investigations_root.glob("*.json")))
    service = ThreatActivityOverviewService(repository, recent_limit=1)
    assert service.summarize() == service.summarize()
    assert len(service.summarize().recent_activity) == 1
    assert before == tuple((path, path.read_bytes()) for path in
                           sorted(repository.investigations_root.glob("*.json")))
    assert repository.load_record("INV-1").revision == 1


@pytest.mark.parametrize("width", (100, 60))
def test_terminal_screen_full_offline_narrow_and_no_color(tmp_path, width, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    overview = ThreatActivityOverviewService(_repository(tmp_path)).summarize()
    rendered = render_threat_activity_overview(overview, width=width)
    assert "SOC-FORGE" in rendered
    if width >= 60:
        assert "ANALYSIS" in rendered
        assert "THREAT ACTIVITY" in rendered
    assert "ACTIVITY STATE" in rendered
    assert "[OFFLINE]" in rendered
    assert "OBSERVED ATT&CK ACTIVITY" in rendered
    assert "RECENT SECURITY ACTIVITY" in rendered
    assert "[ANALYST]" in rendered
    assert strip_ansi(rendered) == rendered
    assert all(len(line) <= resolve_terminal_width(width)
               for line in rendered.splitlines())


def test_controller_renders_and_back_does_not_mutate(tmp_path):
    repository = _repository(tmp_path)
    output, prompts = [], []
    controller = ThreatActivityConsoleController(
        ThreatActivityOverviewService(repository),
        input_func=lambda prompt: prompts.append(prompt) or "",
        output_func=output.append,
    )
    controller.run()
    assert "THREAT ACTIVITY" in output[0]
    assert prompts == ["\nPress Enter to go back..."]
    assert repository.load_record("INV-1").revision == 1


def test_analysis_option_one_dispatches_real_controller(monkeypatch):
    from soc_forge.menus import analysis
    calls = []
    choices = iter(("1", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("overview")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analysis, "begin_screen", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_group", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_option", lambda *_args: None)
    analysis.analysis_menu(lambda: None, lambda: None, lambda: None, controller)
    assert calls == ["overview"]


def test_terminal_screen_handles_minimum_width(tmp_path):
    overview = ThreatActivityOverviewService(_repository(tmp_path)).summarize()
    rendered = render_threat_activity_overview(overview, width=24, ansi=False)
    assert all(len(line) <= 24 for line in rendered.splitlines())
    assert 'ACTIVITY STATE' in rendered
