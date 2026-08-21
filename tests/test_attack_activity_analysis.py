from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from soc_forge.attack_activity import AttackActivityService
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.menus.attack_activity import (
    AttackActivityConsoleController, render_attack_activity_menu,
    render_attack_activity_summary, render_recent, render_tactics,
    render_technique_detail, render_techniques,
)
from soc_forge.pipeline import AnalysisResult
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_investigation_repository import build_investigation


def _analysis():
    mapping = {"tactic": "Credential Access", "technique_id": "T1110.003",
               "technique": "Password Spraying"}
    alert = {
        "rule_id": "SOCF-010", "title": "Password spray",
        "timestamp": "2026-08-21T11:00:00Z",
        "mitre": [mapping, dict(mapping),
                  {"tactic": "Discovery", "technique_id": "T1087",
                   "technique": "Account Discovery"}],
    }
    case = {
        "case_id": "CASE-1", "title": "Credential case",
        "created_at": "2026-08-21T11:30:00Z", "mitre": [mapping],
    }
    reconstruction = {
        "case_id": "CASE-1", "attack_path": [{
            "title": "Persistence step", "timestamp": "2026-08-21T12:00:00Z",
            "tactic": "Persistence", "technique": "Scheduled Task/Job",
        }],
    }
    return AnalysisResult(
        "events.jsonl", None, Path("out"), None, None, None, None, None, None,
        0, [], [alert], [], [alert], {}, [], {}, [case], [reconstruction],
        [], {}, [], 1,
    )


def _finding(investigation_id, finding_id):
    return InvestigationFinding(
        finding_id, investigation_id, "Password spraying Finding", "Recorded.",
        "substantiated", "high", "analyst", "2026-08-21T09:00:00Z",
        "2026-08-21T10:00:00Z", decision_ids=("DECISION-001",),
        attack_tactics=("Credential Access",),
        attack_techniques=("T1110.003 - Password Spraying",),
    )


def _repository(tmp_path, count=1):
    repository = InvestigationRepository(tmp_path / "workspace")
    for index in range(1, count + 1):
        investigation_id = f"INV-{index}"
        repository.save(replace(
            build_investigation(investigation_id),
            findings=(_finding(investigation_id, f"FIND-{index}"),),
            handoff_manifest=None,
        ))
    return repository


def test_offline_analyst_findings_are_authoritative_and_immutable(tmp_path):
    summary = AttackActivityService(_repository(tmp_path)).summarize()
    assert summary.mode == "offline"
    assert summary.observation_count == 2
    assert summary.machine_observation_count == 0
    assert summary.analyst_observation_count == 2
    assert summary.tactic_count == summary.technique_count == 1
    assert summary.investigations_represented == 1
    assert all(row.attribution == "analyst" for row in summary.recent_observations)
    with pytest.raises(FrozenInstanceError):
        summary.mode = "full"


def test_full_sources_counts_grouping_and_duplicate_mapping_deduplication(tmp_path):
    summary = AttackActivityService(
        _repository(tmp_path, count=2), _analysis
    ).summarize()
    assert summary.mode == "full"
    assert summary.observation_count == 8
    assert summary.machine_observation_count == 4
    assert summary.analyst_observation_count == 4
    assert summary.tactic_count == 3
    assert summary.technique_count == 3
    assert summary.investigations_represented == 2
    credential = next(row for row in summary.tactics
                      if row.tactic == "Credential Access")
    assert credential.observation_count == 4
    assert credential.machine_observation_count == 2
    assert credential.analyst_observation_count == 2
    password = next(row for row in summary.techniques
                    if row.technique_id == "T1110.003")
    assert password.observation_count == 4
    assert password.alert_count == 1
    assert password.case_count == 1
    assert password.finding_count == 2
    assert password.investigation_ids == ("INV-1", "INV-2")


def test_alert_case_reconstruction_and_finding_attribution(tmp_path):
    summary = AttackActivityService(_repository(tmp_path), _analysis).summarize()
    sources = {(row.source_type, row.attribution)
               for row in summary.recent_observations}
    assert ("alert", "machine") in sources
    assert ("case", "machine") in sources
    assert ("reconstruction", "machine") in sources
    assert ("finding", "analyst") in sources
    assert all(row.source_id for row in summary.recent_observations)


def test_same_technique_across_sources_and_investigations_is_not_merged(tmp_path):
    summary = AttackActivityService(
        _repository(tmp_path, count=2), _analysis
    ).summarize()
    technique = next(row for row in summary.techniques
                     if row.technique_id == "T1110.003")
    assert technique.observation_count == 4
    assert len(technique.source_ids) == 4
    assert technique.investigation_count == 2


def test_explicit_metadata_only_and_no_detection_coverage_leakage(tmp_path):
    analysis = _analysis()
    analysis.alerts[0]["mitre"] = []
    analysis.cases[0]["mitre"] = []
    analysis.reconstructions[0]["attack_path"][0]["tactic"] = None
    analysis.reconstructions[0]["attack_path"][0]["technique"] = None
    summary = AttackActivityService(
        InvestigationRepository(tmp_path / "workspace"), lambda: analysis
    ).summarize()
    assert summary.mode == "full"
    assert summary.observation_count == 0
    assert summary.tactics == summary.techniques == ()


def test_case_strings_are_not_treated_as_explicit_mapping_pairs(tmp_path):
    analysis = _analysis()
    analysis.alerts.clear()
    analysis.reconstructions.clear()
    analysis.cases[0]["mitre"] = ["Credential Access"]
    summary = AttackActivityService(
        InvestigationRepository(tmp_path / "workspace"), lambda: analysis
    ).summarize()
    assert summary.observation_count == 0


def test_technique_name_is_not_invented(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    finding = _finding("INV-1", "FIND-1")
    finding = replace(finding, attack_tactics=(),
                      attack_techniques=("T1110.003",))
    repository.save(replace(build_investigation("INV-1"), findings=(finding,),
                            handoff_manifest=None))
    technique = AttackActivityService(repository).summarize().techniques[0]
    assert technique.technique_id == "T1110.003"
    assert technique.technique_name is None
    assert technique.technique_key == "T1110.003"


def test_deterministic_order_recent_tie_break_and_bound(tmp_path):
    service = AttackActivityService(
        _repository(tmp_path, count=2), _analysis, recent_limit=3
    )
    first = service.summarize()
    assert first == service.summarize()
    assert len(first.recent_observations) == 3
    assert list(first.tactics) == sorted(
        first.tactics, key=lambda row: (-row.observation_count,
                                        row.tactic.casefold())
    )
    assert [row.timestamp or "" for row in first.recent_observations] == sorted(
        (row.timestamp or "" for row in first.recent_observations), reverse=True
    )


def test_missing_timestamp_is_safe(tmp_path):
    analysis = _analysis()
    analysis.alerts[0]["timestamp"] = ""
    summary = AttackActivityService(
        InvestigationRepository(tmp_path / "workspace"), lambda: analysis
    ).summarize()
    assert any(row.timestamp is None for row in summary.recent_observations)


def test_projection_does_not_mutate_repository_or_analysis(tmp_path):
    repository = _repository(tmp_path)
    analysis = _analysis()
    before_analysis = deepcopy(analysis)
    path = repository.investigations_root / "INV-1.json"
    before_bytes = path.read_bytes()
    assert AttackActivityService(repository, lambda: analysis).summarize()
    assert path.read_bytes() == before_bytes
    assert repository.load_record("INV-1").revision == 1
    assert analysis == before_analysis


def test_empty_and_partial_full_state_are_honest(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    offline = AttackActivityService(repository).summarize()
    full = AttackActivityService(repository, lambda: _analysis()).summarize()
    assert offline.mode == "offline" and offline.observation_count == 0
    assert full.mode == "full" and full.machine_observation_count == 4


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_terminal_views_are_width_safe_and_no_color(tmp_path, width, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    summary = AttackActivityService(_repository(tmp_path), _analysis).summarize()
    views = (
        render_attack_activity_menu(width=width),
        render_attack_activity_summary(summary, width=width),
        render_tactics(summary, width=width),
        render_techniques(summary, width=width),
        render_technique_detail(summary.techniques[0], width=width),
        render_recent(summary, width=width),
    )
    for rendered in views:
        assert strip_ansi(rendered) == rendered
        assert all(len(line) <= resolve_terminal_width(width)
                   for line in rendered.splitlines())
    if width >= 80:
        joined = "\n".join(views)
        assert "ATT&CK ACTIVITY STATE" in joined
        assert "[MACHINE]" in joined and "[ANALYST]" in joined
        assert "do not establish" in joined
        assert "not Detection Coverage" in joined


def test_terminal_empty_state():
    summary = AttackActivityService(
        InvestigationRepository(Path("/tmp/no-attack-activity"))
    ).summarize()
    rendered = render_attack_activity_summary(summary, ansi=False)
    assert "No explicit observed tactics." in rendered
    assert "No explicit observed techniques." in rendered
    assert "[OFFLINE]" in rendered


def test_controller_all_real_views_and_back(tmp_path):
    summary_service = AttackActivityService(_repository(tmp_path), _analysis)
    inputs = iter((
        "1", "", "2", "", "3", "1", "", "4", "", "0",
    ))
    output = []
    AttackActivityConsoleController(
        summary_service, input_func=lambda _prompt="": next(inputs),
        output_func=output.append,
    ).run()
    joined = "\n".join(output)
    assert "ATT&CK ACTIVITY STATE" in joined
    assert "ACTIVITY BY TACTIC" in joined
    assert "ACTIVITY BY TECHNIQUE" in joined
    assert "TECHNIQUE ACTIVITY" in joined
    assert "RECENT ATT&CK OBSERVATIONS" in joined


def test_analysis_option_three_dispatches_real_controller(monkeypatch):
    from soc_forge.menus import analysis
    calls = []
    choices = iter(("3", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("attack")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analysis, "begin_screen", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_group", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_option", lambda *_args: None)
    analysis.analysis_menu(
        lambda: None, lambda: None, lambda: None, None, None, controller
    )
    assert calls == ["attack"]
