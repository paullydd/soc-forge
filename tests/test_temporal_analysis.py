from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from soc_forge.investigations.models import (
    InvestigationFinding, ResponseAction, ResponseActionTransition,
)
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.menus.temporal_analysis import (
    CAUTION, TemporalAnalysisConsoleController, render_temporal,
    render_temporal_menu,
)
from soc_forge.pipeline import AnalysisResult
from soc_forge.temporal_analysis import TemporalAnalysisService
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_investigation_repository import build_investigation


def analysis():
    event = {"event_id": "EVT-1", "timestamp": "2026-08-21T09:00:00Z",
             "message": "Event"}
    alert = {"alert_id": "ALERT-1", "timestamp": "2026-08-21T10:00:00Z",
             "title": "Alert", "mitre": [{"tactic": "Discovery",
             "technique_id": "T1087", "technique": "Account Discovery"}]}
    case = {"case_id": "CASE-1", "created_at": "2026-08-21T11:00:00Z",
            "title": "Case", "mitre": []}
    recon = {"case_id": "CASE-1", "attack_path": [{
        "timestamp": "2026-08-21T12:00:00Z", "title": "Step",
        "tactic": "Discovery", "technique": "T1087 - Account Discovery",
    }]}
    return AnalysisResult(
        "events.jsonl", None, Path("out"), None, None, None, None, None,
        None, 1, [event], [alert], [], [alert], {}, [], {}, [case], [recon],
        [], {}, [], 1,
    )


def repository(tmp_path, order=("INV-1", "INV-2")):
    repo = InvestigationRepository(tmp_path / "workspace")
    for inv_id in order:
        index = int(inv_id.rsplit("-", 1)[-1]) - 1
        base = build_investigation(inv_id)
        ref = replace(
            base.evidence_references[0], origin="analyst_selection",
            classification="supporting", rationale="Selected.",
            selected_by="analyst",
            selected_at=f"2026-08-21T0{index + 1}:00:00Z",
            source_analysis_id=base.analysis_id, evidence_type="alert",
        )
        hypothesis = replace(
            base.hypotheses[0],
            supporting_evidence_reference_ids=(ref.reference_id,),
            created_at=f"2026-08-21T0{index + 2}:00:00Z",
        )
        decision = replace(
            base.decisions[0], evidence_reference_ids=(ref.reference_id,),
            hypothesis_ids=(hypothesis.hypothesis_id,),
            decided_at=f"2026-08-21T0{index + 3}:00:00Z",
        )
        finding = InvestigationFinding(
            f"FIND-{index + 1}", inv_id, "Finding", "Conclusion",
            "substantiated", "high", "analyst",
            f"2026-08-21T0{index + 4}:00:00Z",
            f"2026-08-21T0{index + 4}:00:00Z",
            decision_ids=(decision.decision_id,),
            attack_tactics=("Discovery",),
            attack_techniques=("T1087 - Account Discovery",),
        )
        transitions = (
            ResponseActionTransition("TRANS-1", "proposed", "approved",
                "analyst", "Approved.", "2026-08-21T05:00:00Z"),
            ResponseActionTransition("TRANS-2", "approved", "in_progress",
                "analyst", "Started.", "2026-08-21T06:00:00Z"),
            ResponseActionTransition("TRANS-3", "in_progress", "completed",
                "analyst", "Completed.", "2026-08-21T07:00:00Z"),
        )
        action = ResponseAction(
            f"ACT-{index + 1}", inv_id, (finding.finding_id,), "Action",
            "Description", "containment", "high", "completed", "Rationale",
            "owner", "analyst", "2026-08-21T04:30:00Z",
            "2026-08-21T07:00:00Z", transitions,
        )
        repo.save(replace(
            base, evidence_references=(ref,), hypotheses=(hypothesis,),
            decisions=(decision,), findings=(finding,),
            response_actions=(action,), handoff_manifest=None,
        ))
    return repo


def test_offline_projects_authoritative_analyst_sources_and_lifecycle(tmp_path):
    result = TemporalAnalysisService(repository(tmp_path, ("INV-1",))).analyze()
    assert result.mode == "offline"
    assert result.machine_entry_count == 0
    assert {row.source_type for row in result.entries} == {
        "evidence", "hypothesis", "decision", "finding", "response_action"
    }
    actions = [row for row in result.entries if row.source_type == "response_action"]
    assert [row.title.split()[-1] for row in actions] == [
        "proposed", "approved", "in_progress", "completed"
    ]
    assert len({row.entry_id for row in actions}) == 4


def test_full_machine_alert_event_case_and_reconstruction_attribution(tmp_path):
    result = TemporalAnalysisService(
        repository(tmp_path, ("INV-1",)), analysis
    ).analyze()
    assert result.mode == "full"
    assert {row.source_type for row in result.entries
            if row.attribution == "machine"} == {
                "event", "alert", "case", "reconstruction"
            }
    assert result.machine_entry_count == 4
    assert all(row.entry_id.startswith("TEMP:") for row in result.entries)


def test_ordering_ties_determinism_and_repository_insertion_independence(tmp_path):
    left = TemporalAnalysisService(repository(tmp_path / "a")).analyze()
    right = TemporalAnalysisService(
        repository(tmp_path / "b", ("INV-2", "INV-1"))
    ).analyze()
    assert [row.timestamp for row in left.entries] == sorted(
        row.timestamp for row in left.entries
    )
    assert left == TemporalAnalysisService(
        repository(tmp_path / "c")
    ).analyze()
    assert [(r.timestamp, r.entry_id) for r in left.entries] == [
        (r.timestamp, r.entry_id) for r in right.entries
    ]


def test_untimed_is_separate_and_recent_is_exact_reverse(tmp_path):
    repo = repository(tmp_path, ("INV-1",))
    inv = repo.load("INV-1")
    repo.save(replace(
        inv, hypotheses=(replace(inv.hypotheses[0], created_at=None),)
    ), expected_revision=1)
    service = TemporalAnalysisService(repo, recent_limit=3)
    result = service.analyze()
    assert result.untimed_entry_count == 1
    assert result.untimed_entries[0].source_type == "hypothesis"
    assert service.recent(result) == tuple(reversed(result.entries[-3:]))


@pytest.mark.parametrize(("kwargs", "expected"), (
    ({"investigation_id": "INV-1"}, {"INV-1"}),
    ({"source_type": "finding"}, {"finding"}),
    ({"tactic": "discovery"}, {"finding"}),
    ({"technique_id": "t1087"}, {"finding"}),
))
def test_filters_preserve_chronology(tmp_path, kwargs, expected):
    result = TemporalAnalysisService(repository(tmp_path)).analyze(**kwargs)
    assert list(result.entries) == sorted(
        result.entries, key=TemporalAnalysisService._order_key
    )
    values = ({row.investigation_id for row in result.entries}
              if "investigation_id" in kwargs
              else {row.source_type for row in result.entries})
    assert values == expected


def test_empty_filter_and_no_fabricated_machine_state(tmp_path):
    result = TemporalAnalysisService(repository(tmp_path)).analyze(
        source_type="alert"
    )
    assert result.mode == "offline"
    assert result.entries == ()
    assert result.machine_entry_count == 0


def test_projection_is_immutable_and_does_not_mutate_repository_or_analysis(tmp_path):
    repo = repository(tmp_path, ("INV-1",))
    current = analysis()
    before_analysis = deepcopy(current)
    path = repo.investigations_root / "INV-1.json"
    before = path.read_bytes()
    result = TemporalAnalysisService(repo, lambda: current).analyze()
    with pytest.raises(FrozenInstanceError):
        result.mode = "offline"
    assert path.read_bytes() == before
    assert repo.load_record("INV-1").revision == 1
    assert current == before_analysis


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_terminal_width_color_ascii_dumb_caution_and_untimed(
    tmp_path, width, monkeypatch
):
    repo = repository(tmp_path, ("INV-1",))
    inv = repo.load("INV-1")
    repo.save(replace(inv, hypotheses=(
        replace(inv.hypotheses[0], created_at=None),
    )), expected_revision=1)
    result = TemporalAnalysisService(repo, analysis).analyze()
    monkeypatch.setenv("NO_COLOR", "1")
    views = (render_temporal_menu(width=width),
             render_temporal(result, width=width),
             render_temporal(result, recent=True, width=width),
             render_temporal(result, width=width, unicode=False, ansi=False))
    for rendered in views:
        assert strip_ansi(rendered) == rendered
        assert all(len(line) <= resolve_terminal_width(width)
                   for line in rendered.splitlines())
    monkeypatch.setenv("TERM", "dumb")
    assert strip_ansi(render_temporal(result, width=width)) == render_temporal(
        result, width=width
    )
    if width >= 80:
        joined = "\n".join(views)
        assert "TEMPORAL STATE" in joined and "UNTIMED ACTIVITY" in joined
        assert "[MACHINE]" in joined and "[ANALYST]" in joined
        assert "Temporal proximity across Investigations" in joined
        assert "campaign, or causal relationship." in joined


def test_controller_views_filters_and_back(tmp_path):
    inputs = iter(("1", "", "2", "", "3", "INV-1", "", "4", "finding", "",
                   "5", "technique", "T1087", "", "0"))
    output = []
    TemporalAnalysisConsoleController(
        TemporalAnalysisService(repository(tmp_path), analysis),
        input_func=lambda _prompt="": next(inputs), output_func=output.append,
    ).run()
    joined = "\n".join(output)
    assert "CHRONOLOGICAL ACTIVITY" in joined
    assert "RECENT ACTIVITY" in joined
    assert "filtered to INV-1" in joined
    assert "Source type: finding" in joined
    assert "ATT&CK technique: T1087" in joined


def test_analysis_option_five_dispatches_controller(monkeypatch):
    from soc_forge.menus import analysis as menu
    calls = []
    choices = iter(("5", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("temporal")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(menu, "begin_screen", lambda _title: None)
    monkeypatch.setattr(menu, "menu_group", lambda _title: None)
    monkeypatch.setattr(menu, "menu_option", lambda *_args: None)
    menu.analysis_menu(
        lambda: None,
        None, None, None, None, controller,
    )
    assert calls == ["temporal"]
