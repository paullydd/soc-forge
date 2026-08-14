from copy import deepcopy
from pathlib import Path

import pytest

from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.evidence_console import EvidenceConsoleController
from soc_forge.investigations.evidence_service import InvestigationEvidenceService
from soc_forge.investigations.models import Decision, Hypothesis
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.ui.terminal import strip_ansi
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.pipeline import AnalysisResult


class ScriptedInput:
    def __init__(self, values=()):
        self.values = iter(values)

    def __call__(self, _prompt=""):
        return next(self.values)


def build_analysis(tmp_path, *, case_id="CASE-001", suffix=""):
    event = {
        "record_id": f"EVENT-001{suffix}",
        "event_id": 4688,
        "timestamp": "2026-08-06T10:00:00Z",
        "host": "WS-LAB-01",
        "username": "alice",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc very-sensitive-command",
        "message": "raw sensitive source message",
    }
    alert = {
        "alert_id": f"ALERT-001{suffix}",
        "rule_id": "SOCF-021",
        "severity": "high",
        "title": "Security control tampering",
        "timestamp": "2026-08-06T10:00:00Z",
        "source_event_id": event["record_id"],
        "details": {
            "host": "WS-LAB-01",
            "username": "alice",
            "command_line": event["command_line"],
        },
        "mitre": [{"id": "T1562.001", "tactic": "Defense Evasion"}],
    }
    case = {
        "case_id": case_id,
        "title": "Security control investigation",
        "timestamp": "2026-08-06T10:00:00Z",
        "items": [deepcopy(alert)],
    }
    reconstruction = {
        "case_id": case_id,
        "attack_path": [{
            "step_no": 1,
            "stage": "Defense Evasion",
            "title": "Disable security controls",
            "tactic": "Defense Evasion",
            "technique": "Impair Defenses",
            "timestamp": "2026-08-06T10:00:00Z",
            "entities": {"host": "WS-LAB-01"},
        }],
    }
    artifacts = {
        "cases": tmp_path / "cases.json",
        "alerts": tmp_path / "alerts.json",
        "events": tmp_path / "events.jsonl",
        "reconstructions": tmp_path / "reconstructions.json",
    }
    return AnalysisResult(
        input_name=f"evidence{suffix}.jsonl",
        input_path=tmp_path / f"evidence{suffix}.jsonl",
        output_dir=tmp_path,
        alerts_path=artifacts["alerts"],
        report_path=None,
        cases_output_dir=tmp_path,
        hunts_path=None,
        reconstructions_path=artifacts["reconstructions"],
        events_path=artifacts["events"],
        event_count=1,
        events=[event],
        alerts=[alert],
        legacy_alerts=[],
        yaml_alerts=[alert],
        correlations={"total": 0, "by_rule": []},
        hunt_findings=[],
        risk_summary={"level": "high"},
        cases=[case],
        reconstructions=[reconstruction],
        mitre_coverage=[],
        artifacts=artifacts,
        ingest_diagnostics=[],
    )


def build_controller(tmp_path, *, inputs=(), analysis_marker=True):
    analysis = build_analysis(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    repository = InvestigationRepository(tmp_path / "workspace")
    workspace = InvestigationWorkspaceService(
        repository, clock=lambda: "2026-08-06T12:01:00Z"
    )
    created = workspace.create_investigation(
        investigation_id="INV-001",
        title="Evidence investigation",
        analysis_id=catalog.source_analysis_id(analysis),
        case_ids=("CASE-001",),
        artifact_keys=("alerts", "cases", "events", "reconstructions"),
        created_at="2026-08-06T11:59:00Z",
    )
    evidence_service = InvestigationEvidenceService(
        workspace, clock=lambda: "2026-08-06T12:00:00Z"
    )
    messages = []
    active = analysis if analysis_marker is True else analysis_marker
    controller = EvidenceConsoleController(
        catalog=catalog,
        evidence_service=evidence_service,
        analysis_provider=lambda: active,
        input_func=ScriptedInput(inputs),
        output_func=messages.append,
        screen_func=lambda _title: None,
    )
    return controller, analysis, catalog, evidence_service, workspace, created, messages


def candidate(catalog, analysis, evidence_type):
    return next(
        item for item in catalog.list_candidates(
            analysis, case_ids=("CASE-001",), evidence_types=(evidence_type,)
        )
    )


def select(controller, current, item, classification="supporting", rationale="Reason"):
    choice = {"supporting": "1", "contradicting": "2", "context": "3"}[classification]
    controller.input = ScriptedInput([choice, rationale, "alice", "y"])
    return controller.select_candidate(current, item)


def test_menu_navigation_and_counts_separate_scope_from_selections(tmp_path):
    controller, analysis, catalog, _, _, current, messages = build_controller(tmp_path)
    current = select(controller, current, candidate(catalog, analysis, "alert"))
    controller.input = ScriptedInput(["0"])
    assert controller.run(current) == current
    rendered = strip_ansi("\n".join(messages))
    assert "Scope references" in rendered and "1" in rendered
    assert "Selected evidence" in rendered and "1" in rendered
    assert "Supporting" in rendered and "1" in rendered
    assert "[1] Browse Evidence Candidates" in rendered
    assert "[5] Remove Selected Evidence" in rendered


@pytest.mark.parametrize(
    ("choice", "evidence_type"),
    [("2", "event"), ("3", "alert"), ("4", "case"), ("5", "reconstruction_step")],
)
def test_browse_filters_use_catalog_and_preserve_deterministic_order(
    tmp_path, choice, evidence_type
):
    controller, analysis, catalog, _, _, current, messages = build_controller(
        tmp_path, inputs=[choice, ""]
    )
    assert controller.browse(current) == current
    rendered = strip_ansi("\n".join(messages))
    expected = catalog.list_candidates(
        analysis,
        case_ids=("CASE-001",),
        evidence_types=(evidence_type,),
    )[0]
    assert expected.evidence_id in rendered
    assert evidence_type in rendered


def test_all_candidates_are_ordered_and_lists_hide_raw_sensitive_values(tmp_path):
    controller, analysis, catalog, _, _, current, messages = build_controller(
        tmp_path, inputs=["1", ""]
    )
    before = deepcopy(analysis)
    controller.browse(current)
    rendered = strip_ansi("\n".join(messages))
    expected = catalog.list_candidates(analysis, case_ids=("CASE-001",))
    positions = [rendered.index(item.evidence_id) for item in expected]
    assert positions == sorted(positions)
    assert "very-sensitive-command" not in rendered
    assert "raw sensitive source message" not in rendered
    assert "SENSITIVE" in rendered
    assert analysis == before


def test_empty_filter_and_no_active_analysis_are_clear(tmp_path):
    controller, _, catalog, _, _, current, messages = build_controller(
        tmp_path, analysis_marker=None
    )
    assert controller.browse(current) == current
    assert any("No active analysis" in line for line in messages)

    matching, analysis, _, _, _, current, messages = build_controller(
        tmp_path / "empty", inputs=["2"]
    )
    matching.catalog.list_candidates = lambda *_args, **_kwargs: ()
    assert matching.browse(current) == current
    assert "No evidence candidates match this filter." in messages


def test_provenance_mismatch_blocks_discovery(tmp_path):
    other = build_analysis(tmp_path / "other", suffix="-OTHER")
    controller, _, _, _, _, current, messages = build_controller(
        tmp_path, analysis_marker=other
    )
    assert controller.browse(current) == current
    assert any("does not match" in line for line in messages)


def test_detail_displays_provenance_and_requires_sensitive_confirmation(tmp_path):
    controller, analysis, catalog, _, _, _, messages = build_controller(
        tmp_path, inputs=["n"]
    )
    item = candidate(catalog, analysis, "event")
    controller.show_candidate_details(analysis, item)
    output = "\n".join(messages)
    assert "Field: command_line" in output
    assert "Source field: command_line" in output
    assert "Interpretation layer: normalized_event" in output
    assert "Normalized: yes" in output
    assert "Sensitive: yes" in output
    assert "[hidden - confirmation required]" in output
    assert "very-sensitive-command" not in output

    messages.clear()
    controller.input = ScriptedInput(["y"])
    controller.show_candidate_details(analysis, item)
    assert "very-sensitive-command" in "\n".join(messages)


@pytest.mark.parametrize("classification", ["supporting", "contradicting", "context"])
def test_select_classifications_refresh_revision_and_persist(
    tmp_path, classification
):
    controller, analysis, catalog, _, workspace, current, _ = build_controller(tmp_path)
    updated = select(
        controller,
        current,
        candidate(catalog, analysis, "alert"),
        classification,
    )
    selected = updated.investigation.evidence_references[1]
    assert updated.revision == current.revision + 1
    assert selected.classification == classification
    assert selected.rationale == "Reason"
    assert selected.selected_by == "alice"
    assert workspace.get_investigation("INV-001") == updated


def test_blank_duplicate_and_cancelled_selection_do_not_change_revision(tmp_path):
    controller, analysis, catalog, _, workspace, current, messages = build_controller(tmp_path)
    item = candidate(catalog, analysis, "alert")
    controller.input = ScriptedInput(["1", "", "alice", "y"])
    assert controller.select_candidate(current, item) == current
    assert workspace.get_investigation("INV-001").revision == current.revision

    updated = select(controller, current, item)
    controller.input = ScriptedInput(["1", "Another", "alice", "y"])
    assert controller.select_candidate(updated, item) == updated
    assert workspace.get_investigation("INV-001").revision == updated.revision
    assert any("already selected" in line for line in messages)

    other = candidate(catalog, analysis, "case")
    controller.input = ScriptedInput(["1", "Cancelled", "alice", "n"])
    assert controller.select_candidate(updated, other) == updated


def test_selected_list_and_inspection_with_and_without_active_analysis(tmp_path):
    controller, analysis, catalog, _, _, current, messages = build_controller(tmp_path)
    updated = select(controller, current, candidate(catalog, analysis, "alert"))
    controller.view_selected(updated)
    output = "\n".join(messages)
    assert "Investigation Scope References" in output
    assert "Analyst-Selected Evidence" in output
    plain = strip_ansi(output)
    assert "[SUPPORTING]" in plain
    assert "Analyst" in plain and "alice" in plain

    messages.clear()
    controller.input = ScriptedInput(["1", "n"])
    controller.inspect_selected(updated)
    assert any("Field:" in line for line in messages)

    controller.analysis_provider = lambda: None
    messages.clear()
    controller.input = ScriptedInput(["1"])
    controller.inspect_selected(updated)
    assert any("cannot be resolved" in line for line in messages)
    assert any("Rationale: Reason" in line for line in messages)


def test_selected_evidence_views_pause_before_menu_rerender(tmp_path):
    controller, analysis, catalog, _, _, current, messages = build_controller(tmp_path)
    current = select(controller, current, candidate(catalog, analysis, "alert"))
    pauses = []
    controller.pause = lambda: pauses.append(tuple(messages))
    controller.input = ScriptedInput(["2", "3", "1", "n", "0"])

    returned = controller.run(current)

    assert returned == current
    assert len(pauses) == 2
    assert any("Analyst-Selected Evidence" in line for line in pauses[0])
    assert any("Rationale: Reason" in line for line in pauses[1])
    assert any("Field:" in line for line in pauses[1])
    assert not any("very-sensitive-command" in line for line in pauses[1])

def test_update_preserves_identity_and_selection_time(tmp_path):
    controller, analysis, catalog, _, _, current, _ = build_controller(tmp_path)
    updated = select(controller, current, candidate(catalog, analysis, "alert"))
    original = updated.investigation.evidence_references[1]
    controller.input = ScriptedInput(["1", "context", "Updated reason", "bob", "y"])
    changed = controller.update_selected(updated)
    selected = changed.investigation.evidence_references[1]
    assert changed.revision == updated.revision + 1
    assert selected.reference_id == original.reference_id
    assert selected.selected_at == original.selected_at
    assert selected.classification == "context"
    assert selected.rationale == "Updated reason"
    assert selected.selected_by == "bob"


def test_remove_requires_confirmation_and_never_removes_scope(tmp_path):
    controller, analysis, catalog, _, _, current, messages = build_controller(tmp_path)
    updated = select(controller, current, candidate(catalog, analysis, "alert"))
    controller.input = ScriptedInput(["1", "n"])
    assert controller.remove_selected(updated) == updated
    assert "Evidence removal cancelled." in messages

    controller.input = ScriptedInput(["1", "y"])
    removed = controller.remove_selected(updated)
    assert removed.revision == updated.revision + 1
    assert [item.origin for item in removed.investigation.evidence_references] == ["scope"]


def test_referenced_evidence_removal_fails_without_cascade(tmp_path):
    controller, analysis, catalog, _, workspace, current, messages = build_controller(tmp_path)
    selected = select(controller, current, candidate(catalog, analysis, "alert"))
    evidence_id = selected.investigation.evidence_references[1].reference_id
    related = workspace.record_decision(
        "INV-001",
        decision_id="DEC-1",
        decision_type="disposition",
        outcome="escalate",
        rationale="Relevant",
        author="alice",
        evidence_reference_ids=(evidence_id,),
        expected_revision=selected.revision,
    )
    controller.input = ScriptedInput(["1", "y"])
    assert controller.remove_selected(related) == related
    assert any("decision DEC-1" in line for line in messages)
    assert workspace.get_investigation("INV-001").investigation.decisions


def test_stale_revision_reloads_and_preserves_attempted_rationale(tmp_path):
    controller, analysis, catalog, _, workspace, current, messages = build_controller(tmp_path)
    selected = select(controller, current, candidate(catalog, analysis, "alert"))
    workspace.assign_owner("INV-001", "other", expected_revision=selected.revision)
    controller.input = ScriptedInput(["1", "", "Locally drafted rationale", "", "y"])
    reloaded = controller.update_selected(selected)
    assert reloaded.revision == selected.revision + 1
    assert reloaded.investigation.metadata.owner == "other"
    assert any("Attempted rationale (not saved): Locally drafted rationale" in line for line in messages)


def test_console_uses_catalog_and_service_without_direct_storage_or_id_derivation():
    source = Path(__file__).parents[1] / "soc_forge" / "investigations" / "evidence_console.py"
    text = source.read_text(encoding="utf-8")
    assert "catalog.list_candidates" in text
    assert "catalog.resolve_details" in text
    assert "evidence_service.select_evidence" in text
    assert "evidence_service.update_evidence_rationale" in text
    assert "evidence_service.remove_evidence" in text
    assert "sha256" not in text
    assert "json." not in text
    assert "write_text" not in text
    assert ".events" not in text
    assert ".alerts" not in text
    assert ".cases" not in text
    assert ".reconstructions" not in text


def test_restart_update_remove_preserves_analysis_and_artifact_bytes(tmp_path):
    controller, analysis, catalog, _, _, current, _ = build_controller(tmp_path)
    for key, path in analysis.artifacts.items():
        path.write_bytes(f"immutable-{key}".encode("ascii"))
    original_bytes = {
        key: path.read_bytes() for key, path in analysis.artifacts.items()
    }
    original_collections = deepcopy(
        (analysis.events, analysis.alerts, analysis.cases, analysis.reconstructions)
    )

    selected = select(controller, current, candidate(catalog, analysis, "alert"))
    restarted_workspace = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace"),
        clock=lambda: "2026-08-06T12:02:00Z",
    )
    reopened = restarted_workspace.get_investigation("INV-001")
    assert reopened == selected

    restarted_controller = EvidenceConsoleController(
        catalog=catalog,
        evidence_service=InvestigationEvidenceService(
            restarted_workspace, clock=lambda: "2026-08-06T12:03:00Z"
        ),
        analysis_provider=lambda: analysis,
        input_func=ScriptedInput(["1", "", "Post-restart rationale", "", "y"]),
        output_func=lambda _message: None,
        screen_func=lambda _title: None,
    )
    updated = restarted_controller.update_selected(reopened)
    restarted_controller.input = ScriptedInput(["1", "y"])
    removed = restarted_controller.remove_selected(updated)

    assert removed.revision == selected.revision + 2
    assert restarted_workspace.get_investigation("INV-001") == removed
    assert (
        analysis.events,
        analysis.alerts,
        analysis.cases,
        analysis.reconstructions,
    ) == original_collections
    assert {
        key: path.read_bytes() for key, path in analysis.artifacts.items()
    } == original_bytes
