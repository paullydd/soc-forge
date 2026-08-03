import ast
from copy import deepcopy
from pathlib import Path

import pytest

from soc_forge.investigations.models import EvidenceReference
from soc_forge.investigations.reasoning_console import (
    GENERAL_DECISION_TYPES,
    ReasoningConsoleController,
)
from soc_forge.investigations.reasoning_service import InvestigationReasoningService
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


class ScriptedInput:
    def __init__(self, values=()):
        self.values = iter(values)

    def __call__(self, _prompt=""):
        return next(self.values)


class Clock:
    def __init__(self):
        self.minute = 0

    def __call__(self):
        value = f"2026-08-11T12:{self.minute:02d}:00Z"
        self.minute += 1
        return value


def selected(reference_id, classification, evidence_type="alert"):
    return EvidenceReference(
        reference_id=reference_id,
        source_type=evidence_type,
        source_id=reference_id.replace("EVIDENCE", "SOURCE"),
        origin="analyst_selection",
        classification=classification,
        rationale=f"{classification} analyst rationale",
        selected_by="alice",
        selected_at="2026-08-11T11:00:00Z",
        selection_updated_at="2026-08-11T11:00:00Z",
        source_analysis_id="ANALYSIS-001",
        evidence_type=evidence_type,
        scope_case_ids=("CASE-001",),
    )


def build_controller(tmp_path, inputs=()):
    clock = Clock()
    workspace = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace"),
        clock=clock,
    )
    created = workspace.create_investigation(
        investigation_id="INV-001",
        title="Reasoning workspace",
        analysis_id="ANALYSIS-001",
        case_ids=("CASE-001",),
        artifact_keys=("alerts", "cases"),
    )
    prepared = workspace.replace_evidence_references(
        "INV-001",
        created.investigation.evidence_references
        + (
            selected("EVIDENCE-SUPPORT", "supporting"),
            selected("EVIDENCE-CONTRADICT", "contradicting", "event"),
            selected("EVIDENCE-CONTEXT", "context"),
        ),
        expected_revision=created.revision,
    )
    reasoning = InvestigationReasoningService(workspace, clock=clock)
    messages = []
    controller = ReasoningConsoleController(
        reasoning_service=reasoning,
        input_func=ScriptedInput(inputs),
        output_func=messages.append,
        screen_func=lambda _title: None,
    )
    return controller, reasoning, workspace, prepared, messages


def create_hypothesis(reasoning, current, hypothesis_id="HYP-001"):
    return reasoning.create_hypothesis(
        "INV-001",
        hypothesis_id=hypothesis_id,
        statement="PowerShell activity was used to impair defenses",
        author="alice",
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
        contradicting_evidence_ids=("EVIDENCE-CONTRADICT",),
        expected_revision=current.revision,
    )


def test_reasoning_menu_back_and_empty_summary(tmp_path):
    controller, _, _, current, messages = build_controller(tmp_path, ["1", "0"])

    assert controller.run(current) == current

    output = "\n".join(messages)
    assert "[1] View reasoning summary" in output
    assert "[6] Record investigation decision" in output
    assert "Total hypotheses: 0" in output
    assert "Total decisions: 0" in output
    assert "not machine certainty" in output
    assert "Authoritative revision:" in output


def test_workspace_counts_use_service_summary_and_keep_status_out(tmp_path):
    controller, reasoning, _, current, messages = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current)

    controller.render_workspace_counts(current)

    assert messages == [
        "Hypotheses: 1",
        "Open: 1",
        "Supported: 0",
        "Rejected: 0",
        "Inconclusive: 0",
        "Reasoning decisions: 0",
    ]


def test_create_hypothesis_filters_evidence_and_refreshes_revision(tmp_path):
    controller, _, workspace, current, messages = build_controller(
        tmp_path,
        [
            "HYP-001",
            "Credential access followed defense evasion",
            "alice",
            "1",
            "1",
            "y",
        ],
    )

    updated = controller.create_hypothesis(current)
    hypothesis = updated.investigation.hypotheses[0]

    assert updated.revision == current.revision + 1
    assert hypothesis.state == "open"
    assert hypothesis.supporting_evidence_reference_ids == ("EVIDENCE-SUPPORT",)
    assert hypothesis.contradicting_evidence_reference_ids == (
        "EVIDENCE-CONTRADICT",
    )
    assert "EVIDENCE-CONTEXT" not in "\n".join(messages)
    assert "CASE-001" not in "\n".join(messages)
    assert workspace.get_investigation("INV-001") == updated


def test_cancel_and_invalid_create_do_not_change_workspace(tmp_path):
    controller, _, workspace, current, messages = build_controller(tmp_path, [""])
    assert controller.create_hypothesis(current) == current
    assert workspace.get_investigation("INV-001") == current

    controller.input = ScriptedInput(["HYP-001", "", "alice", "", "", "y"])
    assert controller.create_hypothesis(current) == current
    assert workspace.get_investigation("INV-001") == current
    assert any("Reasoning update failed" in item for item in messages)


def test_list_and_detail_are_deterministic_and_use_persisted_metadata(tmp_path):
    controller, reasoning, _, current, messages = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current, "HYP-B")
    current = reasoning.create_hypothesis(
        "INV-001",
        hypothesis_id="HYP-A",
        statement="Earlier deterministic hypothesis",
        author="bob",
        expected_revision=current.revision,
    )

    listed = controller.list_hypotheses(current)
    controller._render_hypothesis(current, listed[1])

    assert [item.hypothesis_id for item in listed] == ["HYP-A", "HYP-B"]
    output = "\n".join(messages)
    assert "State: OPEN" in output
    assert "EVIDENCE-SUPPORT | alert | supporting" in output
    assert "supporting analyst rationale" in output
    assert "SOURCE-SUPPORT" in output


def test_edit_and_relationship_changes_preserve_domain_behavior(tmp_path):
    controller, reasoning, _, current, _ = build_controller(tmp_path)
    current = reasoning.create_hypothesis(
        "INV-001",
        hypothesis_id="HYP-001",
        statement="Initial statement",
        author="alice",
        expected_revision=current.revision,
    )
    before = current.investigation.hypotheses[0]

    controller.input = ScriptedInput(["Updated statement", "bob", "y"])
    current = controller.edit_statement(current, before)
    edited = current.investigation.hypotheses[0]
    assert edited.created_at == before.created_at
    assert edited.statement == "Updated statement"

    controller.input = ScriptedInput(["1"])
    current = controller.add_evidence(current, edited, "supporting")
    attached = current.investigation.hypotheses[0]
    assert attached.state == "open"
    assert attached.supporting_evidence_reference_ids == ("EVIDENCE-SUPPORT",)

    controller.input = ScriptedInput(["1", "y"])
    current = controller.remove_evidence(current, attached, "supporting")
    assert current.investigation.hypotheses[0].state == "open"
    assert current.investigation.hypotheses[0].supporting_evidence_reference_ids == ()
    assert any(
        item.reference_id == "EVIDENCE-SUPPORT"
        for item in current.investigation.evidence_references
    )


@pytest.mark.parametrize(
    ("choice", "state"),
    [("1", "supported"), ("2", "rejected"), ("3", "inconclusive")],
)
def test_assess_creates_append_only_decision_without_status_change(
    tmp_path, choice, state
):
    controller, reasoning, _, current, _ = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current)
    original_status = current.investigation.metadata.status
    controller.input = ScriptedInput(
        [choice, "Current evidence supports this assessment", "alice", "DEC-001", "y"]
    )

    updated = controller.assess_hypothesis(
        current, current.investigation.hypotheses[0]
    )

    assert updated.investigation.hypotheses[0].state == state
    assert updated.investigation.metadata.status == original_status
    decision = updated.investigation.decisions[0]
    assert decision.decision_type == "hypothesis_assessment"
    assert decision.outcome == state
    assert decision.hypothesis_ids == ("HYP-001",)
    assert decision.evidence_reference_ids == (
        "EVIDENCE-CONTRADICT",
        "EVIDENCE-SUPPORT",
    )


def test_reopen_preserves_evidence_and_assessment_history(tmp_path):
    controller, reasoning, _, current, messages = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current)
    current = reasoning.assess_hypothesis(
        "INV-001",
        "HYP-001",
        state="inconclusive",
        rationale="Mixed evidence",
        author="alice",
        decision_id="DEC-ASSESS",
        expected_revision=current.revision,
    )
    controller.input = ScriptedInput(
        ["New evidence requires review", "bob", "DEC-REOPEN", "y"]
    )

    reopened = controller.reopen_hypothesis(
        current, current.investigation.hypotheses[0]
    )
    hypothesis = reopened.investigation.hypotheses[0]

    assert hypothesis.state == "open"
    assert hypothesis.supporting_evidence_reference_ids == ("EVIDENCE-SUPPORT",)
    assert hypothesis.contradicting_evidence_reference_ids == (
        "EVIDENCE-CONTRADICT",
    )
    assert [item.outcome for item in reopened.investigation.decisions] == [
        "inconclusive",
        "reopened",
    ]
    controller.view_related_decisions(reopened, "HYP-001")
    assert "Decision ID: DEC-ASSESS" in messages
    assert "Decision ID: DEC-REOPEN" in messages


@pytest.mark.parametrize("choice,decision_type", list(enumerate(GENERAL_DECISION_TYPES, 1)))
def test_general_decision_types_are_append_only_and_do_not_change_status(
    tmp_path, choice, decision_type
):
    controller, reasoning, _, current, _ = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current)
    before_status = current.investigation.metadata.status
    controller.input = ScriptedInput(
        [
            "DEC-GENERAL",
            str(choice),
            "recommended",
            "Analyst rationale",
            "alice",
            "1",
            "1",
            "y",
        ]
    )

    updated = controller.record_decision(current)
    decision = updated.investigation.decisions[0]

    assert decision.decision_type == decision_type
    assert decision.decision_type != "hypothesis_assessment"
    assert decision.hypothesis_ids == ("HYP-001",)
    assert decision.evidence_reference_ids == ("EVIDENCE-CONTEXT",)
    assert updated.investigation.metadata.status == before_status


def test_decisions_are_read_only_and_render_without_active_analysis(tmp_path):
    controller, reasoning, _, current, messages = build_controller(tmp_path)
    current = create_hypothesis(reasoning, current)
    current = reasoning.assess_hypothesis(
        "INV-001",
        "HYP-001",
        state="supported",
        rationale="Persisted assessment rationale",
        author="alice",
        decision_id="DEC-001",
        expected_revision=current.revision,
    )
    controller.input = ScriptedInput([""])
    controller.view_decisions(current)

    output = "\n".join(messages)
    assert "DEC-001 | hypothesis_assessment" in output
    assert "Persisted assessment rationale" in output
    assert "edit decision" not in output.lower()
    assert "delete decision" not in output.lower()


def test_stale_revision_reloads_and_preserves_drafted_rationale(tmp_path):
    controller, reasoning, workspace, stale, messages = build_controller(tmp_path)
    stale = create_hypothesis(reasoning, stale)
    workspace.assign_owner("INV-001", "other-session", expected_revision=stale.revision)
    controller.input = ScriptedInput(
        ["1", "Drafted assessment rationale", "alice", "DEC-001", "y"]
    )

    reloaded = controller.assess_hypothesis(
        stale, stale.investigation.hypotheses[0]
    )

    assert reloaded.revision == stale.revision + 1
    assert reloaded.investigation.hypotheses[0].state == "open"
    output = "\n".join(messages)
    assert "No retry or merge was attempted" in output
    assert "Drafted assessment rationale" in output
    assert f"Authoritative revision: {reloaded.revision}" in output


def test_controller_does_not_mutate_analysis_or_write_repository_directly(tmp_path):
    controller, reasoning, _, current, _ = build_controller(tmp_path)
    source_analysis = {"alerts": [{"alert_id": "A-1"}]}
    before = deepcopy(source_analysis)

    current = create_hypothesis(reasoning, current)
    controller.render_summary(current)

    assert source_analysis == before
    assert not hasattr(controller, "repository")
def test_console_boundary_has_no_domain_construction_or_file_writes():
    source = Path("soc_forge/investigations/reasoning_console.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert calls.isdisjoint({"Hypothesis", "Decision", "EvidenceReference", "open"})
    assert "InvestigationRepository," not in source
    assert "AnalysisResult" not in source
