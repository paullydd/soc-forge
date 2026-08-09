from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from soc_forge.investigations.models import (
    Decision,
    EvidenceReference,
    Investigation,
    MissingInvestigationReferenceError,
)
from soc_forge.investigations.evidence_service import (
    InvalidEvidenceClassificationError as EvidenceSelectionClassificationError,
    InvestigationEvidenceService,
)
from soc_forge.investigations.reasoning_service import (
    DuplicateHypothesisError,
    DuplicateHypothesisEvidenceError,
    DuplicateReasoningDecisionError,
    HypothesisEvidenceNotFoundError,
    HypothesisEvidenceRelationshipNotFoundError,
    AssessedHypothesisNotEditableError,
    InvalidAssessmentRationaleError,
    InvalidDecisionRationaleError,
    InvalidDecisionTypeError,
    InvalidEvidenceClassificationError,
    InvalidHypothesisStatementError,
    InvalidHypothesisTransitionError,
    InvalidReasoningAuthorError,
    InvestigationReasoningService,
    ReasoningReferenceError,
)
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepository,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


TIMES = tuple(f"2026-08-10T12:{minute:02d}:00Z" for minute in range(60))


class Clock:
    def __init__(self):
        self.values = iter(TIMES)

    def __call__(self):
        return next(self.values)


def selected(reference_id, classification):
    return EvidenceReference(
        reference_id=reference_id,
        source_type="alert",
        source_id=reference_id.replace("EVIDENCE", "ALERT"),
        origin="analyst_selection",
        classification=classification,
        rationale="Reviewed source evidence",
        selected_by="Analyst",
        selected_at="2026-08-10T11:00:00Z",
        selection_updated_at="2026-08-10T11:00:00Z",
        source_analysis_id="ANALYSIS-001",
        evidence_type="alert",
        scope_case_ids=("CASE-001",),
    )


def build_services(tmp_path):
    clock = Clock()
    repository = InvestigationRepository(tmp_path / "workspace")
    workspace = InvestigationWorkspaceService(repository, clock=clock)
    created = workspace.create_investigation(
        investigation_id="INVESTIGATION-001",
        title="Reasoning investigation",
        analysis_id="ANALYSIS-001",
        case_ids=("CASE-001",),
        artifact_keys=("alerts", "cases"),
    )
    references = created.investigation.evidence_references + (
        selected("EVIDENCE-SUPPORT", "supporting"),
        selected("EVIDENCE-CONTRADICT", "contradicting"),
        selected("EVIDENCE-CONTEXT", "context"),
    )
    prepared = workspace.replace_evidence_references(
        "INVESTIGATION-001",
        references,
        expected_revision=created.revision,
    )
    reasoning = InvestigationReasoningService(workspace, clock=clock)
    return reasoning, workspace, repository, prepared


def create_hypothesis(reasoning, revision, **overrides):
    values = {
        "investigation_id": "INVESTIGATION-001",
        "hypothesis_id": "HYP-001",
        "statement": "PowerShell activity was used to impair defenses",
        "author": "Analyst",
        "expected_revision": revision,
    }
    values.update(overrides)
    return reasoning.create_hypothesis(**values)


def test_create_open_hypothesis_without_evidence_and_round_trip(tmp_path):
    reasoning, _, repository, prepared = build_services(tmp_path)

    result = create_hypothesis(reasoning, prepared.revision)
    hypothesis = result.investigation.hypotheses[0]

    assert result.revision == prepared.revision + 1
    assert hypothesis.state == "open"
    assert hypothesis.author == "Analyst"
    assert hypothesis.created_at == hypothesis.updated_at
    assert repository.load("INVESTIGATION-001") == result.investigation
    assert Investigation.from_dict(result.investigation.to_dict()) == result.investigation


@pytest.mark.parametrize(
    "supporting,contradicting",
    [
        (("EVIDENCE-SUPPORT",), ()),
        ((), ("EVIDENCE-CONTRADICT",)),
        (("EVIDENCE-SUPPORT",), ("EVIDENCE-CONTRADICT",)),
    ],
)
def test_create_with_classification_compatible_evidence(
    tmp_path, supporting, contradicting
):
    reasoning, _, _, prepared = build_services(tmp_path)

    result = create_hypothesis(
        reasoning,
        prepared.revision,
        supporting_evidence_ids=supporting,
        contradicting_evidence_ids=contradicting,
    )
    hypothesis = result.investigation.hypotheses[0]

    assert hypothesis.supporting_evidence_reference_ids == supporting
    assert hypothesis.contradicting_evidence_reference_ids == contradicting


@pytest.mark.parametrize(
    "decision_type",
    (
        "escalation",
        "containment_recommendation",
        "closure_rationale",
        "investigative_conclusion",
    ),
)
def test_general_decision_accepts_controlled_types(tmp_path, decision_type):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001",
        decision_id=f"DECISION-{decision_type}",
        decision_type=decision_type,
        outcome="recorded",
        rationale="Documented analyst reasoning",
        author="Analyst",
        expected_revision=prepared.revision,
    )
    assert current.investigation.decisions[-1].decision_type == decision_type


def test_general_decision_rejects_assessment_without_persisting(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    before = workspace.get_investigation("INVESTIGATION-001")
    workspace_file = next((tmp_path / "workspace").rglob("*.json"))
    before_bytes = workspace_file.read_bytes()
    with pytest.raises(InvalidDecisionTypeError):
        reasoning.record_investigation_decision(
            "INVESTIGATION-001",
            decision_id="DECISION-ASSESSMENT-BYPASS",
            decision_type="hypothesis_assessment",
            outcome="supported",
            rationale="Must use the assessment workflow",
            author="Analyst",
            expected_revision=prepared.revision,
        )
    after = workspace.get_investigation("INVESTIGATION-001")
    assert after == before
    assert after.revision == prepared.revision
    assert after.investigation.metadata.status == before.investigation.metadata.status
    assert after.investigation.decisions == ()
    assert workspace_file.read_bytes() == before_bytes


@pytest.mark.parametrize("decision_type", ("hypothesis_assessment", "legacy_review"))
def test_persisted_decision_types_remain_read_compatible(decision_type):
    decision = Decision.from_dict({
        "decision_id": "DECISION-LEGACY",
        "decision_type": decision_type,
        "outcome": "recorded",
        "rationale": "Historical rationale",
    })
    assert decision.decision_type == decision_type


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"statement": "  "}, InvalidHypothesisStatementError),
        ({"author": ""}, InvalidReasoningAuthorError),
        (
            {"supporting_evidence_ids": ("EVIDENCE-MISSING",)},
            HypothesisEvidenceNotFoundError,
        ),
        (
            {"supporting_evidence_ids": ("CASE-001",)},
            HypothesisEvidenceNotFoundError,
        ),
        (
            {"supporting_evidence_ids": ("EVIDENCE-CONTEXT",)},
            InvalidEvidenceClassificationError,
        ),
        (
            {"supporting_evidence_ids": ("EVIDENCE-CONTRADICT",)},
            InvalidEvidenceClassificationError,
        ),
        (
            {
                "supporting_evidence_ids": ("EVIDENCE-SUPPORT",),
                "contradicting_evidence_ids": ("EVIDENCE-SUPPORT",),
            },
            InvalidEvidenceClassificationError,
        ),
    ],
)
def test_hypothesis_creation_validation_does_not_save(tmp_path, overrides, error):
    reasoning, workspace, _, prepared = build_services(tmp_path)

    with pytest.raises(error):
        create_hypothesis(reasoning, prepared.revision, **overrides)

    assert workspace.get_investigation("INVESTIGATION-001") == prepared


def test_duplicate_hypothesis_id_fails_without_revision_change(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    created = create_hypothesis(reasoning, prepared.revision)

    with pytest.raises(DuplicateHypothesisError):
        create_hypothesis(reasoning, created.revision)

    assert workspace.get_investigation("INVESTIGATION-001") == created


def test_edit_statement_preserves_state_evidence_and_creation_time(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    created = create_hypothesis(
        reasoning,
        prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )
    before = created.investigation.hypotheses[0]

    updated = reasoning.edit_hypothesis_statement(
        "INVESTIGATION-001",
        "HYP-001",
        statement="PowerShell likely impaired endpoint defenses",
        author="Reviewing Analyst",
        expected_revision=created.revision,
    )
    after = updated.investigation.hypotheses[0]

    assert after.statement != before.statement
    assert after.author == "Reviewing Analyst"
    assert after.created_at == before.created_at
    assert after.state == before.state
    assert after.supporting_evidence_reference_ids == before.supporting_evidence_reference_ids


def test_add_and_remove_each_evidence_relationship_without_state_change(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)

    current = reasoning.add_hypothesis_evidence(
        "INVESTIGATION-001", "HYP-001", "EVIDENCE-SUPPORT",
        relationship="supporting", expected_revision=current.revision,
    )
    current = reasoning.add_hypothesis_evidence(
        "INVESTIGATION-001", "HYP-001", "EVIDENCE-CONTRADICT",
        relationship="contradicting", expected_revision=current.revision,
    )
    hypothesis = current.investigation.hypotheses[0]
    assert hypothesis.state == "open"
    assert hypothesis.supporting_evidence_reference_ids == ("EVIDENCE-SUPPORT",)
    assert hypothesis.contradicting_evidence_reference_ids == (
        "EVIDENCE-CONTRADICT",
    )

    current = reasoning.remove_hypothesis_evidence(
        "INVESTIGATION-001", "HYP-001", "EVIDENCE-SUPPORT",
        relationship="supporting", expected_revision=current.revision,
    )
    current = reasoning.remove_hypothesis_evidence(
        "INVESTIGATION-001", "HYP-001", "EVIDENCE-CONTRADICT",
        relationship="contradicting", expected_revision=current.revision,
    )
    hypothesis = current.investigation.hypotheses[0]
    assert hypothesis.state == "open"
    assert not hypothesis.supporting_evidence_reference_ids
    assert not hypothesis.contradicting_evidence_reference_ids


def test_duplicate_and_missing_relationships_fail_clearly(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning,
        prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )

    with pytest.raises(DuplicateHypothesisEvidenceError):
        reasoning.add_hypothesis_evidence(
            "INVESTIGATION-001", "HYP-001", "EVIDENCE-SUPPORT",
            relationship="supporting", expected_revision=current.revision,
        )
    with pytest.raises(HypothesisEvidenceRelationshipNotFoundError):
        reasoning.remove_hypothesis_evidence(
            "INVESTIGATION-001", "HYP-001", "EVIDENCE-CONTRADICT",
            relationship="contradicting", expected_revision=current.revision,
        )
    assert workspace.get_investigation("INVESTIGATION-001") == current


@pytest.mark.parametrize("state", ["supported", "rejected", "inconclusive"])
def test_terminal_assessment_updates_state_and_appends_linked_decision(tmp_path, state):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning,
        prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
        contradicting_evidence_ids=("EVIDENCE-CONTRADICT",),
    )
    status_before = current.investigation.metadata.status

    assessed = reasoning.assess_hypothesis(
        "INVESTIGATION-001",
        "HYP-001",
        state=state,
        rationale=f"Current evidence is {state}",
        author="Assessing Analyst",
        decision_id=f"DECISION-{state}",
        expected_revision=current.revision,
    )
    hypothesis = assessed.investigation.hypotheses[0]
    decision = assessed.investigation.decisions[0]

    assert hypothesis.state == state
    assert decision.decision_type == "hypothesis_assessment"
    assert decision.outcome == state
    assert decision.hypothesis_ids == ("HYP-001",)
    assert decision.evidence_reference_ids == (
        "EVIDENCE-CONTRADICT",
        "EVIDENCE-SUPPORT",
    )
    assert assessed.investigation.metadata.status == status_before


def test_assessment_transition_rationale_and_idempotency_policy(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)

    with pytest.raises(InvalidAssessmentRationaleError):
        reasoning.assess_hypothesis(
            "INVESTIGATION-001", "HYP-001", state="supported", rationale="",
            author="Analyst", decision_id="DECISION-001",
            expected_revision=current.revision,
        )
    with pytest.raises(InvalidHypothesisTransitionError):
        reasoning.assess_hypothesis(
            "INVESTIGATION-001", "HYP-001", state="open", rationale="ignored",
            author="Analyst", decision_id="DECISION-IGNORED",
            expected_revision=current.revision,
        )
    with pytest.raises(InvalidHypothesisTransitionError):
        reasoning.reopen_hypothesis(
            "INVESTIGATION-001", "HYP-001", rationale="Not applicable",
            author="Analyst", decision_id="DECISION-REOPEN",
            expected_revision=current.revision,
        )
    assert workspace.get_investigation("INVESTIGATION-001") == current



def test_assessed_hypothesis_requires_reopen_before_statement_edit(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)
    assessed = reasoning.assess_hypothesis(
        "INVESTIGATION-001", "HYP-001", state="supported",
        rationale="Supported by selected evidence", author="Analyst",
        decision_id="DECISION-ASSESS", expected_revision=current.revision,
    )
    history = assessed.investigation.decisions

    with pytest.raises(AssessedHypothesisNotEditableError):
        reasoning.edit_hypothesis_statement(
            "INVESTIGATION-001", "HYP-001", statement="Changed after assessment",
            author="Analyst", expected_revision=assessed.revision,
        )
    assert workspace.get_investigation("INVESTIGATION-001") == assessed

    reopened = reasoning.reopen_hypothesis(
        "INVESTIGATION-001", "HYP-001", rationale="New evidence requires review",
        author="Analyst", decision_id="DECISION-REOPEN",
        expected_revision=assessed.revision,
    )
    edited = reasoning.edit_hypothesis_statement(
        "INVESTIGATION-001", "HYP-001", statement="Revised open hypothesis",
        author="Analyst", expected_revision=reopened.revision,
    )
    assert edited.investigation.hypotheses[0].statement == "Revised open hypothesis"
    assert edited.investigation.decisions[:1] == history
    assert edited.investigation.decisions[1].outcome == "reopened"


def test_terminal_reassessment_requires_explicit_reopen_and_preserves_history(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)
    current = reasoning.assess_hypothesis(
        "INVESTIGATION-001", "HYP-001", state="supported",
        rationale="Supported now", author="Analyst", decision_id="DECISION-001",
        expected_revision=current.revision,
    )

    with pytest.raises(InvalidHypothesisTransitionError):
        reasoning.assess_hypothesis(
            "INVESTIGATION-001", "HYP-001", state="rejected",
            rationale="Changed", author="Analyst", decision_id="DECISION-002",
            expected_revision=current.revision,
        )
    reopened = reasoning.reopen_hypothesis(
        "INVESTIGATION-001", "HYP-001", rationale="Review new telemetry",
        author="Analyst", decision_id="DECISION-REOPEN",
        expected_revision=current.revision,
    )

    assert reopened.investigation.hypotheses[0].state == "open"
    assert [item.decision_id for item in reopened.investigation.decisions] == [
        "DECISION-001", "DECISION-REOPEN"
    ]
    assert reopened.investigation.decisions[-1].outcome == "reopened"


def test_reopen_requires_rationale(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)
    current = reasoning.assess_hypothesis(
        "INVESTIGATION-001", "HYP-001", state="rejected",
        rationale="Contradicted", author="Analyst", decision_id="DECISION-001",
        expected_revision=current.revision,
    )
    with pytest.raises(InvalidAssessmentRationaleError):
        reasoning.reopen_hypothesis(
            "INVESTIGATION-001", "HYP-001", rationale="", author="Analyst",
            decision_id="DECISION-002", expected_revision=current.revision,
        )
    assert workspace.get_investigation("INVESTIGATION-001") == current


def test_record_investigation_and_hypothesis_linked_decisions(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001", decision_id="DECISION-001",
        decision_type="escalation", outcome="recommend_escalation",
        rationale="Requires senior review", author="Analyst",
        expected_revision=current.revision,
    )
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001", decision_id="DECISION-002",
        decision_type="investigative_conclusion", outcome="continue_review",
        rationale="Hypothesis needs more evidence", author="Analyst",
        hypothesis_ids=("HYP-001",), evidence_reference_ids=("EVIDENCE-SUPPORT",),
        expected_revision=current.revision,
    )

    assert [item.decision_id for item in current.investigation.decisions] == [
        "DECISION-001", "DECISION-002"
    ]
    assert current.investigation.decisions[-1].hypothesis_ids == ("HYP-001",)


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"decision_type": "automatic_response"}, InvalidDecisionTypeError),
        ({"rationale": ""}, InvalidDecisionRationaleError),
        ({"hypothesis_ids": ("HYP-MISSING",)}, ReasoningReferenceError),
        ({"evidence_reference_ids": ("EVIDENCE-MISSING",)}, ReasoningReferenceError),
    ],
)
def test_decision_validation_does_not_save(tmp_path, overrides, error):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(reasoning, prepared.revision)
    values = {
        "investigation_id": "INVESTIGATION-001",
        "decision_id": "DECISION-001",
        "decision_type": "escalation",
        "outcome": "review",
        "rationale": "Review required",
        "author": "Analyst",
        "expected_revision": current.revision,
    }
    values.update(overrides)

    with pytest.raises(error):
        reasoning.record_investigation_decision(**values)

    assert workspace.get_investigation("INVESTIGATION-001") == current


def test_decision_ids_are_append_only_and_unique(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001", decision_id="DECISION-001",
        decision_type="closure_rationale", outcome="keep_open",
        rationale="More evidence required", author="Analyst",
        expected_revision=prepared.revision,
    )
    with pytest.raises(DuplicateReasoningDecisionError):

        reasoning.record_investigation_decision(
            "INVESTIGATION-001", decision_id="DECISION-001",
            decision_type="closure_rationale", outcome="close",
            rationale="Duplicate", author="Analyst",
            expected_revision=current.revision,
        )
    assert workspace.get_investigation("INVESTIGATION-001") == current


def test_decision_referenced_evidence_cannot_be_removed(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001",
        decision_id="DECISION-001",
        decision_type="investigative_conclusion",
        outcome="retain",
        rationale="Evidence supports retaining the investigation",
        author="Analyst",
        evidence_reference_ids=("EVIDENCE-SUPPORT",),
        expected_revision=prepared.revision,
    )
    references = tuple(
        item for item in current.investigation.evidence_references
        if item.reference_id != "EVIDENCE-SUPPORT"
    )

    with pytest.raises(MissingInvestigationReferenceError):
        workspace.replace_evidence_references(
            "INVESTIGATION-001",
            references,
            expected_revision=current.revision,
        )

    assert workspace.get_investigation("INVESTIGATION-001") == current


def test_referenced_evidence_cannot_be_removed_without_cascade(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning, prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )
    before = current.investigation
    references = tuple(
        item for item in before.evidence_references
        if item.reference_id != "EVIDENCE-SUPPORT"
    )

    with pytest.raises(MissingInvestigationReferenceError):
        workspace.replace_evidence_references(
            "INVESTIGATION-001", references, expected_revision=current.revision
        )

    after = workspace.get_investigation("INVESTIGATION-001")
    assert after.investigation == before
    assert after.revision == current.revision


def test_removing_relationship_then_evidence_is_allowed(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning, prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )
    current = reasoning.remove_hypothesis_evidence(
        "INVESTIGATION-001", "HYP-001", "EVIDENCE-SUPPORT",
        relationship="supporting", expected_revision=current.revision,
    )
    references = tuple(
        item for item in current.investigation.evidence_references
        if item.reference_id != "EVIDENCE-SUPPORT"
    )
    removed = workspace.replace_evidence_references(
        "INVESTIGATION-001", references, expected_revision=current.revision
    )

    assert "EVIDENCE-SUPPORT" not in {
        item.reference_id for item in removed.investigation.evidence_references
    }
    assert removed.investigation.hypotheses[0].state == "open"



def test_selected_evidence_cannot_be_reclassified_against_hypothesis(tmp_path):
    reasoning, workspace, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning,
        prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )
    evidence_service = InvestigationEvidenceService(
        workspace,
        clock=lambda: "2026-08-10T13:00:00Z",
    )

    with pytest.raises(
        EvidenceSelectionClassificationError,
        match="must remain supporting",
    ):
        evidence_service.update_evidence_rationale(
            "INVESTIGATION-001",
            "EVIDENCE-SUPPORT",
            classification="contradicting",
            expected_revision=current.revision,
        )

    assert workspace.get_investigation("INVESTIGATION-001") == current

def test_reasoning_summary_is_deterministic_and_has_no_confidence(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    current = create_hypothesis(
        reasoning, prepared.revision, hypothesis_id="HYP-002"
    )
    current = create_hypothesis(
        reasoning, current.revision, hypothesis_id="HYP-001",
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
        contradicting_evidence_ids=("EVIDENCE-CONTRADICT",),
    )
    current = reasoning.record_investigation_decision(
        "INVESTIGATION-001", decision_id="DECISION-002",
        decision_type="escalation", outcome="review", rationale="Review",
        author="Analyst", expected_revision=current.revision,
    )
    summary = reasoning.reasoning_summary("INVESTIGATION-001")

    assert summary.total_hypotheses == 2
    assert summary.open == 2
    assert summary.decision_count == 1
    assert summary.hypotheses_lacking_evidence == ("HYP-002",)
    assert summary.mixed_evidence_hypotheses == ("HYP-001",)
    assert [item.hypothesis_id for item in summary.hypotheses] == [
        "HYP-001", "HYP-002"
    ]
    assert summary.decision_ids == ("DECISION-002",)
    assert not hasattr(summary, "confidence")


def test_stale_revision_fails_and_two_services_observe_shared_state(tmp_path):
    reasoning, workspace, repository, prepared = build_services(tmp_path)
    second = InvestigationReasoningService(
        InvestigationWorkspaceService(repository, clock=Clock()),
        clock=Clock(),
    )
    current = create_hypothesis(reasoning, prepared.revision)

    with pytest.raises(InvestigationConflictError):
        create_hypothesis(reasoning, prepared.revision, hypothesis_id="HYP-STALE")

    observed = second.reasoning_summary("INVESTIGATION-001")
    assert observed.total_hypotheses == 1
    assert workspace.get_investigation("INVESTIGATION-001") == current


def test_original_frozen_aggregate_and_selected_evidence_remain_unchanged(tmp_path):
    reasoning, _, _, prepared = build_services(tmp_path)
    original = prepared.investigation
    original_evidence = deepcopy(original.evidence_references)

    result = create_hypothesis(
        reasoning, prepared.revision,
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
    )

    assert original.hypotheses == ()
    assert original.decisions == ()
    assert original.evidence_references == original_evidence
    assert result.investigation.evidence_references == original_evidence
    with pytest.raises(FrozenInstanceError):
        result.investigation.hypotheses[0].statement = "changed"


def test_reasoning_service_architecture_has_no_pipeline_ui_or_catalog_imports():
    source = (
        Path(__file__).parents[1]
        / "soc_forge" / "investigations" / "reasoning_service.py"
    ).read_text(encoding="utf-8")
    repository_source = (
        Path(__file__).parents[1]
        / "soc_forge" / "investigations" / "repository.py"
    ).read_text(encoding="utf-8")

    assert "soc_forge.pipeline" not in source
    assert "evidence_catalog" not in source
    assert "soc_forge.web" not in source
    assert "analyst_console" not in source
    assert "soc_forge.pipeline" not in repository_source
