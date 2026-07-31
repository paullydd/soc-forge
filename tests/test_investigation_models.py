import json
from dataclasses import FrozenInstanceError, replace

import pytest

from soc_forge.investigations.models import (
    INVESTIGATION_SCHEMA_VERSION,
    AnalysisProvenance,
    Annotation,
    ContradictoryEvidenceAssignmentError,
    Decision,
    DuplicateChildIdError,
    EvidenceReference,
    HandoffManifest,
    Hypothesis,
    Investigation,
    InvalidAnnotationTargetError,
    MismatchedHandoffInvestigationError,
    MissingInvestigationReferenceError,
    TimelineSelection,
    WorkspaceMetadata,
)


def build_investigation() -> Investigation:
    evidence = EvidenceReference(
        reference_id="EVIDENCE-001",
        source_type="alert",
        source_id="SOCF-021:2026-07-30T12:00:00Z",
        artifact_key="alerts",
        case_id="CASE-001",
        timestamp="2026-07-30T12:00:00Z",
        label="Windows security-control tampering",
    )
    contradicting_evidence = EvidenceReference(
        reference_id="EVIDENCE-002",
        source_type="event",
        source_id="EVENT-002",
        artifact_key="events",
        label="Expected administrative change",
    )
    hypothesis = Hypothesis(
        hypothesis_id="HYPOTHESIS-001",
        statement="The host security controls were intentionally modified.",
        supporting_evidence_reference_ids=(evidence.reference_id,),
        contradicting_evidence_reference_ids=(contradicting_evidence.reference_id,),
        created_at="2026-07-30T12:05:00Z",
    )
    decision = Decision(
        decision_id="DECISION-001",
        decision_type="triage",
        outcome="escalate",
        rationale="The command requires endpoint validation.",
        evidence_reference_ids=(evidence.reference_id,),
        hypothesis_ids=(hypothesis.hypothesis_id,),
        decided_at="2026-07-30T12:10:00Z",
        decided_by="analyst",
    )
    timeline = TimelineSelection(
        selection_id="TIMELINE-001",
        evidence_reference_ids=(evidence.reference_id,),
        start_time="2026-07-30T11:55:00Z",
        end_time="2026-07-30T12:15:00Z",
        entity_ids=("host:WS-LAB-01",),
    )
    annotation = Annotation(
        annotation_id="ANNOTATION-001",
        target_type="evidence",
        target_id=evidence.reference_id,
        body="Confirm whether this was approved administrative activity.",
        created_at="2026-07-30T12:12:00Z",
        updated_at="2026-07-30T12:12:00Z",
        created_by="analyst",
    )
    manifest = HandoffManifest(
        manifest_id="HANDOFF-001",
        investigation_id="INVESTIGATION-001",
        evidence_reference_ids=(evidence.reference_id,),
        hypothesis_ids=(hypothesis.hypothesis_id,),
        decision_ids=(decision.decision_id,),
        annotation_ids=(annotation.annotation_id,),
        artifact_keys=("alerts", "cases", "reconstructions"),
    )
    return Investigation(
        investigation_id="INVESTIGATION-001",
        analysis_id="ANALYSIS-001",
        metadata=WorkspaceMetadata(
            title="Security control investigation",
            created_at="2026-07-30T12:00:00Z",
            updated_at="2026-07-30T12:12:00Z",
            owner="analyst",
            labels=("endpoint", "defense-evasion"),
        ),
        analysis_artifact_keys=("alerts", "cases", "reconstructions"),
        evidence_references=(evidence, contradicting_evidence),
        hypotheses=(hypothesis,),
        decisions=(decision,),
        timeline_selections=(timeline,),
        annotations=(annotation,),
        handoff_manifest=manifest,
    )


def test_investigation_constructs_with_versioned_relationships():
    investigation = build_investigation()

    assert investigation.schema_version == INVESTIGATION_SCHEMA_VERSION
    assert investigation.metadata.schema_version == INVESTIGATION_SCHEMA_VERSION
    assert investigation.metadata.status == "open"
    assert investigation.evidence_references[0].source_id.startswith("SOCF-021:")
    assert investigation.hypotheses[0].supporting_evidence_reference_ids == ("EVIDENCE-001",)
    assert investigation.decisions[0].hypothesis_ids == ("HYPOTHESIS-001",)
    assert investigation.handoff_manifest.investigation_id == investigation.investigation_id


def test_investigation_serializes_to_json_compatible_dictionary():
    payload = build_investigation().to_dict()

    encoded = json.dumps(payload, sort_keys=True)

    assert '"investigation_id": "INVESTIGATION-001"' in encoded
    assert payload["metadata"]["labels"] == ["endpoint", "defense-evasion"]
    assert payload["evidence_references"][0]["artifact_key"] == "alerts"
    assert payload["annotations"][0]["updated_at"] == "2026-07-30T12:12:00Z"
    assert payload["handoff_manifest"]["decision_ids"] == ["DECISION-001"]


def test_investigation_round_trip_preserves_nested_models_and_tuples():
    original = build_investigation()

    restored = Investigation.from_dict(json.loads(json.dumps(original.to_dict())))

    assert restored == original
    assert isinstance(restored.metadata, WorkspaceMetadata)
    assert isinstance(restored.evidence_references[0], EvidenceReference)
    assert isinstance(restored.handoff_manifest, HandoffManifest)
    assert restored.timeline_selections[0].entity_ids == ("host:WS-LAB-01",)


def test_evidence_reference_is_immutable_and_contains_no_analysis_payload():
    reference = build_investigation().evidence_references[0]

    with pytest.raises(FrozenInstanceError):
        reference.source_id = "changed"

    assert not hasattr(reference, "payload")
    assert not hasattr(reference, "event")
    assert not hasattr(reference, "alert")


def test_minimal_investigation_has_empty_relationship_collections():
    investigation = Investigation(
        investigation_id="INVESTIGATION-EMPTY",
        analysis_id="ANALYSIS-EMPTY",
        metadata=WorkspaceMetadata(
            title="Empty investigation",
            created_at="2026-07-30T00:00:00Z",
            updated_at="2026-07-30T00:00:00Z",
        ),
    )

    assert investigation.analysis_artifact_keys == ()
    assert investigation.evidence_references == ()
    assert investigation.handoff_manifest is None
    assert Investigation.from_dict(investigation.to_dict()) == investigation


def test_mutable_caller_collections_are_copied_to_tuples():
    labels = ["endpoint"]
    evidence_ids = ["EVIDENCE-001"]
    metadata = WorkspaceMetadata(
        title="List normalization",
        created_at="2026-07-30T00:00:00Z",
        updated_at="2026-07-30T00:00:00Z",
        labels=labels,
    )
    hypothesis = Hypothesis(
        hypothesis_id="HYPOTHESIS-LIST",
        statement="Caller lists are not retained.",
        supporting_evidence_reference_ids=evidence_ids,
    )

    labels.append("mutated")
    evidence_ids.append("EVIDENCE-002")

    assert metadata.labels == ("endpoint",)
    assert hypothesis.supporting_evidence_reference_ids == ("EVIDENCE-001",)


@pytest.mark.parametrize("schema_version", ["", "1", "v1.0", "2.0"])
def test_unknown_or_malformed_schema_versions_fail_clearly(schema_version):
    with pytest.raises(ValueError, match="schema_version"):
        WorkspaceMetadata(
            title="Invalid version",
            created_at="2026-07-30T00:00:00Z",
            updated_at="2026-07-30T00:00:00Z",
            schema_version=schema_version,
        )


def test_additive_minor_schema_version_round_trips():
    metadata = WorkspaceMetadata(
        title="Future minor version",
        created_at="2026-07-30T00:00:00Z",
        updated_at="2026-07-30T00:00:00Z",
        schema_version="1.1",
    )

    assert WorkspaceMetadata.from_dict(metadata.to_dict()) == metadata


def test_missing_required_deserialization_field_has_specific_error():
    with pytest.raises(ValueError, match="Investigation is missing required field.*analysis_id"):
        Investigation.from_dict(
            {
                "investigation_id": "INVESTIGATION-001",
                "metadata": {
                    "title": "Missing analysis",
                    "created_at": "2026-07-30T00:00:00Z",
                    "updated_at": "2026-07-30T00:00:00Z",
                },
            }
        )


def test_invalid_relationship_values_fail_clearly():
    with pytest.raises(ValueError, match="EvidenceReference.source_type"):
        EvidenceReference(reference_id="EVIDENCE-001", source_type="unknown", source_id="1")

    with pytest.raises(ValueError, match="Hypothesis.state"):
        Hypothesis(hypothesis_id="HYPOTHESIS-001", statement="Invalid", state="closed")

    with pytest.raises(ValueError, match="Annotation.target_type"):
        Annotation(
            annotation_id="ANNOTATION-001",
            target_type="case_payload",
            target_id="CASE-001",
            body="Invalid target type",
            created_at="2026-07-30T00:00:00Z",
        )


def test_all_public_domain_models_are_frozen_and_serialize_deterministically():
    model_types = (
        WorkspaceMetadata,
        EvidenceReference,
        Hypothesis,
        Decision,
        TimelineSelection,
        Annotation,
        HandoffManifest,
        Investigation,
    )
    investigation = build_investigation()

    for model_type in model_types:
        assert model_type.__dataclass_params__.frozen is True

    assert investigation.to_dict() == investigation.to_dict()

@pytest.mark.parametrize(
    ("field_name", "duplicate_id"),
    [
        ("evidence_references", "EVIDENCE-001"),
        ("hypotheses", "HYPOTHESIS-001"),
        ("decisions", "DECISION-001"),
        ("annotations", "ANNOTATION-001"),
        ("timeline_selections", "TIMELINE-001"),
    ],
)
def test_duplicate_child_ids_are_rejected_per_namespace(field_name, duplicate_id):
    investigation = build_investigation()
    children = getattr(investigation, field_name)

    with pytest.raises(DuplicateChildIdError, match=duplicate_id):
        replace(investigation, **{field_name: children + (children[0],)})


def test_same_id_is_allowed_across_different_child_namespaces():
    investigation = build_investigation()
    annotation = Annotation(
        annotation_id="DECISION-001",
        target_type="investigation",
        target_id=investigation.investigation_id,
        body="Separate child namespaces may reuse an identifier.",
        created_at="2026-07-30T12:15:00Z",
    )

    updated = replace(
        investigation,
        annotations=investigation.annotations + (annotation,),
        handoff_manifest=None,
    )

    assert updated.decisions[0].decision_id == updated.annotations[-1].annotation_id


@pytest.mark.parametrize(
    ("relationship_field", "missing_id"),
    [
        ("supporting_evidence_reference_ids", "EVIDENCE-MISSING-SUPPORT"),
        ("contradicting_evidence_reference_ids", "EVIDENCE-MISSING-CONTRADICTION"),
    ],
)
def test_hypothesis_rejects_missing_evidence(relationship_field, missing_id):
    investigation = build_investigation()
    hypothesis = replace(
        investigation.hypotheses[0],
        **{relationship_field: (missing_id,)},
    )

    with pytest.raises(MissingInvestigationReferenceError, match=missing_id):
        replace(investigation, hypotheses=(hypothesis,), handoff_manifest=None)


def test_hypothesis_rejects_same_supporting_and_contradicting_evidence():
    investigation = build_investigation()
    hypothesis = replace(
        investigation.hypotheses[0],
        supporting_evidence_reference_ids=("EVIDENCE-001",),
        contradicting_evidence_reference_ids=("EVIDENCE-001",),
    )

    with pytest.raises(
        ContradictoryEvidenceAssignmentError,
        match="EVIDENCE-001",
    ):
        replace(investigation, hypotheses=(hypothesis,), handoff_manifest=None)


@pytest.mark.parametrize(
    ("field_name", "missing_id"),
    [
        ("evidence_reference_ids", "EVIDENCE-MISSING"),
        ("hypothesis_ids", "HYPOTHESIS-MISSING"),
    ],
)
def test_decision_rejects_missing_owned_references(field_name, missing_id):
    investigation = build_investigation()
    decision = replace(investigation.decisions[0], **{field_name: (missing_id,)})

    with pytest.raises(MissingInvestigationReferenceError, match=missing_id):
        replace(investigation, decisions=(decision,), handoff_manifest=None)


def test_timeline_selection_rejects_missing_evidence():
    investigation = build_investigation()
    selection = replace(
        investigation.timeline_selections[0],
        evidence_reference_ids=("EVIDENCE-MISSING",),
    )

    with pytest.raises(MissingInvestigationReferenceError, match="EVIDENCE-MISSING"):
        replace(
            investigation,
            timeline_selections=(selection,),
            handoff_manifest=None,
        )


@pytest.mark.parametrize(
    ("target_type", "target_id"),
    [
        ("investigation", "INVESTIGATION-001"),
        ("evidence", "EVIDENCE-001"),
        ("hypothesis", "HYPOTHESIS-001"),
        ("decision", "DECISION-001"),
        ("timeline_selection", "TIMELINE-001"),
        ("case", "CASE-EXTERNAL"),
        ("analysis", "ANALYSIS-EXTERNAL"),
    ],
)
def test_annotation_target_policy_accepts_valid_internal_and_external_targets(
    target_type,
    target_id,
):
    investigation = build_investigation()
    annotation = Annotation(
        annotation_id="ANNOTATION-TARGET",
        target_type=target_type,
        target_id=target_id,
        body="Target policy",
        created_at="2026-07-30T12:15:00Z",
    )

    updated = replace(
        investigation,
        annotations=(annotation,),
        handoff_manifest=None,
    )

    assert updated.annotations == (annotation,)


def test_annotation_rejects_missing_owned_target():
    investigation = build_investigation()
    annotation = Annotation(
        annotation_id="ANNOTATION-MISSING",
        target_type="evidence",
        target_id="EVIDENCE-MISSING",
        body="Invalid target",
        created_at="2026-07-30T12:15:00Z",
    )

    with pytest.raises(InvalidAnnotationTargetError, match="EVIDENCE-MISSING"):
        replace(investigation, annotations=(annotation,), handoff_manifest=None)


def test_handoff_manifest_requires_owning_investigation_and_known_references():
    investigation = build_investigation()

    with pytest.raises(MismatchedHandoffInvestigationError, match="OTHER"):
        replace(
            investigation,
            handoff_manifest=replace(
                investigation.handoff_manifest,
                investigation_id="OTHER",
            ),
        )

    with pytest.raises(MissingInvestigationReferenceError, match="DECISION-MISSING"):
        replace(
            investigation,
            handoff_manifest=replace(
                investigation.handoff_manifest,
                decision_ids=("DECISION-MISSING",),
            ),
        )


def test_analysis_provenance_round_trips_and_is_immutable():
    provenance = AnalysisProvenance(
        source_analysis_id="analysis-abc",
        normalized_input_name="events.jsonl",
        event_digest="event-digest",
        alert_digest="alert-digest",
        case_digest="case-digest",
        reconstruction_digest="reconstruction-digest",
        rule_set_digest="rule-digest",
        artifact_keys=["cases", "alerts"],
    )

    restored = AnalysisProvenance.from_dict(
        json.loads(json.dumps(provenance.to_dict(), sort_keys=True))
    )

    assert restored == provenance
    assert restored.artifact_keys == ("cases", "alerts")
    with pytest.raises(FrozenInstanceError):
        restored.source_analysis_id = "changed"


def test_legacy_investigation_without_provenance_still_round_trips():
    payload = build_investigation().to_dict()
    payload.pop("provenance")

    restored = Investigation.from_dict(payload)

    assert restored.provenance is None
    assert restored.analysis_id == "ANALYSIS-001"


def test_provenance_id_must_match_investigation_analysis_id():
    investigation = build_investigation()
    provenance = AnalysisProvenance(
        source_analysis_id="analysis-other",
        normalized_input_name="events.jsonl",
        event_digest="event",
        alert_digest="alert",
        case_digest="case",
        reconstruction_digest="reconstruction",
        rule_set_digest="rules",
    )

    with pytest.raises(MissingInvestigationReferenceError, match="analysis-other"):
        replace(investigation, provenance=provenance)
