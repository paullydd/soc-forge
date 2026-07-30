import json
from dataclasses import FrozenInstanceError

import pytest

from soc_forge.investigations.models import (
    INVESTIGATION_SCHEMA_VERSION,
    Annotation,
    Decision,
    EvidenceReference,
    HandoffManifest,
    Hypothesis,
    Investigation,
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
    hypothesis = Hypothesis(
        hypothesis_id="HYPOTHESIS-001",
        statement="The host security controls were intentionally modified.",
        supporting_evidence_reference_ids=(evidence.reference_id,),
        contradicting_evidence_reference_ids=("EVIDENCE-002",),
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
        evidence_references=(evidence,),
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
