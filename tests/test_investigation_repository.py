from dataclasses import replace
import json
from pathlib import Path

import pytest

from soc_forge.investigations.models import (
    Annotation,
    Decision,
    EvidenceReference,
    HandoffManifest,
    Hypothesis,
    Investigation,
    TimelineSelection,
    WorkspaceMetadata,
)
from soc_forge.investigations.repository import (
    CorruptInvestigationRecordError,
    InvalidInvestigationIdError,
    InvestigationAlreadyExistsError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    InvestigationRepository,
)


def build_investigation(
    investigation_id: str = "INVESTIGATION-001",
    *,
    updated_at: str = "2026-07-30T12:12:00Z",
) -> Investigation:
    evidence = EvidenceReference(
        reference_id="EVIDENCE-001",
        source_type="alert",
        source_id="SOCF-021:2026-07-30T12:00:00Z",
        artifact_key="alerts",
        case_id="CASE-001",
        timestamp="2026-07-30T12:00:00Z",
    )
    hypothesis = Hypothesis(
        hypothesis_id="HYPOTHESIS-001",
        statement="Security controls were intentionally modified.",
        supporting_evidence_reference_ids=(evidence.reference_id,),
    )
    decision = Decision(
        decision_id="DECISION-001",
        decision_type="triage",
        outcome="escalate",
        evidence_reference_ids=(evidence.reference_id,),
        hypothesis_ids=(hypothesis.hypothesis_id,),
    )
    annotation = Annotation(
        annotation_id="ANNOTATION-001",
        target_type="evidence",
        target_id=evidence.reference_id,
        body="Validate the command with the endpoint owner.",
        created_at="2026-07-30T12:10:00Z",
    )
    return Investigation(
        investigation_id=investigation_id,
        analysis_id="ANALYSIS-001",
        metadata=WorkspaceMetadata(
            title=f"Investigation {investigation_id}",
            created_at="2026-07-30T12:00:00Z",
            updated_at=updated_at,
            owner="analyst",
            labels=("endpoint",),
        ),
        analysis_artifact_keys=("alerts", "cases", "reconstructions"),
        evidence_references=(evidence,),
        hypotheses=(hypothesis,),
        decisions=(decision,),
        timeline_selections=(
            TimelineSelection(
                selection_id="TIMELINE-001",
                evidence_reference_ids=(evidence.reference_id,),
                start_time="2026-07-30T11:55:00Z",
                end_time="2026-07-30T12:15:00Z",
            ),
        ),
        annotations=(annotation,),
        handoff_manifest=HandoffManifest(
            manifest_id="HANDOFF-001",
            investigation_id=investigation_id,
            evidence_reference_ids=(evidence.reference_id,),
            hypothesis_ids=(hypothesis.hypothesis_id,),
            decision_ids=(decision.decision_id,),
            annotation_ids=(annotation.annotation_id,),
            artifact_keys=("alerts", "cases", "reconstructions"),
        ),
    )


def record_path(root: Path, investigation_id: str = "INVESTIGATION-001") -> Path:
    return root / "investigations" / f"{investigation_id}.json"


def test_save_and_load_preserve_nested_aggregate_equality(tmp_path):
    repository = InvestigationRepository(tmp_path)
    investigation = build_investigation()

    revision = repository.save(investigation)

    assert revision == 1
    assert repository.exists(investigation.investigation_id)
    assert repository.load(investigation.investigation_id) == investigation
    stored = repository.load_record(investigation.investigation_id)
    assert stored.investigation == investigation
    assert stored.revision == 1


def test_json_output_is_deterministic_and_human_inspectable(tmp_path):
    investigation = build_investigation()
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"

    InvestigationRepository(first_root).save(investigation)
    InvestigationRepository(second_root).save(investigation)

    first = record_path(first_root).read_text(encoding="utf-8")
    second = record_path(second_root).read_text(encoding="utf-8")
    assert first == second
    assert first.endswith("\n")
    assert list(json.loads(first)) == [
        "investigation",
        "repository_schema_version",
        "revision",
    ]


def test_duplicate_save_requires_current_revision_and_stale_update_conflicts(tmp_path):
    repository = InvestigationRepository(tmp_path)
    investigation = build_investigation()
    revision = repository.save(investigation)

    with pytest.raises(InvestigationAlreadyExistsError):
        repository.save(investigation)

    updated = replace(
        investigation,
        metadata=replace(
            investigation.metadata,
            title="Updated investigation",
            updated_at="2026-07-30T13:00:00Z",
        ),
    )
    assert repository.save(updated, expected_revision=revision) == 2
    assert repository.load(investigation.investigation_id) == updated

    with pytest.raises(InvestigationConflictError, match="revision 2"):
        repository.save(investigation, expected_revision=revision)


def test_expected_revision_cannot_create_a_missing_record(tmp_path):
    repository = InvestigationRepository(tmp_path)

    with pytest.raises(InvestigationConflictError, match="does not exist"):
        repository.save(build_investigation(), expected_revision=1)


def test_missing_investigation_has_specific_errors(tmp_path):
    repository = InvestigationRepository(tmp_path)

    assert repository.exists("INVESTIGATION-MISSING") is False
    with pytest.raises(InvestigationNotFoundError):
        repository.load("INVESTIGATION-MISSING")
    with pytest.raises(InvestigationNotFoundError):
        repository.delete("INVESTIGATION-MISSING")


@pytest.mark.parametrize(
    "investigation_id",
    ["", " ", "..", "../escape", "nested/id", r"nested\id", "/absolute", "\x00"],
)
def test_invalid_investigation_ids_are_rejected(tmp_path, investigation_id):
    repository = InvestigationRepository(tmp_path)

    with pytest.raises(InvalidInvestigationIdError):
        repository.exists(investigation_id)


@pytest.mark.parametrize("content", ["not-json", "[]"])
def test_malformed_or_non_object_records_fail_clearly(tmp_path, content):
    path = record_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")

    with pytest.raises(CorruptInvestigationRecordError, match="INVESTIGATION-001"):
        InvestigationRepository(tmp_path).load("INVESTIGATION-001")


def test_unsupported_investigation_schema_major_fails_as_corrupt_record(tmp_path):
    repository = InvestigationRepository(tmp_path)
    repository.save(build_investigation())
    path = record_path(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["investigation"]["schema_version"] = "2.0"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CorruptInvestigationRecordError, match="unsupported major version 2"):
        repository.load("INVESTIGATION-001")


def test_listing_is_newest_updated_first_with_id_tie_breaker(tmp_path):
    repository = InvestigationRepository(tmp_path)
    repository.save(
        build_investigation("INVESTIGATION-B", updated_at="2026-07-30T13:00:00Z")
    )
    repository.save(
        build_investigation("INVESTIGATION-A", updated_at="2026-07-30T13:00:00Z")
    )
    repository.save(
        build_investigation("INVESTIGATION-OLD", updated_at="2026-07-30T11:00:00Z")
    )
    (tmp_path / "investigations" / ".INVESTIGATION-TEMP.tmp").write_text(
        "partial",
        encoding="utf-8",
    )

    summaries = repository.list_investigations()

    assert [summary.investigation_id for summary in summaries] == [
        "INVESTIGATION-A",
        "INVESTIGATION-B",
        "INVESTIGATION-OLD",
    ]
    assert summaries[0].title == "Investigation INVESTIGATION-A"
    assert summaries[0].revision == 1


def test_delete_removes_only_investigation_record(tmp_path):
    artifact = tmp_path / "analysis-artifacts" / "alerts.json"
    artifact.parent.mkdir()
    artifact.write_text("[]", encoding="utf-8")
    repository = InvestigationRepository(tmp_path)
    repository.save(build_investigation())

    repository.delete("INVESTIGATION-001")

    assert repository.exists("INVESTIGATION-001") is False
    assert artifact.read_text(encoding="utf-8") == "[]"


def test_failed_atomic_replace_does_not_corrupt_existing_record(tmp_path, monkeypatch):
    repository = InvestigationRepository(tmp_path)
    investigation = build_investigation()
    repository.save(investigation)
    original = record_path(tmp_path).read_text(encoding="utf-8")

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("soc_forge.investigations.repository.os.replace", fail_replace)
    updated = replace(
        investigation,
        metadata=replace(investigation.metadata, updated_at="2026-07-30T14:00:00Z"),
    )

    with pytest.raises(OSError, match="simulated replace failure"):
        repository.save(updated, expected_revision=1)

    assert record_path(tmp_path).read_text(encoding="utf-8") == original
    assert list((tmp_path / "investigations").glob("*.tmp")) == []


def test_records_contain_references_without_copied_analysis_payloads(tmp_path):
    repository = InvestigationRepository(tmp_path)
    repository.save(build_investigation())

    payload = json.loads(record_path(tmp_path).read_text(encoding="utf-8"))
    serialized = payload["investigation"]

    assert serialized["analysis_artifact_keys"] == ["alerts", "cases", "reconstructions"]
    assert serialized["evidence_references"][0]["source_id"].startswith("SOCF-021:")
    assert "events" not in serialized
    assert "alerts" not in serialized
    assert "cases" not in serialized
    assert "reconstructions" not in serialized
    assert "details" not in serialized["evidence_references"][0]


def test_repository_instances_share_persisted_state_without_global_state(tmp_path):
    first = InvestigationRepository(tmp_path)
    second = InvestigationRepository(tmp_path)
    investigation = build_investigation()

    first.save(investigation)

    assert second.exists(investigation.investigation_id)
    assert second.load(investigation.investigation_id) == investigation


def test_listing_rejects_record_symlink_that_escapes_repository_root(tmp_path):
    outside_record = tmp_path / "outside.json"
    outside_record.write_text("{}", encoding="utf-8")
    investigations_root = tmp_path / "workspace" / "investigations"
    investigations_root.mkdir(parents=True)
    (investigations_root / "INVESTIGATION-LINK.json").symlink_to(outside_record)

    with pytest.raises(InvalidInvestigationIdError, match="escapes"):
        InvestigationRepository(tmp_path / "workspace").list_investigations()
