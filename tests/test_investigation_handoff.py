from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path

import pytest

import soc_forge.investigations.handoff as handoff_module

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.handoff import (
    HANDOFF_SCHEMA_VERSION,
    HandoffArtifactDigestMismatchError,
    HandoffBundleValidationError,
    HandoffProvenanceMismatchError,
    HandoffReferenceIntegrityError,
    InvestigationChangedDuringHandoffError,
    InvestigationHandoffService,
    RequiredHandoffArtifactMissingError,
    UnsafeHandoffArtifactPathError,
    UnsafeHandoffOutputPathError,
    UnsupportedHandoffSchemaError,
    validate_handoff_bundle,
)
from soc_forge.investigations.models import (
    Decision, InvestigationFinding, TimelineSelection,
)
from soc_forge.investigations.repository import InvestigationRepository


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_hashes(root: Path):
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def repository_bytes(root: Path):
    return {
        path.name: path.read_bytes()
        for path in (root / "investigations").glob("*.json")
    }


def build_export(tmp_path, *, investigation=None, analysis=None, before_finalize=None):
    analysis = analysis or build_query_analysis(tmp_path / "analysis")
    investigation = investigation or build_query_investigation(analysis)
    workspace = tmp_path / "workspace"
    repository = InvestigationRepository(workspace)
    assert repository.save(investigation) == 1
    result = InvestigationHandoffService(
        repository,
        before_finalize=before_finalize,
    ).export(investigation.investigation_id, analysis, tmp_path / "handoffs")
    return result, analysis, investigation, repository, workspace


def rewrite_component(bundle: Path, name: str, payload) -> None:
    path = bundle / name
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    manifest = read_json(bundle / "manifest.json")
    for item in manifest["files"]:
        if item["filename"] == name:
            data = path.read_bytes()
            item["size"] = len(data)
            item["sha256"] = sha256(data).hexdigest()
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def test_handoff_manifest_snapshot_and_bundle_contract(tmp_path):
    result, analysis, investigation, _, _ = build_export(tmp_path)

    assert result.validation_status == "valid"
    assert result.output_path.name == investigation.investigation_id
    assert validate_handoff_bundle(result.output_path)
    assert {path.name for path in result.output_path.iterdir()} == {
        "manifest.json", "investigation.json", "evidence_index.json",
        "hypotheses.json", "decisions.json", "findings.json", "annotations.json",
        "timeline.json", "limitations.json", "source_artifacts",
    }
    manifest = read_json(result.manifest_path)
    assert manifest["schema_version"] == HANDOFF_SCHEMA_VERSION
    assert manifest["handoff_id"] == result.handoff_id
    assert manifest["investigation_id"] == investigation.investigation_id
    assert manifest["source_analysis_id"] == investigation.analysis_id
    assert manifest["investigation_revision"] == 1
    assert manifest["selected_case_ids"] == ["CASE-001"]
    assert manifest["owner"] == "Analyst"
    assert manifest["status"] == "in_progress"
    assert manifest["provenance"]["algorithm"]
    assert manifest["creation_tool"]["name"] == "SOC-Forge"
    encoded = json.dumps(manifest)
    assert str(tmp_path) not in encoded
    assert "entity-host-" not in encoded
    assert "Review and redact before external sharing" in encoded
    assert set(manifest["logical_artifact_references"]) == set(analysis.artifacts)


def test_snapshot_separates_scope_and_selected_evidence_and_preserves_reasoning(tmp_path):
    result, _, investigation, _, _ = build_export(tmp_path)
    snapshot = read_json(result.output_path / "investigation.json")
    evidence = read_json(result.output_path / "evidence_index.json")
    hypotheses = read_json(result.output_path / "hypotheses.json")["hypotheses"]
    decisions = read_json(result.output_path / "decisions.json")["decisions"]
    annotations = read_json(result.output_path / "annotations.json")["annotations"]

    assert snapshot == {
        "created_at": "2026-08-10T14:04:00Z",
        "investigation_id": "INV-QUERY",
        "limitations": ["Entries without reliable timestamps are returned as untimed."],
        "owner": "Analyst",
        "revision": 1,
        "selected_case_ids": ["CASE-001"],
        "source_analysis_id": investigation.analysis_id,
        "status": "in_progress",
        "title": "Query investigation",
        "updated_at": "2026-08-10T14:10:00Z",
    }
    assert len(evidence["scope_references"]) == 1
    assert len(evidence["analyst_selected_evidence"]) == 3
    selected = {item["classification"]: item for item in evidence["analyst_selected_evidence"]}
    assert selected["supporting"]["rationale"] == "Supports defense-evasion hypothesis"
    assert selected["supporting"]["author"] == "Analyst"
    assert selected["supporting"]["related_case_ids"] == ["CASE-001"]
    assert hypotheses[0]["state"] == "open"
    assert hypotheses[0]["supporting_evidence_ids"]
    assert hypotheses[0]["contradicting_evidence_ids"]
    assert hypotheses[0]["assessment_history_ids"] == ["DEC-ASSESS", "DEC-REOPEN"]
    assert {item["decision_id"] for item in decisions} == {
        "DEC-ASSESS", "DEC-REOPEN", "DEC-GENERAL"
    }
    assert next(item for item in decisions if item["decision_id"] == "DEC-GENERAL")["rationale"] == "Senior review required"
    assert annotations[0]["text"] == "Sensitive annotation body"
    assert annotations[0]["sensitive"] is True


def test_legacy_decision_type_is_exported_without_reinterpretation(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    legacy = Decision(
        decision_id="DEC-LEGACY",
        decision_type="legacy_custom_action",
        outcome="preserved",
        rationale="Keep original wording",
        decided_by="Legacy Analyst",
    )
    investigation = replace(investigation, decisions=investigation.decisions + (legacy,))
    result, *_ = build_export(tmp_path, investigation=investigation, analysis=analysis)
    decisions = read_json(result.output_path / "decisions.json")["decisions"]
    exported = next(item for item in decisions if item["decision_id"] == "DEC-LEGACY")
    assert exported["decision_type"] == "legacy_custom_action"
    assert exported["outcome"] == "preserved"


def test_timeline_exports_scoped_projection_and_persisted_selection_without_raw_payload(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    selected_evidence = next(
        item.reference_id
        for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    selection = TimelineSelection(
        selection_id="TIMELINE-001",
        evidence_reference_ids=(selected_evidence,),
        start_time="2026-08-10T14:00:00Z",
        entity_ids=("entity-host-0123456789abcdef01234567",),
    )
    investigation = replace(investigation, timeline_selections=(selection,))
    result, *_ = build_export(tmp_path, investigation=investigation, analysis=analysis)
    timeline = read_json(result.output_path / "timeline.json")

    assert timeline["timed_entries"]
    assert timeline["untimed_entries"]
    assert {item["context_kind"] for item in timeline["timed_entries"] + timeline["untimed_entries"]} == {"machine", "analyst"}
    assert timeline["timeline_selections"][0]["selection_id"] == "TIMELINE-001"
    encoded = json.dumps(timeline)
    assert "powershell.exe -enc sensitive" not in encoded
    assert "Sensitive annotation body" not in encoded
    assert "entity-host-0123456789abcdef01234567" not in encoded
    alert = next(item for item in timeline["timed_entries"] if item["source_id"] == "ALERT-001")
    assert alert["rule_id"] == "SOCF-021"
    assert alert["attack_technique"] == "T1562.001"
    assert alert["relationship_reason"]
    assert alert["related_hypothesis_ids"] == ["HYP-001"]


def test_handoff_identity_changes_only_with_stable_investigation_content(tmp_path):
    result_a, analysis, investigation, _, _ = build_export(tmp_path / "a")
    result_b, *_ = build_export(tmp_path / "b", investigation=investigation, analysis=analysis)
    assert result_a.handoff_id == result_b.handoff_id

    changed_evidence = replace(
        investigation.evidence_references[-1], rationale="Different analyst rationale"
    )
    changed = replace(
        investigation,
        evidence_references=investigation.evidence_references[:-1] + (changed_evidence,),
    )
    result_c, *_ = build_export(tmp_path / "c", investigation=changed, analysis=analysis)
    assert result_c.handoff_id != result_a.handoff_id

    changed_hypothesis = replace(investigation.hypotheses[0], state="supported")
    changed = replace(investigation, hypotheses=(changed_hypothesis,))
    result_d, *_ = build_export(tmp_path / "d", investigation=changed, analysis=analysis)
    assert result_d.handoff_id != result_a.handoff_id

    workspace = tmp_path / "revision" / "workspace"
    repository = InvestigationRepository(workspace)
    repository.save(investigation)
    updated = replace(
        investigation,
        metadata=replace(investigation.metadata, updated_at="2026-08-10T15:00:00Z"),
    )
    repository.save(updated, expected_revision=1)
    result_e = InvestigationHandoffService(repository).export(
        investigation.investigation_id,
        analysis,
        tmp_path / "revision" / "handoffs",
    )
    assert result_e.revision == 2
    assert result_e.handoff_id != result_a.handoff_id


def test_bundle_bytes_are_deterministic_across_roots_and_collection_order(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    first, *_ = build_export(tmp_path / "first", investigation=investigation, analysis=analysis)
    reordered = deepcopy(analysis)
    for name in ("events", "alerts", "cases", "reconstructions"):
        getattr(reordered, name).reverse()
    reordered.events = [dict(reversed(tuple(item.items()))) for item in reordered.events]
    reordered.alerts = [dict(reversed(tuple(item.items()))) for item in reordered.alerts]
    reordered.cases = [dict(reversed(tuple(item.items()))) for item in reordered.cases]
    second, *_ = build_export(tmp_path / "second", investigation=investigation, analysis=reordered)
    assert file_hashes(first.output_path) == file_hashes(second.output_path)


def test_artifact_allowlist_copy_integrity_optional_missing_and_required_missing(tmp_path):
    result, analysis, _, _, _ = build_export(tmp_path / "valid")
    manifest = read_json(result.manifest_path)
    artifact_entries = [item for item in manifest["files"] if item["logical_type"].startswith("artifact:")]
    assert {item["logical_type"] for item in artifact_entries} == {
        f"artifact:{key}" for key in analysis.artifacts
    }
    for key, source in analysis.artifacts.items():
        copied = result.output_path / "source_artifacts" / ({
            "alerts": "alerts.json", "cases": "cases.json", "events": "events.json",
            "reconstructions": "reconstructions.json",
        }[key])
        assert copied.read_bytes() == source.read_bytes()

    optional = build_query_analysis(tmp_path / "optional" / "analysis")
    optional.artifacts["hunts"] = optional.output_dir / "missing-hunts.json"
    investigation = build_query_investigation(optional)
    result, *_ = build_export(tmp_path / "optional", investigation=investigation, analysis=optional)
    assert "Optional analysis artifact is unavailable: hunts" in result.warnings

    required = build_query_analysis(tmp_path / "required" / "analysis")
    required.artifacts["cases"].unlink()
    investigation = build_query_investigation(required)
    repository = InvestigationRepository(tmp_path / "required" / "workspace")
    repository.save(investigation)
    with pytest.raises(RequiredHandoffArtifactMissingError):
        InvestigationHandoffService(repository).export(
            investigation.investigation_id, required, tmp_path / "required" / "handoffs"
        )


def test_unknown_outside_and_symlink_artifacts_are_rejected(tmp_path):
    for mode in ("unknown", "outside", "symlink"):
        root = tmp_path / mode
        analysis = build_query_analysis(root / "analysis")
        if mode == "unknown":
            analysis.artifacts["arbitrary"] = analysis.output_dir / "arbitrary.json"
            analysis.artifacts["arbitrary"].write_text("x", encoding="utf-8")
        elif mode == "outside":
            outside = root / "outside.json"
            outside.write_text("x", encoding="utf-8")
            analysis.artifacts["alerts"] = outside
        else:
            target = root / "outside.json"
            target.write_text("x", encoding="utf-8")
            link = analysis.output_dir / "linked-alerts.json"
            link.symlink_to(target)
            analysis.artifacts["alerts"] = link
        investigation = build_query_investigation(analysis)
        repository = InvestigationRepository(root / "workspace")
        repository.save(investigation)
        with pytest.raises(UnsafeHandoffArtifactPathError):
            InvestigationHandoffService(repository).export(
                investigation.investigation_id, analysis, root / "handoffs"
            )


def test_output_path_and_reexport_policy_are_explicit(tmp_path):
    result, analysis, investigation, repository, _ = build_export(tmp_path)
    with pytest.raises(UnsafeHandoffOutputPathError):
        InvestigationHandoffService(repository).export(
            investigation.investigation_id, analysis, tmp_path / "handoffs"
        )
    replacement = InvestigationHandoffService(repository).export(
        investigation.investigation_id,
        analysis,
        tmp_path / "handoffs",
        overwrite=True,
    )
    assert replacement.handoff_id == result.handoff_id
    outside = tmp_path / "outside.txt"
    outside.write_text("unchanged", encoding="utf-8")
    assert outside.read_text(encoding="utf-8") == "unchanged"


def test_failed_overwrite_publication_restores_previous_bundle(tmp_path, monkeypatch):
    result, analysis, investigation, repository, _ = build_export(tmp_path)
    before = file_hashes(result.output_path)
    real_replace = handoff_module.os.replace
    failure_injected = False

    def fail_staging_publication(source, destination):
        nonlocal failure_injected
        source_path = Path(source)
        destination_path = Path(destination)
        if (
            not failure_injected
            and source_path.name.startswith(f".{investigation.investigation_id}.")
            and destination_path == result.output_path
        ):
            failure_injected = True
            raise OSError("injected publication failure")
        return real_replace(source, destination)

    monkeypatch.setattr(handoff_module.os, "replace", fail_staging_publication)

    with pytest.raises(OSError, match="injected publication failure"):
        InvestigationHandoffService(repository).export(
            investigation.investigation_id,
            analysis,
            tmp_path / "handoffs",
            overwrite=True,
        )

    assert failure_injected is True
    assert file_hashes(result.output_path) == before
    assert validate_handoff_bundle(result.output_path) is True
    assert not (result.output_path.parent / f".{result.output_path.name}.previous").exists()
    assert not any(
        path.name.startswith(f".{investigation.investigation_id}.")
        for path in result.output_path.parent.iterdir()
    )


@pytest.mark.parametrize("unsafe_id", ["../INV-QUERY", "/tmp/INV-QUERY", r"INV\QUERY"])
def test_output_identity_cannot_escape_selected_root(tmp_path, unsafe_id):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    repository.save(investigation)
    with pytest.raises(UnsafeHandoffOutputPathError):
        InvestigationHandoffService(repository).export(
            unsafe_id,
            analysis,
            tmp_path / "handoffs",
        )


def test_symlink_output_root_is_rejected(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    repository.save(investigation)
    real_root = tmp_path / "real-handoffs"
    real_root.mkdir()
    linked_root = tmp_path / "linked-handoffs"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(UnsafeHandoffOutputPathError):
        InvestigationHandoffService(repository).export(
            investigation.investigation_id,
            analysis,
            linked_root,
        )


def test_provenance_and_revision_conflicts_do_not_publish_partial_bundle(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    repository.save(investigation)
    mismatch = build_query_analysis(tmp_path / "other-analysis")
    mismatch.events[0]["host"] = "DIFFERENT-HOST"
    with pytest.raises(HandoffProvenanceMismatchError):
        InvestigationHandoffService(repository).export(
            investigation.investigation_id, mismatch, tmp_path / "mismatch"
        )

    def change_revision():
        changed = replace(
            investigation,
            metadata=replace(investigation.metadata, updated_at="2026-08-10T16:00:00Z"),
        )
        repository.save(changed, expected_revision=1)

    with pytest.raises(InvestigationChangedDuringHandoffError):
        InvestigationHandoffService(
            repository, before_finalize=change_revision
        ).export(investigation.investigation_id, analysis, tmp_path / "conflict")
    assert not (tmp_path / "conflict" / investigation.investigation_id).exists()
    assert repository.load_record(investigation.investigation_id).revision == 2


def test_export_is_read_only_for_repository_analysis_and_source_artifacts(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    repository.save(investigation)
    repo_before = repository_bytes(tmp_path / "workspace")
    analysis_before = deepcopy(analysis)
    artifacts_before = {key: path.read_bytes() for key, path in analysis.artifacts.items()}

    InvestigationHandoffService(repository).export(
        investigation.investigation_id, analysis, tmp_path / "handoffs"
    )

    assert repository_bytes(tmp_path / "workspace") == repo_before
    assert repository.load_record(investigation.investigation_id).revision == 1
    assert analysis == analysis_before
    assert {key: path.read_bytes() for key, path in analysis.artifacts.items()} == artifacts_before


def test_validator_detects_digest_missing_schema_and_unexpected_file(tmp_path):
    result, *_ = build_export(tmp_path / "digest")
    (result.output_path / "evidence_index.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(HandoffArtifactDigestMismatchError):
        validate_handoff_bundle(result.output_path)

    result, *_ = build_export(tmp_path / "missing")
    (result.output_path / "annotations.json").unlink()
    with pytest.raises(HandoffBundleValidationError):
        validate_handoff_bundle(result.output_path)

    result, *_ = build_export(tmp_path / "schema")
    manifest = read_json(result.manifest_path)
    manifest["schema_version"] = "2.0"
    result.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(UnsupportedHandoffSchemaError):
        validate_handoff_bundle(result.output_path)

    result, *_ = build_export(tmp_path / "extra")
    (result.output_path / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(HandoffBundleValidationError):
        validate_handoff_bundle(result.output_path)


@pytest.mark.parametrize("kind", ["manifest", "hypothesis", "decision", "timeline"])
def test_validator_detects_reference_integrity_failures(tmp_path, kind):
    result, *_ = build_export(tmp_path)
    if kind == "manifest":
        manifest = read_json(result.manifest_path)
        manifest["investigation_id"] = "INV-OTHER"
        result.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    elif kind == "hypothesis":
        payload = read_json(result.output_path / "hypotheses.json")
        payload["hypotheses"][0]["supporting_evidence_ids"] = ["EVIDENCE-MISSING"]
        rewrite_component(result.output_path, "hypotheses.json", payload)
    elif kind == "decision":
        payload = read_json(result.output_path / "decisions.json")
        payload["decisions"][0]["related_hypothesis_ids"] = ["HYP-MISSING"]
        rewrite_component(result.output_path, "decisions.json", payload)
    else:
        payload = read_json(result.output_path / "timeline.json")
        payload["timed_entries"][0]["related_decision_ids"] = ["DEC-MISSING"]
        rewrite_component(result.output_path, "timeline.json", payload)
    with pytest.raises(HandoffReferenceIntegrityError):
        validate_handoff_bundle(result.output_path)


def test_architecture_uses_read_only_query_layer_without_pipeline_execution():
    source = Path("soc_forge/investigations/handoff.py").read_text(encoding="utf-8")
    assert "InvestigationQueryContext" in source
    assert "InvestigationTimelineService" in source
    for forbidden in (
        "run_analysis(", "run_analysis_for_events(", "run_rules(",
        "correlate_alerts(", "workspace_service", "evidence_service",
        "reasoning_service", ".save(", ".delete(",
    ):
        assert forbidden not in source


def _finding_investigation(analysis):
    investigation = build_query_investigation(analysis)
    evidence_id = next(
        item.reference_id for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    finding = InvestigationFinding(
        finding_id="FIND-001",
        investigation_id=investigation.investigation_id,
        title="Security control tampering",
        conclusion="Analyst review links selected evidence to control tampering.",
        status="substantiated",
        confidence="high",
        author="alice",
        created_at="2026-08-12T10:00:00Z",
        updated_at="2026-08-12T10:05:00Z",
        evidence_ids=(evidence_id,),
        hypothesis_ids=(investigation.hypotheses[0].hypothesis_id,),
        decision_ids=(investigation.decisions[0].decision_id,),
        attack_tactics=("Defense Evasion",),
        attack_techniques=("T1562.001",),
        limitations=("Command-line visibility may be incomplete.",),
    )
    return replace(investigation, findings=(finding,))


def test_findings_component_preview_manifest_and_read_only_export(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = _finding_investigation(analysis)
    result, _analysis, _investigation, repository, workspace = build_export(
        tmp_path, investigation=investigation, analysis=analysis
    )
    payload = read_json(result.output_path / "findings.json")
    manifest = read_json(result.manifest_path)
    preview = InvestigationHandoffService(repository).preview("INV-QUERY", analysis)

    assert payload["findings"] == [investigation.findings[0].to_dict()]
    entry = next(item for item in manifest["files"] if item["filename"] == "findings.json")
    data = (result.output_path / "findings.json").read_bytes()
    assert entry["logical_type"] == "component:findings"
    assert entry["size"] == len(data)
    assert entry["sha256"] == sha256(data).hexdigest()
    assert preview.finding_count == 1
    assert preview.findings[0].attribution == "analyst"
    assert preview.findings[0].conclusion == investigation.findings[0].conclusion
    assert preview.findings[0].evidence_count == 1
    assert preview.findings[0].evidence_ids == investigation.findings[0].evidence_ids
    assert preview.findings[0].hypothesis_ids == investigation.findings[0].hypothesis_ids
    assert preview.findings[0].decision_ids == investigation.findings[0].decision_ids
    assert repository.load_record("INV-QUERY").revision == 1
    assert repository_bytes(workspace)["INV-QUERY.json"]


@pytest.mark.parametrize(
    ("kind", "error"),
    [
        ("malformed", HandoffBundleValidationError),
        ("status", HandoffBundleValidationError),
        ("confidence", HandoffBundleValidationError),
        ("evidence", HandoffReferenceIntegrityError),
        ("hypothesis", HandoffReferenceIntegrityError),
        ("decision", HandoffReferenceIntegrityError),
        ("duplicate", HandoffBundleValidationError),
        ("logical", HandoffBundleValidationError),
    ],
)
def test_findings_component_validation_rejects_invalid_content(tmp_path, kind, error):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = _finding_investigation(analysis)
    result, *_ = build_export(tmp_path, investigation=investigation, analysis=analysis)
    payload = read_json(result.output_path / "findings.json")
    if kind == "malformed":
        payload["findings"] = ["bad"]
    elif kind in {"status", "confidence"}:
        payload["findings"][0][kind] = "invalid"
    elif kind in {"evidence", "hypothesis", "decision"}:
        payload["findings"][0][f"{kind}_ids"] = [f"{kind.upper()}-MISSING"]
    elif kind == "duplicate":
        payload["findings"].append(payload["findings"][0])
    else:
        manifest = read_json(result.manifest_path)
        next(item for item in manifest["files"] if item["filename"] == "findings.json")["logical_type"] = "wrong"
        result.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with pytest.raises(error):
            validate_handoff_bundle(result.output_path)
        return
    rewrite_component(result.output_path, "findings.json", payload)
    with pytest.raises(error):
        validate_handoff_bundle(result.output_path)


def test_legacy_schema_one_bundle_without_findings_remains_valid(tmp_path):
    result, *_ = build_export(tmp_path)
    (result.output_path / "findings.json").unlink()
    manifest = read_json(result.manifest_path)
    manifest["schema_version"] = "1.0"
    manifest["files"] = [
        item for item in manifest["files"] if item["filename"] != "findings.json"
    ]
    result.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert validate_handoff_bundle(result.output_path) is True
