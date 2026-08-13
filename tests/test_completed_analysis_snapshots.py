import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.handoff import InvestigationHandoffService
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.investigations.snapshots import (
    CompletedAnalysisSnapshotStore,
    InvalidSnapshotIdError,
    SnapshotConflictError,
    SnapshotIntegrityError,
    SnapshotNotFoundError,
    SnapshotProvenanceMismatchError,
    SnapshotValidationError,
    UnsupportedSnapshotSchemaError,
)


def artifact_hashes(analysis):
    return {
        key: sha256(Path(path).read_bytes()).hexdigest()
        for key, path in analysis.artifacts.items()
    }


def build_snapshot(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    store = CompletedAnalysisSnapshotStore(tmp_path)
    source_id = AnalysisEvidenceCatalog().source_analysis_id(analysis)
    return analysis, store, source_id


def rewrite_manifest(snapshot_path, mutate):
    path = snapshot_path / "manifest.json"
    manifest = json.loads(path.read_text())
    mutate(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def test_snapshot_publication_and_load_preserve_analysis_semantics(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    before = deepcopy(analysis)
    before_artifacts = artifact_hashes(analysis)

    published = store.publish(analysis)
    loaded = store.load(source_id)

    assert published.created is True
    assert published.path == tmp_path / "analysis_snapshots" / source_id
    assert published.manifest_path.is_file()
    assert loaded.input_name == analysis.input_name
    assert loaded.event_count == analysis.event_count
    assert loaded.events == analysis.events
    assert loaded.alerts == analysis.alerts
    assert loaded.cases == analysis.cases
    assert loaded.hunt_findings == analysis.hunt_findings
    assert loaded.reconstructions == analysis.reconstructions
    assert loaded.correlations == analysis.correlations
    assert loaded.risk_summary == analysis.risk_summary
    assert loaded.ingest_diagnostics == analysis.ingest_diagnostics
    assert sorted(loaded.artifacts) == sorted(analysis.artifacts)
    assert AnalysisEvidenceCatalog().source_analysis_id(loaded) == source_id
    assert analysis == before
    assert artifact_hashes(analysis) == before_artifacts


def test_snapshot_manifest_is_bounded_complete_and_hash_verified(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    manifest = json.loads(published.manifest_path.read_text())
    rendered = published.manifest_path.read_text()

    assert manifest["schema_version"] == "1.0"
    assert manifest["source_analysis_id"] == source_id
    assert manifest["event_count"] == len(analysis.events)
    assert manifest["alert_count"] == len(analysis.alerts)
    assert manifest["case_count"] == len(analysis.cases)
    assert manifest["reconstruction_count"] == len(analysis.reconstructions)
    assert manifest["logical_artifact_keys"] == sorted(analysis.artifacts)
    assert manifest["cryptographic_authenticity"] is False
    assert "sensitive" in manifest["sensitive_data_warning"].lower()
    assert str(tmp_path) not in rendered
    for item in manifest["files"]:
        data = (published.path / item["filename"]).read_bytes()
        assert item["size"] == len(data)
        assert item["sha256"] == sha256(data).hexdigest()


def test_identical_snapshot_publication_is_idempotent(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    first = store.publish(analysis)
    before = {
        path.relative_to(first.path): path.read_bytes()
        for path in first.path.rglob("*")
        if path.is_file()
    }

    second = store.publish(analysis)

    assert second.source_analysis_id == source_id
    assert second.created is False
    assert {
        path.relative_to(second.path): path.read_bytes()
        for path in second.path.rglob("*")
        if path.is_file()
    } == before


def test_corrupt_existing_snapshot_cannot_be_republished(tmp_path):
    analysis, store, _source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    (published.path / "events.json").write_text("[]\n")

    with pytest.raises((SnapshotIntegrityError, SnapshotConflictError)):
        store.publish(analysis)


@pytest.mark.parametrize(
    ("filename", "replacement"),
    [
        ("events.json", "[]\n"),
        ("alerts.json", "[]\n"),
        ("cases.json", None),
    ],
)
def test_corrupt_or_missing_required_collection_is_rejected(
    tmp_path, filename, replacement
):
    analysis, store, source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    path = published.path / filename
    if replacement is None:
        path.unlink()
    else:
        path.write_text(replacement)

    with pytest.raises((SnapshotIntegrityError, SnapshotValidationError)):
        store.load(source_id)


def test_unsupported_schema_and_manifest_identity_are_rejected(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    rewrite_manifest(published.path, lambda value: value.update(schema_version="2.0"))
    with pytest.raises(UnsupportedSnapshotSchemaError):
        store.load(source_id)

    shutil_target = tmp_path / "second"
    analysis2 = build_query_analysis(shutil_target / "analysis")
    store2 = CompletedAnalysisSnapshotStore(shutil_target)
    source2 = AnalysisEvidenceCatalog().source_analysis_id(analysis2)
    published2 = store2.publish(analysis2)
    rewrite_manifest(
        published2.path,
        lambda value: value.update(source_analysis_id="analysis-" + "0" * 20),
    )
    with pytest.raises(SnapshotProvenanceMismatchError):
        store2.load(source2)


@pytest.mark.parametrize(
    "source_id",
    ["../analysis-" + "0" * 20, "/tmp/analysis-" + "0" * 20, "analysis-bad"],
)
def test_unsafe_snapshot_ids_are_rejected(tmp_path, source_id):
    store = CompletedAnalysisSnapshotStore(tmp_path)
    with pytest.raises(InvalidSnapshotIdError):
        store.load(source_id)


def test_missing_snapshot_is_controlled(tmp_path):
    store = CompletedAnalysisSnapshotStore(tmp_path)
    with pytest.raises(SnapshotNotFoundError):
        store.load("analysis-" + "0" * 20)


def test_snapshot_target_symlink_is_rejected(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    store.root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.root / source_id).symlink_to(outside, target_is_directory=True)

    with pytest.raises(SnapshotConflictError):
        store.publish(analysis)


def test_loaded_snapshot_validates_original_investigation_references(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    investigation = build_query_investigation(analysis)
    original = InvestigationQueryContext(analysis, investigation)
    store.publish(analysis)

    loaded = store.load(source_id)
    recovered = InvestigationQueryContext(loaded, investigation)

    assert recovered.source_analysis_id == original.source_analysis_id
    assert tuple(recovered.sources) == tuple(original.sources)


def test_restart_recovery_restores_query_evidence_and_handoff_without_mutation(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    current = service.get_investigation(investigation.investigation_id)
    repository_file = next((tmp_path / "workspace" / "investigations").glob("*.json"))
    repository_before = repository_file.read_bytes()
    artifacts_before = artifact_hashes(analysis)
    original_context = InvestigationQueryContext(analysis, investigation)
    original_timeline = InvestigationTimelineService().timeline(original_context)
    pivot_service = InvestigationPivotService()
    original_entities = pivot_service.related_entities(
        original_context, "host", "WS-LAB-01"
    )
    selected_reference = next(
        item for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    original_candidate = original_context.evidence_catalog.get_candidate(
        analysis, selected_reference.reference_id
    )
    store.publish(analysis)

    restarted_store = CompletedAnalysisSnapshotStore(tmp_path)
    restarted_repository = InvestigationRepository(tmp_path / "workspace")
    restarted_service = InvestigationWorkspaceService(restarted_repository)
    restarted_current = restarted_service.get_investigation(investigation.investigation_id)
    recovered = restarted_store.load(source_id)
    recovered_context = InvestigationQueryContext(
        recovered, restarted_current.investigation
    )
    recovered_timeline = InvestigationTimelineService().timeline(recovered_context)
    recovered_entities = pivot_service.related_entities(
        recovered_context, "host", "WS-LAB-01"
    )
    recovered_candidate = recovered_context.evidence_catalog.get_candidate(
        recovered, selected_reference.reference_id
    )
    handoff = InvestigationHandoffService(restarted_repository)
    preview = handoff.preview(investigation.investigation_id, recovered)
    exported = handoff.export(
        investigation.investigation_id,
        recovered,
        tmp_path / "handoff",
    )

    assert [item.entry_id for item in recovered_timeline.entries] == [
        item.entry_id for item in original_timeline.entries
    ]
    assert [item.entry_id for item in recovered_timeline.untimed_entries] == [
        item.entry_id for item in original_timeline.untimed_entries
    ]
    assert recovered_entities == original_entities
    assert recovered_candidate == original_candidate
    assert preview.source_analysis_id == source_id
    assert exported.validation_status == "valid"
    assert restarted_current.revision == current.revision
    assert repository_file.read_bytes() == repository_before
    assert artifact_hashes(analysis) == artifacts_before


def test_console_explicit_snapshot_recovery_activates_only_valid_analysis(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    investigation = build_query_investigation(analysis)
    store.publish(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    current = service.get_investigation(investigation.investigation_id)
    state = {"analysis": None}
    messages = []
    values = iter(["15", "0"])
    controller = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(service),
        workspace_service=service,
        analysis_provider=lambda: state["analysis"],
        workspace_root=tmp_path / "workspace",
        input_func=lambda _prompt="": next(values),
        output_func=messages.append,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
        snapshot_store=CompletedAnalysisSnapshotStore(tmp_path),
        analysis_activator=lambda result: state.update(analysis=result),
    )
    before = next((tmp_path / "workspace" / "investigations").glob("*.json")).read_bytes()

    returned = controller.workspace_loop(current)

    assert returned == current
    assert state["analysis"] is not None
    assert AnalysisEvidenceCatalog().source_analysis_id(state["analysis"]) == source_id
    assert any("Loaded completed analysis snapshot" in item for item in messages)
    assert next((tmp_path / "workspace" / "investigations").glob("*.json")).read_bytes() == before


def test_wrong_analysis_snapshot_cannot_satisfy_investigation(tmp_path):
    original, store, _source_id = build_snapshot(tmp_path / "original")
    investigation = build_query_investigation(original)
    different = build_query_analysis(tmp_path / "different")
    different.events[0]["timestamp"] = "2030-01-01T00:00:00Z"
    different_store = CompletedAnalysisSnapshotStore(tmp_path / "different-store")
    different_id = AnalysisEvidenceCatalog().source_analysis_id(different)
    different_store.publish(different)
    loaded = different_store.load(different_id)

    with pytest.raises(Exception):
        InvestigationQueryContext(loaded, investigation)

    assert loaded.cases[0]["case_id"] == original.cases[0]["case_id"]


def test_unlisted_snapshot_file_is_rejected(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    (published.path / "unexpected.txt").write_text("not inventoried")

    with pytest.raises(SnapshotValidationError):
        store.load(source_id)


def test_directory_and_manifest_source_ids_must_match(tmp_path):
    analysis, store, source_id = build_snapshot(tmp_path)
    published = store.publish(analysis)
    other_id = "analysis-" + "f" * 20
    published.path.rename(store.root / other_id)

    with pytest.raises(SnapshotProvenanceMismatchError):
        store.load(other_id)

    with pytest.raises(SnapshotNotFoundError):
        store.load(source_id)


def test_symlink_snapshot_root_is_rejected(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "store"
    root.mkdir()
    (root / "analysis_snapshots").symlink_to(outside, target_is_directory=True)
    store = CompletedAnalysisSnapshotStore(root)

    with pytest.raises(SnapshotValidationError):
        store.publish(analysis)
