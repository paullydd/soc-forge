from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from soc_forge.investigations.evidence_catalog import (
    AnalysisEvidenceCatalog,
    AmbiguousLegacyEvidenceIdentityError,
    EvidenceCandidateNotFoundError,
    UnsupportedEvidenceTypeError,
)
from soc_forge.investigations.evidence_models import (
    EvidenceCandidate,
    EvidenceDetails,
)
from soc_forge.investigations.evidence_service import (
    DuplicateEvidenceSelectionError,
    EvidenceOutsideScopeError,
    EvidenceProvenanceMismatchError,
    EvidenceSelectionNotFoundError,
    InvalidEvidenceClassificationError,
    InvalidEvidenceRationaleError,
    InvestigationEvidenceService,
)
from soc_forge.investigations.provenance import derive_legacy_analysis_provenance
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepository,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.pipeline import AnalysisResult


FIXED_TIME = "2026-08-05T12:00:00Z"


def build_analysis_result(tmp_path):
    event_one = {
        "record_id": "EVENT-001",
        "event_id": 4688,
        "timestamp": "2026-08-05T10:00:00Z",
        "host": "WS-LAB-01",
        "username": "alice",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc sensitive",
        "raw": {
            "host": "WS-LAB-01",
            "username": "alice",
            "command_line": "powershell.exe -enc sensitive",
        },
    }
    event_two = {
        "record_id": "EVENT-002",
        "event_id": 7045,
        "timestamp": "2026-08-05T10:05:00Z",
        "host": "WS-OTHER",
        "service_name": "ExpectedService",
    }
    alert_one = {
        "alert_id": "ALERT-001",
        "rule_id": "SOCF-021",
        "severity": "high",
        "title": "Security control tampering",
        "timestamp": "2026-08-05T10:00:00Z",
        "source_event_id": "EVENT-001",
        "details": {
            "host": "WS-LAB-01",
            "username": "alice",
            "command_line": "powershell.exe -enc sensitive",
        },
        "mitre": [{"id": "T1562.001", "tactic": "Defense Evasion"}],
    }
    alert_two = {
        "alert_id": "ALERT-002",
        "rule_id": "SOCF-020",
        "severity": "medium",
        "title": "Archive collection",
        "timestamp": "2026-08-05T10:05:00Z",
        "details": {"host": "WS-OTHER"},
    }
    case_one = {
        "case_id": "CASE-001",
        "title": "Security control investigation",
        "timestamp": "2026-08-05T10:00:00Z",
        "items": [deepcopy(alert_one)],
    }
    case_two = {
        "case_id": "CASE-002",
        "title": "Collection investigation",
        "timestamp": "2026-08-05T10:05:00Z",
        "items": [deepcopy(alert_two)],
    }
    reconstructions = [
        {
            "case_id": "CASE-001",
            "attack_path": [
                {
                    "step_no": 1,
                    "stage": "Defense Evasion",
                    "title": "Disable security controls",
                    "tactic": "Defense Evasion",
                    "technique": "Impair Defenses",
                    "timestamp": "2026-08-05T10:00:00Z",
                    "entities": {"host": "WS-LAB-01"},
                }
            ],
        },
        {"case_id": "CASE-002", "attack_path": []},
    ]
    artifacts = {
        "cases": tmp_path / "cases.json",
        "alerts": tmp_path / "alerts.json",
        "events": tmp_path / "events.jsonl",
        "reconstructions": tmp_path / "reconstructions.json",
    }
    return AnalysisResult(
        input_name="/unstable/path/evidence.jsonl",
        input_path=tmp_path / "evidence.jsonl",
        output_dir=tmp_path,
        alerts_path=artifacts["alerts"],
        report_path=None,
        cases_output_dir=tmp_path,
        hunts_path=None,
        reconstructions_path=artifacts["reconstructions"],
        events_path=artifacts["events"],
        event_count=2,
        events=[event_one, event_two],
        alerts=[alert_one, alert_two],
        legacy_alerts=[],
        yaml_alerts=[alert_one, alert_two],
        correlations={"total": 0, "by_rule": []},
        hunt_findings=[],
        risk_summary={"level": "high"},
        cases=[case_one, case_two],
        reconstructions=reconstructions,
        mitre_coverage=[],
        artifacts=artifacts,
        ingest_diagnostics=[],
    )


def build_services(tmp_path, analysis=None, case_ids=("CASE-001",)):
    analysis = analysis or build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    candidates = catalog.list_candidates(analysis)
    analysis_id = candidates[0].source_analysis_id
    repository = InvestigationRepository(tmp_path / "workspace")
    workspace = InvestigationWorkspaceService(
        repository,
        clock=lambda: "2026-08-05T12:01:00Z",
    )
    created = workspace.create_investigation(
        investigation_id="INVESTIGATION-001",
        title="Evidence investigation",
        analysis_id=analysis_id,
        case_ids=case_ids,
        artifact_keys=("alerts", "cases", "events", "reconstructions"),
        created_at="2026-08-05T11:59:00Z",
    )
    service = InvestigationEvidenceService(
        workspace,
        clock=lambda: FIXED_TIME,
    )
    return analysis, catalog, service, workspace, repository, created


def candidate_of_type(catalog, analysis, evidence_type, case_id="CASE-001"):
    return next(
        item
        for item in catalog.list_candidates(analysis, case_ids=(case_id,))
        if item.evidence_type == evidence_type
    )

@pytest.mark.parametrize("evidence_type", ["event", "alert", "case", "reconstruction_step"])
def test_supported_evidence_ids_are_deterministic(evidence_type, tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()

    first = candidate_of_type(catalog, analysis, evidence_type)
    second = candidate_of_type(catalog, deepcopy(analysis), evidence_type)

    assert first.evidence_id == second.evidence_id
    assert first.evidence_id.startswith("evidence-")
    assert len(first.evidence_id) == 33


def test_same_source_id_across_types_is_unambiguous(tmp_path):
    analysis = build_analysis_result(tmp_path)
    analysis.events[0]["record_id"] = "SHARED-ID"
    analysis.alerts[0]["alert_id"] = "SHARED-ID"
    analysis.cases[0]["items"][0]["alert_id"] = "SHARED-ID"
    catalog = AnalysisEvidenceCatalog()

    event = next(
        item for item in catalog.list_candidates(analysis)
        if item.evidence_type == "event" and item.source_id == "SHARED-ID"
    )
    alert = next(
        item for item in catalog.list_candidates(analysis)
        if item.evidence_type == "alert" and item.source_id == "SHARED-ID"
    )

    assert event.source_id == alert.source_id == "SHARED-ID"
    assert event.evidence_id != alert.evidence_id


def test_paths_and_filter_order_do_not_affect_candidate_ids(tmp_path):
    first = build_analysis_result(tmp_path / "first")
    second = deepcopy(first)
    second.input_name = r"C:\moved\evidence.jsonl"
    second.input_path = Path("/moved/evidence.jsonl")
    second.output_dir = Path("/moved/out")
    second.artifacts = {
        key: Path("/different") / value.name
        for key, value in reversed(tuple(first.artifacts.items()))
    }
    catalog = AnalysisEvidenceCatalog()

    first_ids = {
        item.evidence_id
        for item in catalog.list_candidates(
            first,
            case_ids=("CASE-001", "CASE-002"),
            evidence_types=("event", "alert", "case", "reconstruction_step"),
        )
    }
    second_ids = {
        item.evidence_id
        for item in catalog.list_candidates(
            second,
            case_ids=("CASE-002", "CASE-001"),
            evidence_types=("case", "alert", "reconstruction_step", "event"),
        )
    }

    assert first_ids == second_ids


def test_event_without_native_id_uses_canonical_content_identity(tmp_path):
    analysis = build_analysis_result(tmp_path)
    analysis.events[0].pop("record_id")
    changed = deepcopy(analysis)
    changed.events[0]["process_name"] = "cmd.exe"
    catalog = AnalysisEvidenceCatalog()

    first = next(
        item for item in catalog.list_candidates(analysis)
        if item.evidence_type == "event" and item.timestamp == "2026-08-05T10:00:00Z"
    )
    second = next(
        item for item in catalog.list_candidates(changed)
        if item.evidence_type == "event" and item.timestamp == "2026-08-05T10:00:00Z"
    )

    assert first.source_id.startswith("event-")
    assert first.evidence_id != second.evidence_id


def test_catalog_order_is_deterministic_and_unknown_or_unsupported_fails(tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()

    candidates = catalog.list_candidates(analysis)
    assert candidates == tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.timestamp is None,
                item.timestamp or "",
                item.evidence_type,
                item.evidence_id,
            ),
        )
    )

    with pytest.raises(EvidenceCandidateNotFoundError, match="missing"):
        catalog.get_candidate(analysis, "missing")
    with pytest.raises(UnsupportedEvidenceTypeError, match="report"):
        catalog.list_candidates(analysis, evidence_types=("report",))


def test_case_scoped_discovery_uses_only_proven_relationships(tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()

    scoped = catalog.list_candidates(analysis, case_ids=("CASE-001",))
    by_type = {}
    for candidate in scoped:
        by_type.setdefault(candidate.evidence_type, []).append(candidate)

    assert [item.source_id for item in by_type["case"]] == ["CASE-001"]
    assert [item.source_id for item in by_type["alert"]] == ["ALERT-001"]
    assert [item.source_id for item in by_type["event"]] == ["EVENT-001"]
    assert len(by_type["reconstruction_step"]) == 1
    assert "ALERT-002" not in {item.source_id for item in scoped}
    assert "EVENT-002" not in {item.source_id for item in scoped}


def test_untraceable_event_is_not_inferred_and_limitation_is_exposed(tmp_path):
    analysis = build_analysis_result(tmp_path)
    analysis.alerts[0].pop("source_event_id")
    analysis.cases[0]["items"][0].pop("source_event_id")
    catalog = AnalysisEvidenceCatalog()

    scoped = catalog.list_candidates(analysis, case_ids=("CASE-001",))
    alert = next(item for item in scoped if item.evidence_type == "alert")

    assert all(item.evidence_type != "event" for item in scoped)
    assert "not explicitly available" in alert.limitation_reason


def test_multi_case_scope_is_deduplicated_and_deterministic(tmp_path):
    analysis = build_analysis_result(tmp_path)
    analysis.cases[1]["items"].append(deepcopy(analysis.alerts[0]))
    catalog = AnalysisEvidenceCatalog()

    candidates = catalog.list_candidates(
        analysis,
        case_ids=("CASE-002", "CASE-001"),
    )
    ids = [item.evidence_id for item in candidates]
    shared_alert = next(
        item for item in candidates if item.source_id == "ALERT-001"
    )

    assert len(ids) == len(set(ids))
    assert shared_alert.case_ids == ("CASE-001", "CASE-002")


def test_field_provenance_and_sensitive_details_are_compact(tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    event = candidate_of_type(catalog, analysis, "event")
    alert = candidate_of_type(catalog, analysis, "alert")
    case = candidate_of_type(catalog, analysis, "case")
    reconstruction = candidate_of_type(
        catalog, analysis, "reconstruction_step"
    )

    event_kinds = {item.source_kind for item in event.field_provenance}
    alert_fields = {item.field_name: item for item in alert.field_provenance}

    assert {"raw_source", "normalized_event"}.issubset(event_kinds)
    assert alert_fields["rule_id"].source_kind == "rule_interpretation"
    assert all(
        item.source_kind == "case_context"
        for item in case.field_provenance
    )
    assert all(
        item.source_kind == "reconstruction_context"
        for item in reconstruction.field_provenance
    )
    assert "command_line" in alert.sensitive_fields
    assert not hasattr(alert, "payload")
    assert "rationale" not in {item.field_name for item in alert.field_provenance}

    details = catalog.resolve_details(analysis, alert.evidence_id)
    assert isinstance(details, EvidenceDetails)
    assert any(item.sensitive for item in details.fields)
    assert all(len(item.value) <= 2048 for item in details.fields)


def test_attack_technique_field_renders_readable_label_not_raw_json(tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    alert = candidate_of_type(catalog, analysis, "alert")

    details = catalog.resolve_details(analysis, alert.evidence_id)
    attack_technique = next(
        item for item in details.fields if item.field_name == "attack_technique"
    )

    assert attack_technique.value == "T1562.001 (Defense Evasion)"
    assert "{" not in attack_technique.value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            [{"tactic": "Credential Access", "technique": "Brute Force: Password Spraying", "technique_id": "T1110.003"}],
            "T1110.003 - Brute Force: Password Spraying (Credential Access)",
        ),
        ([{"id": "T1562.001", "tactic": "Defense Evasion"}], "T1562.001 (Defense Evasion)"),
        (
            [
                {"technique_id": "T1078", "technique": "Valid Accounts"},
                {"technique_id": "T1070.001", "technique": "Clear Windows Event Logs"},
            ],
            "T1078 - Valid Accounts; T1070.001 - Clear Windows Event Logs",
        ),
        (
            # SOCF-007: same technique legitimately mapped to two tactics -
            # both must remain visible, not silently deduplicated away.
            [
                {"tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
                {"tactic": "Privilege Escalation", "technique": "Create Account", "id": "T1136"},
            ],
            "T1136 - Create Account (Persistence); T1136 - Create Account (Privilege Escalation)",
        ),
        ([], None),
        ([{"tactic": "Defense Evasion"}], "Defense Evasion"),
        ("T1562.001", None),
    ],
)
def test_render_mitre_value_handles_real_and_degenerate_shapes(value, expected):
    assert AnalysisEvidenceCatalog._render_mitre_value(value) == expected


def test_catalog_is_read_only_and_does_not_open_artifacts(tmp_path):
    analysis = build_analysis_result(tmp_path)
    snapshot = deepcopy(analysis)
    catalog = AnalysisEvidenceCatalog()

    catalog.list_candidates(analysis, case_ids=("CASE-001",))
    alert = candidate_of_type(catalog, analysis, "alert")
    catalog.resolve_details(analysis, alert.evidence_id)

    assert analysis == snapshot
    assert all(not path.exists() for path in analysis.artifacts.values())


@pytest.mark.parametrize(
    "classification",
    ["supporting", "contradicting", "context"],
)
def test_select_evidence_classifications_persist_reference_metadata(
    classification,
    tmp_path,
):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    candidate_snapshot = deepcopy(candidate)
    analysis_snapshot = deepcopy(analysis)

    result = service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification=classification,
        rationale="Relevant to the current investigation.",
        author="alice",
        expected_revision=created.revision,
    )

    selected = next(
        item
        for item in result.investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    assert result.revision == 2
    assert selected.reference_id == candidate.evidence_id
    assert selected.classification == classification
    assert selected.rationale == "Relevant to the current investigation."
    assert selected.selected_by == "alice"
    assert selected.selected_at == FIXED_TIME
    assert selected.source_analysis_id == result.investigation.analysis_id
    assert selected.scope_case_ids == ("CASE-001",)
    assert selected.provenance_fields
    assert repository.load("INVESTIGATION-001") == result.investigation
    assert candidate == candidate_snapshot
    assert analysis == analysis_snapshot


@pytest.mark.parametrize(
    ("classification", "rationale", "error_type"),
    [
        ("certainty", "Reason", InvalidEvidenceClassificationError),
        ("supporting", "", InvalidEvidenceRationaleError),
        ("supporting", "   ", InvalidEvidenceRationaleError),
    ],
)
def test_invalid_selection_fields_do_not_save(
    classification,
    rationale,
    error_type,
    tmp_path,
):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    before = repository.load_record("INVESTIGATION-001")

    with pytest.raises(error_type):
        service.select_evidence(
            "INVESTIGATION-001",
            candidate,
            classification=classification,
            rationale=rationale,
            author="alice",
            expected_revision=created.revision,
        )

    assert repository.load_record("INVESTIGATION-001") == before


def test_provenance_mismatch_and_outside_scope_are_rejected(tmp_path):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    mismatched = replace(candidate, source_analysis_id="analysis-other")
    outside = candidate_of_type(
        catalog,
        analysis,
        "alert",
        case_id="CASE-002",
    )
    before = repository.load_record("INVESTIGATION-001")

    with pytest.raises(EvidenceProvenanceMismatchError, match="analysis-other"):
        service.select_evidence(
            "INVESTIGATION-001",
            mismatched,
            classification="context",
            rationale="Mismatch",
            author="alice",
            expected_revision=created.revision,
        )
    with pytest.raises(EvidenceOutsideScopeError, match="outside"):
        service.select_evidence(
            "INVESTIGATION-001",
            outside,
            classification="context",
            rationale="Outside",
            author="alice",
            expected_revision=created.revision,
        )

    assert repository.load_record("INVESTIGATION-001") == before


def test_duplicate_selection_fails_without_incrementing_revision(tmp_path):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    selected = service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="supporting",
        rationale="Initial rationale",
        author="alice",
        expected_revision=created.revision,
    )

    with pytest.raises(DuplicateEvidenceSelectionError, match=candidate.evidence_id):
        service.select_evidence(
            "INVESTIGATION-001",
            candidate,
            classification="context",
            rationale="Duplicate",
            author="alice",
            expected_revision=selected.revision,
        )

    assert repository.load_record("INVESTIGATION-001").revision == 2


def test_update_rationale_and_classification_then_remove(tmp_path):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    selected = service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="supporting",
        rationale="Initial rationale",
        author="alice",
        expected_revision=created.revision,
    )

    updated = service.update_evidence_rationale(
        "INVESTIGATION-001",
        candidate.evidence_id,
        classification="contradicting",
        rationale="Updated rationale",
        author="bob",
        expected_revision=selected.revision,
    )
    reference = next(
        item
        for item in updated.investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    assert updated.revision == 3
    assert reference.classification == "contradicting"
    assert reference.rationale == "Updated rationale"
    assert reference.selected_by == "bob"
    assert reference.selected_at == FIXED_TIME
    assert reference.selection_updated_at == FIXED_TIME

    removed = service.remove_evidence(
        "INVESTIGATION-001",
        candidate.evidence_id,
        expected_revision=updated.revision,
    )
    assert removed.revision == 4
    assert all(
        item.origin == "scope"
        for item in removed.investigation.evidence_references
    )
    assert repository.load("INVESTIGATION-001") == removed.investigation


def test_missing_selection_and_stale_revision_fail(tmp_path):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")

    with pytest.raises(EvidenceSelectionNotFoundError, match="missing"):
        service.remove_evidence(
            "INVESTIGATION-001",
            "missing",
            expected_revision=created.revision,
        )

    selected = service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="context",
        rationale="Context",
        author="alice",
        expected_revision=created.revision,
    )
    with pytest.raises(InvestigationConflictError):
        service.update_evidence_rationale(
            "INVESTIGATION-001",
            candidate.evidence_id,
            rationale="Stale update",
            expected_revision=created.revision,
        )

    assert selected.revision == 2
    assert repository.load_record("INVESTIGATION-001").revision == 2


def test_two_service_instances_share_selection_state_and_revision(tmp_path):
    analysis, catalog, first, workspace, repository, created = build_services(tmp_path)
    second_workspace = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace"),
        clock=lambda: "2026-08-05T12:02:00Z",
    )
    second = InvestigationEvidenceService(
        second_workspace,
        clock=lambda: "2026-08-05T12:03:00Z",
    )
    candidate = candidate_of_type(catalog, analysis, "alert")

    selected = first.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="context",
        rationale="Shared state",
        author="alice",
        expected_revision=created.revision,
    )
    observed = second_workspace.get_investigation("INVESTIGATION-001")
    updated = second.update_evidence_rationale(
        "INVESTIGATION-001",
        candidate.evidence_id,
        rationale="Observed and updated",
        expected_revision=observed.revision,
    )

    assert observed == selected
    assert updated.revision == 3
    assert repository.load_record("INVESTIGATION-001").revision == 3


def test_persisted_selection_contains_no_source_payload_or_analyst_provenance(tmp_path):
    analysis, catalog, service, _, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="supporting",
        rationale="Analyst-owned rationale",
        author="alice",
        expected_revision=created.revision,
    )

    payload = repository.load("INVESTIGATION-001").to_dict()
    selected = next(
        item for item in payload["evidence_references"]
        if item["origin"] == "analyst_selection"
    )

    assert "payload" not in selected
    assert "details" not in selected
    assert "command_line" not in selected
    assert selected["rationale"] == "Analyst-owned rationale"
    assert "rationale" not in selected["provenance_fields"]


def test_scope_references_remain_distinct_from_analyst_selection(tmp_path):
    _, _, _, _, _, created = build_services(tmp_path)

    scope = created.investigation.evidence_references

    assert scope
    assert all(item.origin == "scope" for item in scope)
    assert all(item.classification is None for item in scope)
    assert all(item.rationale is None for item in scope)


def test_candidate_is_frozen(tmp_path):
    analysis = build_analysis_result(tmp_path)
    candidate = candidate_of_type(AnalysisEvidenceCatalog(), analysis, "alert")

    with pytest.raises(FrozenInstanceError):
        candidate.title = "changed"


@pytest.mark.parametrize(
    "collection_name",
    ["events", "alerts", "cases", "reconstructions"],
)
def test_completed_analysis_collection_order_does_not_change_identity(
    tmp_path, collection_name
):
    original = build_analysis_result(tmp_path)
    reordered = deepcopy(original)
    setattr(reordered, collection_name, list(reversed(getattr(reordered, collection_name))))
    catalog = AnalysisEvidenceCatalog()

    assert catalog.source_analysis_id(original) == catalog.source_analysis_id(reordered)
    assert {
        item.evidence_id for item in catalog.list_candidates(original)
    } == {
        item.evidence_id for item in catalog.list_candidates(reordered)
    }


def test_rule_and_artifact_order_do_not_change_identity(tmp_path):
    original = build_analysis_result(tmp_path)
    reordered = deepcopy(original)
    reordered.alerts = list(reversed(reordered.alerts))
    reordered.artifacts = dict(reversed(tuple(reordered.artifacts.items())))
    catalog = AnalysisEvidenceCatalog()

    assert catalog.source_analysis_id(original) == catalog.source_analysis_id(reordered)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda result: result.events[0].update({"command_line": "changed"}),
        lambda result: result.alerts[0].update({"severity": "critical"}),
        lambda result: result.cases[0]["items"].append({"rule_id": "SOCF-022"}),
        lambda result: result.reconstructions[0]["attack_path"][0].update(
            {"stage": "Changed stage"}
        ),
    ],
)
def test_material_completed_analysis_changes_change_identity(tmp_path, mutator):
    original = build_analysis_result(tmp_path)
    changed = deepcopy(original)
    mutator(changed)
    catalog = AnalysisEvidenceCatalog()

    assert catalog.source_analysis_id(original) != catalog.source_analysis_id(changed)


def test_order_inside_one_analysis_member_remains_meaningful(tmp_path):
    original = build_analysis_result(tmp_path)
    original.events[0]["ordered_values"] = ["first", "second"]
    changed = deepcopy(original)
    changed.events[0]["ordered_values"].reverse()
    catalog = AnalysisEvidenceCatalog()

    assert catalog.source_analysis_id(original) != catalog.source_analysis_id(changed)


@pytest.mark.parametrize(
    "field,first,second",
    [
        ("host", "WS-ONE", "WS-TWO"),
        ("channel", "Security", "System"),
        ("provider", "Microsoft-Windows-Security-Auditing", "Sysmon"),
    ],
)
def test_same_event_record_id_with_different_context_stays_distinct(
    tmp_path, field, first, second
):
    analysis = build_analysis_result(tmp_path)
    analysis.events[0][field] = first
    duplicate = deepcopy(analysis.events[0])
    duplicate[field] = second
    analysis.events.append(duplicate)
    candidates = [
        item for item in AnalysisEvidenceCatalog().list_candidates(analysis)
        if item.evidence_type == "event" and item.source_id == "EVENT-001"
    ]

    assert len(candidates) == 2
    assert len({item.evidence_id for item in candidates}) == 2


def test_identical_duplicate_event_is_deliberately_deduplicated(tmp_path):
    analysis = build_analysis_result(tmp_path)
    analysis.events.append(deepcopy(analysis.events[0]))
    candidates = [
        item for item in AnalysisEvidenceCatalog().list_candidates(analysis)
        if item.evidence_type == "event" and item.source_id == "EVENT-001"
    ]

    assert len(candidates) == 1


def test_same_alert_id_with_different_rule_stays_distinct(tmp_path):
    analysis = build_analysis_result(tmp_path)
    duplicate = deepcopy(analysis.alerts[0])
    duplicate["rule_id"] = "SOCF-022"
    analysis.alerts.append(duplicate)
    candidates = [
        item for item in AnalysisEvidenceCatalog().list_candidates(analysis)
        if item.evidence_type == "alert" and item.source_id == "ALERT-001"
    ]

    assert len(candidates) == 2
    assert len({item.evidence_id for item in candidates}) == 2


def test_duplicate_case_id_with_different_content_stays_distinct(tmp_path):
    analysis = build_analysis_result(tmp_path)
    duplicate = deepcopy(analysis.cases[0])
    duplicate["title"] = "Different case content"
    analysis.cases.append(duplicate)
    candidates = [
        item for item in AnalysisEvidenceCatalog().list_candidates(analysis)
        if item.evidence_type == "case" and item.source_id == "CASE-001"
    ]

    assert len(candidates) == 2
    assert len({item.evidence_id for item in candidates}) == 2


def test_legacy_evidence_id_resolves_only_when_unambiguous(tmp_path):
    analysis = build_analysis_result(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    artifact_keys = tuple(sorted(analysis.artifacts))
    legacy = derive_legacy_analysis_provenance(
        normalized_input_name="evidence.jsonl",
        events=analysis.events,
        alerts=analysis.alerts,
        cases=analysis.cases,
        reconstructions=analysis.reconstructions,
        artifact_keys=artifact_keys,
    )
    legacy_id = catalog._legacy_evidence_id(legacy.source_analysis_id, "event", "EVENT-001")

    assert catalog.get_candidate(analysis, legacy_id).source_id == "EVENT-001"

    duplicate = deepcopy(analysis.events[0])
    duplicate["host"] = "WS-COLLISION"
    analysis.events.append(duplicate)
    colliding_legacy = derive_legacy_analysis_provenance(
        normalized_input_name="evidence.jsonl",
        events=analysis.events,
        alerts=analysis.alerts,
        cases=analysis.cases,
        reconstructions=analysis.reconstructions,
        artifact_keys=artifact_keys,
    )
    colliding_id = catalog._legacy_evidence_id(
        colliding_legacy.source_analysis_id, "event", "EVENT-001"
    )
    with pytest.raises(AmbiguousLegacyEvidenceIdentityError, match="ambiguous"):
        catalog.get_candidate(analysis, colliding_id)


def test_reconstruction_step_identity_includes_owning_case(tmp_path):
    analysis = build_analysis_result(tmp_path)
    shared_step = deepcopy(analysis.reconstructions[0]["attack_path"][0])
    analysis.reconstructions[1]["attack_path"] = [shared_step]
    candidates = [
        item for item in AnalysisEvidenceCatalog().list_candidates(analysis)
        if item.evidence_type == "reconstruction_step"
    ]

    assert len(candidates) == 2
    assert {item.case_ids for item in candidates} == {
        ("CASE-001",), ("CASE-002",)
    }
    assert len({item.source_id for item in candidates}) == 2
    assert len({item.evidence_id for item in candidates}) == 2


def test_legacy_selected_evidence_rationale_updates_without_migration(tmp_path):
    analysis, catalog, service, workspace, repository, created = build_services(tmp_path)
    candidate = candidate_of_type(catalog, analysis, "alert")
    selected_result = service.select_evidence(
        "INVESTIGATION-001",
        candidate,
        classification="supporting",
        rationale="Initial legacy rationale",
        author="Analyst",
        expected_revision=created.revision,
    )
    before = repository.load("INVESTIGATION-001")
    assert before.provenance is None

    updated = service.update_evidence_rationale(
        "INVESTIGATION-001",
        candidate.evidence_id,
        rationale="Updated legacy rationale",
        expected_revision=selected_result.revision,
    )
    after = repository.load("INVESTIGATION-001")

    assert updated.investigation.provenance is None
    assert after.analysis_id == before.analysis_id
    assert after.provenance is None
    assert next(
        item for item in after.evidence_references
        if item.reference_id == candidate.evidence_id
    ).rationale == "Updated legacy rationale"
    assert workspace.get_investigation("INVESTIGATION-001").revision == 3
