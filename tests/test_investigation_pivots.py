from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from ipaddress import ip_address

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import (
    InvestigationQueryContext,
    normalize_entity,
)
from soc_forge.investigations.query_models import (
    InvalidEntityValueError,
    UnsupportedEntityTypeError,
)
from soc_forge.investigations.provenance import derive_legacy_analysis_provenance
from soc_forge.investigations.timeline_query import InvestigationTimelineService


def build_context(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)
    return analysis, investigation, InvestigationQueryContext(analysis, investigation)


@pytest.mark.parametrize(
    ("method", "entity_type", "value", "source_id"),
    [
        ("events_for_entity", "host", "ws-lab-01", "EVENT-001"),
        ("alerts_for_entity", "host", "WS-LAB-01", "ALERT-001"),
        ("cases_for_entity", "host", "WS-LAB-01", "CASE-001"),
        ("events_for_entity", "user", "domain\\ALICE", "EVENT-001"),
        ("alerts_for_entity", "ip", "10.0.0.5", "ALERT-001"),
        ("events_for_entity", "process", "powershell.exe", "EVENT-001"),
        ("alerts_for_entity", "rule", "SOCF-021", "ALERT-001"),
        ("alerts_for_entity", "attack_technique", "t1562.001", "ALERT-001"),
    ],
)
def test_typed_entity_pivots(method, entity_type, value, source_id, tmp_path):
    _, _, context = build_context(tmp_path)
    result = getattr(InvestigationPivotService(), method)(
        context, entity_type, value
    )

    assert source_id in {match.source_id for match in result.matches}
    assert all(match.relationship_reason for match in result.matches)
    assert all(match.source_analysis_id == context.source_analysis_id for match in result.matches)


def test_case_to_evidence_and_evidence_hypothesis_bidirectional_pivots(tmp_path):
    _, investigation, context = build_context(tmp_path)
    pivots = InvestigationPivotService()
    case_evidence = pivots.evidence_for_entity(context, "case", "CASE-001")
    selected_id = next(
        reference.reference_id
        for reference in investigation.evidence_references
        if reference.origin == "analyst_selection"
        and reference.classification == "supporting"
    )

    assert {"event", "alert", "case", "reconstruction_step"} <= {
        match.source_type for match in case_evidence.matches
    }
    evidence_hypotheses = pivots.hypotheses_for_entity(
        context, "evidence", selected_id
    )
    assert [match.source_id for match in evidence_hypotheses.matches] == ["HYP-001"]
    assert "supporting" in evidence_hypotheses.matches[0].relationship_reason
    assert evidence_hypotheses.matches[0].hypothesis_overlays[0].state == "open"

    hypothesis_evidence = pivots.evidence_for_hypothesis(context, "HYP-001")
    assert selected_id in {match.source_id for match in hypothesis_evidence.matches}
    selected_match = next(
        match for match in hypothesis_evidence.matches
        if match.source_id == selected_id
    )
    assert selected_match.analyst_selected is True
    assert selected_match.evidence_classification == "supporting"
    assert selected_match.hypothesis_overlays[0].state == "open"
    assert all(match.relationship_reason for match in hypothesis_evidence.matches)


def test_entity_timeline_and_related_entities_are_explainable_and_bounded(tmp_path):
    _, _, context = build_context(tmp_path)
    pivots = InvestigationPivotService()

    timeline = pivots.timeline_for_entity(context, "host", "WS-LAB-01")
    assert {"EVENT-001", "ALERT-001"} <= {
        entry.source_id for entry in timeline.entries
    }

    related = pivots.related_entities(context, "user", "DOMAIN\\alice")
    related_types = {item.entity.entity_type for item in related.relationships}
    assert {"host", "ip", "process", "rule", "case", "evidence"} <= related_types
    assert all(item.relationship_reason for item in related.relationships)
    assert all(item.count >= 1 for item in related.relationships)
    assert all(item.source_ids for item in related.relationships)


def test_explicit_pivot_can_explore_beyond_timeline_scope_without_time_inference(tmp_path):
    analysis, _, context = build_context(tmp_path)
    analysis.events.append({
        "record_id": "NEAR-TIME",
        "timestamp": "2026-08-10T14:00:00Z",
        "host": "UNRELATED",
        "username": "DOMAIN\\alice",
    })
    # The immutable context index was built before this source appeared.
    result = InvestigationPivotService().events_for_entity(
        context, "user", "DOMAIN\\alice"
    )
    assert "NEAR-TIME" not in {match.source_id for match in result.matches}
    assert "EVENT-002" not in {match.source_id for match in result.matches}


def test_duplicate_relationships_and_reordered_sources_are_deterministic(tmp_path):
    analysis, investigation, context = build_context(tmp_path)
    first = InvestigationPivotService().related_entities(
        context, "host", "WS-LAB-01"
    )
    reordered = deepcopy(analysis)
    reordered.events.reverse()
    reordered.alerts.reverse()
    reordered.cases.reverse()
    second = InvestigationPivotService().related_entities(
        InvestigationQueryContext(reordered, investigation),
        "host",
        "WS-LAB-01",
    )
    assert first == second
    keys = [
        (
            item.entity.entity_type,
            item.entity.normalized_value,
            item.entity.secondary_key,
        )
        for item in first.relationships
    ]
    assert len(keys) == len(set(keys))
    assert keys == sorted(keys)


@pytest.mark.parametrize(
    ("entity_type", "value", "normalized"),
    [
        ("host", "  WS-LAB-01  ", "ws-lab-01"),
        ("user", "DOMAIN\\Alice", "domain\\alice"),
        ("user", "OTHER\\Alice", "other\\alice"),
        ("ip", "10.0.0.5", "10.0.0.5"),
        ("ip", "2001:0db8::1", "2001:db8::1"),
        ("process", r"C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("rule", "SOCF-021", "SOCF-021"),
        ("attack_technique", "t1562.001", "T1562.001"),
    ],
)
def test_entity_normalization(entity_type, value, normalized):
    entity = normalize_entity(entity_type, value)
    assert entity.normalized_value == normalized


def test_user_domain_context_and_process_path_policy_remain_distinct():
    assert normalize_entity("user", "DOMAIN\\alice") != normalize_entity(
        "user", "OTHER\\alice"
    )
    process = normalize_entity(
        "process", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert process.normalized_value == "powershell.exe"
    assert process.secondary_key.endswith(
        r"windows\\system32\\windowspowershell\\v1.0\\powershell.exe"
    )


@pytest.mark.parametrize(
    ("entity_type", "value", "error"),
    [
        ("ip", "not-an-ip", InvalidEntityValueError),
        ("unknown", "value", UnsupportedEntityTypeError),
        ("host", "   ", InvalidEntityValueError),
    ],
)
def test_invalid_entity_values_fail(entity_type, value, error):
    with pytest.raises(error):
        normalize_entity(entity_type, value)


def test_reasoning_and_evidence_overlays_do_not_duplicate_rationales(tmp_path):
    _, _, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(context)
    machine = {
        entry.source_id: entry
        for entry in timeline.entries
        if entry.context_kind == "machine"
    }

    assert machine["ALERT-001"].analyst_selected is True
    assert machine["ALERT-001"].evidence_classification == "supporting"
    assert machine["EVENT-001"].evidence_classification == "contradicting"
    reconstruction = next(
        entry for entry in timeline.entries
        if entry.entry_type == "reconstruction_step"
    )
    assert reconstruction.evidence_classification == "context"
    assert machine["ALERT-001"].related_hypothesis_ids == ("HYP-001",)
    assert machine["ALERT-001"].hypothesis_overlays[0].relationship == "supporting"
    assert machine["ALERT-001"].hypothesis_overlays[0].state == "open"
    assert "DEC-ASSESS" in machine["ALERT-001"].related_decision_ids
    assert {
        item.decision_type for item in machine["ALERT-001"].decision_overlays
    } == {"hypothesis_assessment", "escalation"}
    serialized = repr(timeline)
    assert "Evidence supported the working hypothesis" not in serialized
    assert "Supports defense-evasion hypothesis" not in serialized


def test_scope_reference_is_not_mislabeled_analyst_selected(tmp_path):
    _, _, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(context)
    case = next(entry for entry in timeline.entries if entry.source_id == "CASE-001")
    assert case.analyst_selected is False
    assert case.evidence_classification is None


def test_projection_models_are_frozen(tmp_path):
    _, _, context = build_context(tmp_path)
    result = InvestigationPivotService().events_for_entity(
        context, "host", "WS-LAB-01"
    )
    with pytest.raises(FrozenInstanceError):
        result.matches[0].source_id = "changed"



def test_legacy_evidence_identity_remains_resolvable_for_overlays(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)
    catalog = AnalysisEvidenceCatalog()
    selected = next(
        item
        for item in investigation.evidence_references
        if item.origin == "analyst_selection" and item.classification == "supporting"
    )
    legacy = derive_legacy_analysis_provenance(
        normalized_input_name=analysis.input_name,
        events=analysis.events,
        alerts=analysis.alerts,
        cases=analysis.cases,
        reconstructions=analysis.reconstructions,
        artifact_keys=tuple(sorted(analysis.artifacts)),
    )
    legacy_id = catalog._legacy_evidence_id(
        legacy.source_analysis_id,
        selected.evidence_type,
        selected.source_id,
    )
    references = tuple(
        replace(item, reference_id=legacy_id)
        if item.reference_id == selected.reference_id
        else item
        for item in investigation.evidence_references
    )
    hypotheses = tuple(
        replace(
            item,
            supporting_evidence_reference_ids=tuple(
                legacy_id if value == selected.reference_id else value
                for value in item.supporting_evidence_reference_ids
            ),
        )
        for item in investigation.hypotheses
    )
    decisions = tuple(
        replace(
            item,
            evidence_reference_ids=tuple(
                legacy_id if value == selected.reference_id else value
                for value in item.evidence_reference_ids
            ),
        )
        for item in investigation.decisions
    )
    legacy_investigation = replace(
        investigation,
        evidence_references=references,
        hypotheses=hypotheses,
        decisions=decisions,
    )

    context = InvestigationQueryContext(analysis, legacy_investigation)
    timeline = InvestigationTimelineService().timeline(context)
    alert = next(entry for entry in timeline.entries if entry.source_id == "ALERT-001")
    assert alert.analyst_selected is True
    assert alert.related_hypothesis_ids == ("HYP-001",)
