from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.query_models import (
    AnalysisProvenanceMismatchError,
    InvalidTimelineRangeError,
    InvestigationTimelineEntry,
    InvestigationTimelineFilters,
    UnsupportedTimelineFilterError,
)
from soc_forge.investigations.timeline_query import (
    ENTRY_TYPE_PRECEDENCE,
    InvestigationTimelineService,
)


def build_context(tmp_path, case_ids=("CASE-001",)):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis, case_ids)
    return analysis, investigation, InvestigationQueryContext(analysis, investigation)


def all_entries(timeline):
    return timeline.entries + timeline.untimed_entries


def test_timeline_scopes_one_case_and_projects_all_supported_layers(tmp_path):
    analysis, investigation, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(context)
    entry_types = {entry.entry_type for entry in all_entries(timeline)}

    assert {
        "event",
        "alert",
        "case",
        "reconstruction_step",
        "analyst_evidence_selection",
        "hypothesis_created",
        "hypothesis_assessed",
        "hypothesis_reopened",
        "analyst_decision",
        "annotation",
    } <= entry_types
    assert {entry.source_id for entry in all_entries(timeline)}.isdisjoint(
        {"EVENT-002", "ALERT-002", "CASE-002"}
    )
    assert next(entry for entry in timeline.entries if entry.source_id == "EVENT-001")
    assert any(entry.source_id == "ALERT-001" for entry in timeline.entries)
    assert any(entry.source_id == "CASE-001" for entry in timeline.entries)
    assert any(
        entry.entry_type == "reconstruction_step" for entry in timeline.entries
    )
    assert not any(
        "sensitive" in entry.summary.casefold() for entry in all_entries(timeline)
    )
    assert all(len(entry.summary) <= 240 for entry in all_entries(timeline))
    assert "Senior review required" not in {
        entry.summary for entry in all_entries(timeline)
    }
    assert "Sensitive annotation body" not in {
        entry.summary for entry in all_entries(timeline)
    }


def test_multiple_case_scope_and_untimed_entries(tmp_path):
    _, _, context = build_context(tmp_path, ("CASE-001", "CASE-002"))
    timeline = InvestigationTimelineService().timeline(context)

    assert any(entry.source_id == "CASE-002" for entry in timeline.untimed_entries)
    assert any(entry.source_id == "ALERT-002" for entry in timeline.entries)
    assert any(entry.source_id == "EVENT-002" for entry in timeline.entries)
    assert any(entry.source_id == "DEC-GENERAL" for entry in timeline.untimed_entries)
    assert timeline.limitations


def test_unreferenced_events_are_not_added_by_shared_entities_or_time(tmp_path):
    analysis, investigation, context = build_context(tmp_path)
    analysis.events.append({
        "record_id": "EVENT-NEARBY",
        "timestamp": "2026-08-10T14:00:01Z",
        "host": "WS-LAB-01",
        "username": "DOMAIN\\alice",
    })
    # Existing context is a fixed projection and is not rebuilt from mutated inputs.
    timeline = InvestigationTimelineService().timeline(context)
    assert "EVENT-NEARBY" not in {entry.source_id for entry in all_entries(timeline)}


def test_timestamps_are_utc_and_same_time_order_is_deterministic(tmp_path):
    _, _, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(context)

    assert all(entry.timestamp.endswith("Z") for entry in timeline.entries)
    at_fourteen = [
        entry for entry in timeline.entries
        if entry.timestamp == "2026-08-10T14:00:00Z"
    ]
    assert at_fourteen == sorted(
        at_fourteen,
        key=lambda item: (ENTRY_TYPE_PRECEDENCE[item.entry_type], item.entry_id),
    )


def test_reordered_analysis_collections_produce_identical_timeline(tmp_path):
    analysis, investigation, context = build_context(tmp_path)
    reordered = deepcopy(analysis)
    reordered.events.reverse()
    reordered.alerts.reverse()
    reordered.cases.reverse()
    reordered.reconstructions.reverse()

    first = InvestigationTimelineService().timeline(context)
    second = InvestigationTimelineService().timeline(
        InvestigationQueryContext(reordered, investigation)
    )
    assert first == second


def test_context_and_timeline_do_not_mutate_sources_or_artifacts(tmp_path):
    analysis, investigation, _ = build_context(tmp_path)
    analysis_before = deepcopy(analysis)
    investigation_before = deepcopy(investigation)
    hashes = {
        name: sha256(path.read_bytes()).hexdigest()
        for name, path in analysis.artifacts.items()
    }

    context = InvestigationQueryContext(analysis, investigation)
    timeline = InvestigationTimelineService().timeline(context)

    assert timeline.entries
    assert analysis == analysis_before
    assert investigation == investigation_before
    assert hashes == {
        name: sha256(path.read_bytes()).hexdigest()
        for name, path in analysis.artifacts.items()
    }
    with pytest.raises(FrozenInstanceError):
        timeline.entries[0].title = "changed"
    with pytest.raises(AttributeError):
        context.source_analysis_id = "changed"


def test_context_rejects_analysis_provenance_and_case_mismatch(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)

    mismatched = deepcopy(analysis)
    mismatched.events[0]["action"] = "Materially different source analysis"
    with pytest.raises(AnalysisProvenanceMismatchError):
        InvestigationQueryContext(mismatched, investigation)

    with pytest.raises(Exception, match="CASE-MISSING"):
        InvestigationQueryContext(
            analysis,
            replace(
                investigation,
                evidence_references=tuple(
                    replace(reference, source_id="CASE-MISSING")
                    if reference.origin == "scope"
                    else reference
                    for reference in investigation.evidence_references
                ),
            ),
        )


@pytest.mark.parametrize(
    ("filters", "expected_source"),
    [
        ({"entry_types": ("alert",)}, "ALERT-001"),
        ({"host": "ws-lab-01"}, "EVENT-001"),
        ({"user": "domain\\ALICE"}, "EVENT-001"),
        ({"ip": "10.0.0.5"}, "EVENT-001"),
        ({"process": "powershell.exe"}, "EVENT-001"),
        ({"rule_id": "socf-021"}, "ALERT-001"),
        ({"attack_tactic": "defense evasion"}, "ALERT-001"),
        ({"attack_technique": "t1562.001"}, "ALERT-001"),
        ({"severity": "HIGH"}, "ALERT-001"),
        ({"evidence_classification": "supporting"}, "ALERT-001"),
        ({"hypothesis_id": "HYP-001"}, "ALERT-001"),
        ({"case_id": "CASE-001"}, "CASE-001"),
    ],
)
def test_typed_filters(filters, expected_source, tmp_path):
    _, _, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(context, filters=filters)
    assert expected_source in {entry.source_id for entry in all_entries(timeline)}


def test_time_range_and_multiple_filters_use_and_semantics(tmp_path):
    _, _, context = build_context(tmp_path)
    timeline = InvestigationTimelineService().timeline(
        context,
        filters=InvestigationTimelineFilters(
            start_time="2026-08-10T14:00:00Z",
            end_time="2026-08-10T14:00:00Z",
            entry_types=("alert",),
            host="WS-LAB-01",
            severity="high",
        ),
    )
    assert [entry.source_id for entry in timeline.entries] == ["ALERT-001"]


def test_invalid_filters_and_time_ranges_fail_clearly(tmp_path):
    _, _, context = build_context(tmp_path)
    service = InvestigationTimelineService()

    with pytest.raises(UnsupportedTimelineFilterError):
        service.timeline(context, filters={"free_text": "powershell"})
    with pytest.raises(UnsupportedTimelineFilterError):
        service.timeline(context, filters={"entry_types": ("invented",)})
    with pytest.raises(InvalidTimelineRangeError):
        service.timeline(
            context,
            filters={
                "start_time": "2026-08-11T00:00:00Z",
                "end_time": "2026-08-10T00:00:00Z",
            },
        )


def test_timeline_entry_rejects_unknown_type():
    with pytest.raises(ValueError):
        InvestigationTimelineEntry(
            entry_id="x",
            timestamp=None,
            entry_type="invented",
            source_id="x",
            source_analysis_id="analysis",
            case_ids=(),
            title="x",
            summary="x",
            context_kind="machine",
            relationship_reason="x",
        )



def test_query_architecture_boundaries_are_read_only():
    from pathlib import Path

    context_source = Path("soc_forge/investigations/query_context.py").read_text()
    timeline_source = Path("soc_forge/investigations/timeline_query.py").read_text()
    pivot_source = Path("soc_forge/investigations/pivots.py").read_text()
    pipeline_source = Path("soc_forge/pipeline.py").read_text()
    lower_sources = [
        Path(path).read_text()
        for path in (
            "soc_forge/investigations/repository.py",
            "soc_forge/investigations/workspace_service.py",
            "soc_forge/investigations/evidence_service.py",
            "soc_forge/investigations/reasoning_service.py",
        )
    ]

    assert "from soc_forge.pipeline import AnalysisResult" in context_source
    assert "soc_forge.pipeline" not in timeline_source
    assert "soc_forge.pipeline" not in pivot_source
    assert all("soc_forge.pipeline" not in source for source in lower_sources)
    assert "soc_forge.investigations" not in pipeline_source
    for source in (context_source, timeline_source, pivot_source):
        assert ".write_text(" not in source
        assert "json.dump" not in source
        assert "InvestigationRepository" not in source
        assert "correlate_alerts" not in source
        assert "build_cases" not in source
        assert "run_rules" not in source
