from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.models import Decision
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.summary import (
    ATTRIBUTION_ANALYST,
    ATTRIBUTION_MACHINE,
    InvestigationSummaryService,
    SUMMARY_NARRATIVE_LIMIT,
    SUMMARY_TEXT_LIMIT,
)
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


def build_summary_fixture(tmp_path, investigation=None):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = investigation or build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    return analysis, investigation, repository, InvestigationSummaryService(service)


def artifact_hashes(analysis):
    return {
        key: sha256(Path(path).read_bytes()).hexdigest()
        for key, path in analysis.artifacts.items()
    }


def repository_bytes(repository):
    return next(repository.investigations_root.glob("*.json")).read_bytes()


def test_complete_summary_contract_counts_attribution_and_bounding(tmp_path):
    analysis, investigation, _repository, service = build_summary_fixture(tmp_path)

    summary = service.summarize(investigation.investigation_id, analysis)

    assert summary.mode == "full"
    assert summary.schema_version == "1.0"
    assert summary.investigation_id == "INV-QUERY"
    assert summary.title == "Query investigation"
    assert summary.owner == "Analyst"
    assert summary.status == "in_progress"
    assert summary.revision == 1
    assert summary.source_analysis_id == investigation.analysis_id
    assert summary.selected_case_ids == ("CASE-001",)
    assert summary.state.annotation_count == 1
    assert summary.state.selected_evidence_count == 3
    assert summary.state.supporting_evidence_count == 1
    assert summary.state.contradicting_evidence_count == 1
    assert summary.state.context_evidence_count == 1
    assert summary.state.hypothesis_counts_by_state == (("open", 1),)
    assert summary.state.decision_count == 3
    assert all(item.attribution == ATTRIBUTION_MACHINE for item in summary.findings)
    assert all(item.attribution == ATTRIBUTION_ANALYST for item in summary.evidence)
    assert all(item.attribution == ATTRIBUTION_ANALYST for item in summary.hypotheses)
    assert all(item.attribution == ATTRIBUTION_ANALYST for item in summary.decisions)
    assert all(len(item.rationale_summary) <= SUMMARY_TEXT_LIMIT for item in summary.evidence)
    assert all(len(item.rationale_summary) <= SUMMARY_TEXT_LIMIT for item in summary.decisions)
    assert len(summary.narrative) <= SUMMARY_NARRATIVE_LIMIT
    assert "Analyst assessment: HYP-001 as open" in summary.narrative
    assert "confirmed attack" not in summary.narrative.casefold()
    assert summary.to_dict()["mode"] == "full"


def test_full_summary_uses_existing_case_evidence_and_timeline_projection(tmp_path):
    analysis, investigation, _repository, service = build_summary_fixture(tmp_path)
    expected = InvestigationTimelineService().timeline(
        InvestigationQueryContext(analysis, investigation)
    )

    summary = service.summarize("INV-QUERY", analysis)

    finding = summary.findings[0]
    assert finding.case_id == "CASE-001"
    assert finding.title == "Defense evasion investigation"
    assert "SOCF-021" in finding.rule_ids
    assert "high" in finding.severities
    assert "Defense Evasion" in finding.attack_tactics
    assert "T1562.001" in finding.attack_techniques
    assert {item.evidence_type for item in summary.evidence} == {
        "event", "alert", "reconstruction_step"
    }
    assert any(item.sensitive_content for item in summary.evidence)
    assert summary.timeline is not None
    assert summary.timeline.first_timed_activity == expected.entries[0].timestamp
    assert summary.timeline.last_timed_activity == expected.entries[-1].timestamp
    assert summary.timeline.timed_entry_count == len(expected.entries)
    assert summary.timeline.untimed_entry_count == len(expected.untimed_entries)
    assert [item.entry_id for item in summary.timeline.milestones] == [
        item.entry_id for item in expected.entries[:6]
    ]


def test_offline_summary_preserves_durable_analyst_state(tmp_path):
    _analysis, investigation, _repository, service = build_summary_fixture(tmp_path)

    summary = service.summarize("INV-QUERY")

    assert summary.mode == "offline"
    assert summary.findings == ()
    assert summary.timeline is None
    assert len(summary.evidence) == 3
    assert all(item.sensitive_content is None for item in summary.evidence)
    assert len(summary.hypotheses) == 1
    assert len(summary.decisions) == 3
    assert summary.state.annotation_count == 1
    assert summary.source_analysis_id == investigation.analysis_id
    assert summary.narrative.startswith("Source analysis is not active.")
    assert any("machine context is omitted" in item for item in summary.limitations)


def test_mismatched_analysis_is_bounded_offline_and_never_used(tmp_path):
    analysis, investigation, repository, service = build_summary_fixture(tmp_path)
    different = build_query_analysis(tmp_path / "different")
    different.events[0]["timestamp"] = "2030-01-01T00:00:00Z"
    before = repository_bytes(repository)

    summary = service.summarize("INV-QUERY", different)

    assert summary.mode == "offline"
    assert summary.findings == ()
    assert summary.timeline is None
    assert summary.source_analysis_id == investigation.analysis_id
    assert any("could not be validated" in item for item in summary.limitations)
    assert repository_bytes(repository) == before
    assert analysis.events[0]["timestamp"] != different.events[0]["timestamp"]


def test_summary_is_deterministic_when_source_and_investigation_order_changes(tmp_path):
    analysis, investigation, _repository, service = build_summary_fixture(
        tmp_path / "original"
    )
    original = service.summarize("INV-QUERY", analysis)

    reordered_analysis = deepcopy(analysis)
    for field in ("events", "alerts", "cases", "reconstructions"):
        setattr(reordered_analysis, field, list(reversed(getattr(reordered_analysis, field))))
    reordered_investigation = replace(
        investigation,
        evidence_references=tuple(reversed(investigation.evidence_references)),
        hypotheses=tuple(reversed(investigation.hypotheses)),
        decisions=tuple(reversed(investigation.decisions)),
        annotations=tuple(reversed(investigation.annotations)),
    )
    _analysis, _investigation, _repository, reordered_service = build_summary_fixture(
        tmp_path / "reordered",
        reordered_investigation,
    )

    assert reordered_service.summarize("INV-QUERY", reordered_analysis) == original
    assert service.summarize("INV-QUERY", analysis) == original


def test_summary_is_read_only_for_analysis_repository_revision_and_artifacts(tmp_path):
    analysis, _investigation, repository, service = build_summary_fixture(tmp_path)
    analysis_before = deepcopy(analysis)
    repository_before = repository_bytes(repository)
    hashes_before = artifact_hashes(analysis)

    first = service.summarize("INV-QUERY", analysis)
    second = service.summarize("INV-QUERY", analysis)

    assert first == second
    assert analysis == analysis_before
    assert repository_bytes(repository) == repository_before
    assert artifact_hashes(analysis) == hashes_before
    assert service.workspace_service.get_investigation("INV-QUERY").revision == 1


def test_unknown_legacy_decision_type_remains_displayable(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    legacy = Decision(
        decision_id="DEC-LEGACY",
        decision_type="legacy_custom_review",
        outcome="retained",
        rationale="Historical decision remains visible",
        decided_by="Legacy Analyst",
    )
    investigation = replace(
        investigation,
        decisions=investigation.decisions + (legacy,),
    )
    _analysis, _investigation, _repository, service = build_summary_fixture(
        tmp_path / "fixture",
        investigation,
    )

    summary = service.summarize("INV-QUERY", analysis)

    rendered = next(item for item in summary.decisions if item.decision_id == "DEC-LEGACY")
    assert rendered.decision_type == "legacy_custom_review"
    assert rendered.outcome == "retained"


def test_summary_narrative_does_not_leak_raw_sensitive_or_analyst_text(tmp_path):
    analysis, _investigation, _repository, service = build_summary_fixture(tmp_path)

    summary = service.summarize("INV-QUERY", analysis)

    assert "powershell.exe -enc sensitive" not in summary.narrative
    assert "Sensitive annotation body" not in summary.narrative
    assert "Supports defense-evasion hypothesis" not in summary.narrative
    assert "Senior review required" not in summary.narrative
    assert summary.contains_sensitive_content is True


def test_summary_delegates_chronology_to_timeline_service(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    workspace_service = InvestigationWorkspaceService(repository)

    class RecordingTimelineService:
        def __init__(self):
            self.contexts = []
            self.delegate = InvestigationTimelineService()

        def timeline(self, context):
            self.contexts.append(context)
            return self.delegate.timeline(context)

    timeline_service = RecordingTimelineService()
    service = InvestigationSummaryService(
        workspace_service,
        timeline_service=timeline_service,
    )

    summary = service.summarize("INV-QUERY", analysis)

    assert len(timeline_service.contexts) == 1
    assert timeline_service.contexts[0].source_analysis_id == investigation.analysis_id
    assert summary.timeline is not None
