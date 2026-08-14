from copy import deepcopy
from dataclasses import replace

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.summary import InvestigationSummaryService
from soc_forge.investigations.summary_view import (
    SUMMARY_DRILLDOWN_GROUPS,
    render_investigation_summary,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.ui.terminal import visible_length


def _summary_fixture(tmp_path, *, with_findings=False):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    if with_findings:
        evidence_id = next(
            item.reference_id
            for item in investigation.evidence_references
            if item.origin == "analyst_selection"
        )
        old = InvestigationFinding(
            finding_id="FIND-OLD",
            investigation_id="INV-QUERY",
            title="Earlier conclusion",
            conclusion="Earlier conclusion was superseded.",
            status="substantiated",
            confidence="high",
            author="alice",
            created_at="2026-08-12T10:00:00Z",
            updated_at="2026-08-12T10:00:00Z",
            evidence_ids=(evidence_id,),
            lifecycle_state="superseded",
            superseded_by_finding_id="FIND-ACTIVE",
            supersession_reason="Later evidence changed the assessment.",
            supersession_author="bob",
            superseded_at="2026-08-12T11:00:00Z",
        )
        active = InvestigationFinding(
            finding_id="FIND-ACTIVE",
            investigation_id="INV-QUERY",
            title="Current analyst conclusion",
            conclusion="Current activity remains inconclusive.",
            status="inconclusive",
            confidence="low",
            author="bob",
            created_at="2026-08-12T10:30:00Z",
            updated_at="2026-08-12T10:30:00Z",
            evidence_ids=(evidence_id,),
            limitations=("Visibility is limited.",),
            supersedes_finding_id="FIND-OLD",
        )
        investigation = replace(investigation, findings=(old, active))
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationSummaryService(
        InvestigationWorkspaceService(repository)
    )
    return analysis, investigation, repository, service


def _normalized(value):
    return " ".join(
        str(value)
        .replace("│", " ")
        .replace("┌", " ")
        .replace("┐", " ")
        .replace("└", " ")
        .replace("┘", " ")
        .split()
    )


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_full_summary_hierarchy_is_width_safe(width, tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)

    rendered = render_investigation_summary(summary, width=width, ansi=False)

    assert all(visible_length(line) <= max(24, width) for line in rendered.splitlines())
    assert "INV-QUERY" in rendered
    assert "[FULL]" in rendered
    assert "ANALYST ASSESSMENT" in rendered
    assert "INVESTIGATION ST" in rendered
    assert "MACHINE-GENERATED" in rendered
    assert "ANALYST-SELECTED" in rendered
    assert "ANALYST HYPOTHESES" in rendered
    assert "ANALYST DECISIONS" in rendered
    assert "ACTIVE FINDINGS" in rendered
    assert "HISTORICAL /" in rendered
    assert "TIMELINE SUMMARY" in rendered
    assert "LIMITATIONS" in rendered


def test_exact_service_narrative_and_active_finding_metadata_render(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)

    rendered = render_investigation_summary(summary, width=100, ansi=False)

    assert _normalized(summary.narrative) in _normalized(rendered)
    assert "FIND-ACTIVE" in rendered
    assert "[INCONCLUSIVE]" in rendered
    assert "[ACTIVE]" in rendered
    assert "[LOW]" in rendered
    assert "bob" in rendered


def test_summary_without_active_finding_uses_safe_empty_state(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(tmp_path)
    summary = service.summarize(investigation.investigation_id, analysis)

    rendered = render_investigation_summary(summary, width=80, ansi=False)

    assert _normalized(summary.narrative) in _normalized(rendered)
    assert "EMPTY: No active analyst-authored findings." in rendered
    assert "EMPTY: No historical analyst-authored findings." in rendered


def test_authoritative_state_machine_evidence_reasoning_and_timeline_render(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(tmp_path)
    summary = service.summarize(investigation.investigation_id, analysis)

    rendered = render_investigation_summary(summary, width=100, ansi=False)

    assert "3 selected | 1 supporting | 1 contradicting | 1 context" in rendered
    assert "1 total | 1 open | 0 supported" in rendered
    assert "3" in rendered and "Decisions" in rendered
    assert "CASE-001" in rendered
    assert "SOCF-021" in rendered
    assert "T1562.001" in rendered
    assert "[SUPPORTING]" in rendered
    assert "[CONTRADICTING]" in rendered
    assert "Sensitive" in rendered
    assert "Analyst assessment" in rendered and "[OPEN]" in rendered
    assert "DEC-ASSESS" in rendered
    assert str(summary.timeline.timed_entry_count) in rendered
    assert "powershell.exe -enc sensitive" not in rendered


def test_offline_mode_keeps_analyst_state_and_names_unavailable_context(tmp_path):
    _analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id)

    rendered = render_investigation_summary(summary, width=80, ansi=False)

    assert "[OFFLINE]" in rendered
    assert "Persisted analyst state remains available" in _normalized(rendered)
    assert "Detection context requiring the matching analysis is unavailable" in _normalized(rendered)
    assert "Chronology requires the matching source analysis." in rendered
    assert "Unavailable timed | Unavailable untimed" in rendered
    assert "FIND-ACTIVE" in rendered
    assert "SOCF-021" not in rendered


def test_active_and_historical_findings_remain_distinct(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)

    rendered = render_investigation_summary(summary, width=100, ansi=False)

    active_position = rendered.index("ACTIVE FINDINGS")
    history_position = rendered.index("HISTORICAL / SUPERSEDED FINDINGS")
    assert active_position < history_position
    assert "FIND-ACTIVE" in rendered
    assert "FIND-OLD" in rendered
    assert "[ACTIVE]" in rendered
    assert "[SUPERSEDED]" in rendered
    assert "Superseded by" in rendered
    assert "Later evidence changed the assessment." in rendered
    assert "1 active | 1 historical" in rendered


def test_empty_sections_render_without_fabricating_data(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(tmp_path)
    summary = service.summarize(investigation.investigation_id, analysis)
    empty = replace(
        summary,
        evidence=(),
        hypotheses=(),
        decisions=(),
        analyst_findings=(),
        findings=(),
        limitations=(),
    )

    rendered = render_investigation_summary(empty, width=80, ansi=False)

    assert "EMPTY: No selected-case detection context is available." in rendered
    assert "EMPTY: No analyst-selected evidence." in rendered
    assert "EMPTY: No analyst hypotheses." in rendered
    assert "EMPTY: No analyst decisions." in rendered
    assert "EMPTY: No summary limitations." in rendered


def test_long_narrative_and_finding_text_wrap_without_mutating_summary(tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)
    active = next(
        item for item in summary.analyst_findings
        if item.lifecycle_state == "active"
    )
    long_summary = replace(
        summary,
        narrative="Narrative " + "N" * 600,
        analyst_findings=(
            replace(
                active,
                title="Finding " + "T" * 150,
                conclusion="Conclusion " + "C" * 300,
            ),
        ),
    )
    before = deepcopy(long_summary)

    rendered = render_investigation_summary(long_summary, width=60, ansi=False)

    assert long_summary == before
    assert all(visible_length(line) <= 60 for line in rendered.splitlines())
    assert "Narrative" in rendered
    assert "Conclusion:" in rendered


def test_no_color_and_ansi_disabled_modes_keep_text_labels(monkeypatch, tmp_path):
    analysis, investigation, _repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)
    monkeypatch.setenv("NO_COLOR", "1")

    environment_render = render_investigation_summary(summary, width=80)
    explicit_render = render_investigation_summary(summary, width=80, ansi=False)

    assert "\x1b" not in environment_render
    assert "\x1b" not in explicit_render
    assert "[FULL]" in environment_render
    assert "[ACTIVE]" in environment_render
    assert "[0] Back" in environment_render


def test_locked_drilldown_numbers_are_visually_grouped_without_remapping():
    assert SUMMARY_DRILLDOWN_GROUPS == (
        (
            "INVESTIGATION ANALYSIS",
            (
                ("1", "Evidence Workspace"),
                ("2", "Hypotheses and Decisions"),
                ("3", "Timeline and Pivot Workbench"),
                ("5", "Investigation Findings"),
            ),
        ),
        (
            "OUTPUT & RECOVERY",
            (
                ("4", "Investigation Handoff"),
                ("6", "Load Source Analysis Snapshot"),
            ),
        ),
    )
    assert {
        number: label
        for _heading, options in SUMMARY_DRILLDOWN_GROUPS
        for number, label in options
    } == {
        "1": "Evidence Workspace",
        "2": "Hypotheses and Decisions",
        "3": "Timeline and Pivot Workbench",
        "4": "Investigation Handoff",
        "5": "Investigation Findings",
        "6": "Load Source Analysis Snapshot",
    }


def test_summary_render_does_not_mutate_repository_projection_or_analysis(tmp_path):
    analysis, investigation, repository, service = _summary_fixture(
        tmp_path, with_findings=True
    )
    summary = service.summarize(investigation.investigation_id, analysis)
    before_summary = deepcopy(summary)
    before_analysis = deepcopy(analysis)
    repository_path = next(repository.investigations_root.glob("*.json"))
    before_repository = repository_path.read_bytes()
    before_artifacts = {
        key: path.read_bytes() for key, path in analysis.artifacts.items()
    }

    render_investigation_summary(summary, width=80, ansi=False)

    assert summary == before_summary
    assert analysis == before_analysis
    assert repository_path.read_bytes() == before_repository
    assert {
        key: path.read_bytes() for key, path in analysis.artifacts.items()
    } == before_artifacts
