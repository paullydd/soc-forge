from copy import deepcopy
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.handoff import (
    HandoffFile,
    HandoffFindingPreview,
    HandoffManifestSummary,
    HandoffPreview,
    HandoffResult,
)
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.timeline_handoff_view import (
    HANDOFF_MENU_GROUPS,
    PIVOT_MENU_OPTIONS,
    TIMELINE_MENU_GROUPS,
    render_handoff_manifest,
    render_handoff_preview,
    render_handoff_result,
    render_handoff_workspace,
    render_pivot_menu,
    render_pivot_result,
    render_related_entities,
    render_timeline,
    render_timeline_entry_detail,
    render_timeline_workspace,
)
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.terminal import visible_length


def _state(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)
    current = WorkspaceResult(investigation, revision=8)
    context = InvestigationQueryContext(analysis, investigation)
    timeline = InvestigationTimelineService().timeline(context)
    return analysis, current, context, timeline


def _finding(finding_id, lifecycle, **kwargs):
    return HandoffFindingPreview(
        finding_id=finding_id,
        title=f"Analyst finding {finding_id}",
        conclusion="Bounded analyst conclusion with uncertainty.",
        status="substantiated",
        confidence="high",
        author="Analyst",
        updated_at="2026-08-14T10:00:00Z",
        evidence_count=1,
        hypothesis_count=1,
        decision_count=1,
        evidence_ids=("EVIDENCE-001",),
        hypothesis_ids=("HYP-001",),
        decision_ids=("DEC-ASSESS",),
        attack_tactics=("Defense Evasion",),
        attack_techniques=("T1562.001",),
        limitations=("Source visibility is bounded.",),
        lifecycle_state=lifecycle,
        supersedes_finding_id=kwargs.get("supersedes"),
        superseded_by_finding_id=kwargs.get("superseded_by"),
        supersession_reason=kwargs.get("reason"),
        supersession_author=kwargs.get("supersession_author"),
        superseded_at=kwargs.get("superseded_at"),
    )


def _preview():
    return HandoffPreview(
        investigation_id="INV-QUERY",
        title="Query investigation",
        owner="Analyst",
        status="in_progress",
        revision=8,
        source_analysis_id="analysis-001",
        selected_case_count=1,
        analyst_evidence_count=3,
        hypothesis_count=1,
        decision_count=3,
        finding_count=2,
        findings=(
            _finding(
                "FIND-OLD",
                "superseded",
                superseded_by="FIND-ACTIVE",
                reason="Later evidence refined the conclusion.",
                supersession_author="Analyst",
                superseded_at="2026-08-14T10:01:00Z",
            ),
            _finding("FIND-ACTIVE", "active", supersedes="FIND-OLD"),
        ),
        annotation_count=1,
        timed_entry_count=8,
        untimed_entry_count=2,
        available_artifact_keys=("alerts", "cases", "report"),
        required_artifacts_available=True,
        missing_required_artifact_keys=(),
        missing_optional_artifact_keys=("hunts",),
        sensitive_data_warning="Handoff content may contain sensitive telemetry.",
    )


def _manifest(tmp_path):
    return HandoffManifestSummary(
        schema_version="1.2",
        handoff_id="HANDOFF-001",
        investigation_id="INV-QUERY",
        source_analysis_id="analysis-001",
        revision=8,
        owner="Analyst",
        status="in_progress",
        selected_case_ids=("CASE-001",),
        files=(
            HandoffFile(
                filename="manifest.json",
                logical_type="manifest",
                size=42,
                sha256="a" * 64,
            ),
        ),
        limitations=("Review before sharing.",),
        sensitive_data_warning="Sensitive security telemetry may be present.",
    )


def _assert_width(rendered, width):
    assert all(
        visible_length(line) <= max(24, width)
        for line in rendered.splitlines()
    )


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_timeline_and_handoff_renderers_are_width_safe(width, tmp_path):
    _analysis, current, context, timeline = _state(tmp_path)
    pivot = InvestigationPivotService().events_for_entity(
        context, "host", "WS-LAB-01"
    )
    related = InvestigationPivotService().related_entities(
        context, "host", "WS-LAB-01"
    )
    preview = _preview()
    manifest = _manifest(tmp_path)
    result = HandoffResult(
        handoff_id="HANDOFF-001",
        investigation_id="INV-QUERY",
        revision=8,
        output_path=Path("out/handoffs/INV-QUERY"),
        manifest_path=Path("out/handoffs/INV-QUERY/manifest.json"),
        files=manifest.files,
        warnings=("Review before sharing.",),
        validation_status="valid",
    )
    timeline_text, _ordered = render_timeline(timeline, width=width, ansi=False)
    outputs = (
        render_timeline_workspace(
            current, timeline, source_mode="full", width=width, ansi=False
        ),
        render_timeline_workspace(
            current, None, source_mode="offline", width=width, ansi=False
        ),
        timeline_text,
        render_timeline_entry_detail(
            timeline.entries[0], width=width, ansi=False
        ),
        render_pivot_menu("host", "WS-LAB-01", width=width, ansi=False),
        render_pivot_result("Events", pivot, width=width, ansi=False),
        render_related_entities(related, width=width, ansi=False),
        render_handoff_workspace(
            current,
            source_available=True,
            last_result=result,
            width=width,
            ansi=False,
        ),
        render_handoff_preview(preview, width=width, ansi=False),
        render_handoff_result(result, width=width, ansi=False),
        render_handoff_manifest(manifest, validation=True, width=width, ansi=False),
    )
    for rendered in outputs:
        _assert_width(rendered, width)


def test_timeline_workspace_full_offline_counts_and_locked_menu(tmp_path):
    _analysis, current, _context, timeline = _state(tmp_path)
    full = render_timeline_workspace(
        current, timeline, source_mode="full", width=100, ansi=False
    )
    offline = render_timeline_workspace(
        current, None, source_mode="offline", width=100, ansi=False
    )

    assert "INV-QUERY" in full and "TIMELINE" in full
    assert "TIMELINE STATE" in full
    assert "[FULL]" in full
    assert str(len(timeline.entries)) in full
    assert str(len(timeline.untimed_entries)) in full
    assert "[OFFLINE]" in offline
    assert "Chronology requires the matching completed analysis" in offline
    assert "Unavailable" in offline
    assert TIMELINE_MENU_GROUPS == (
        ("TIMELINE REVIEW", (("1", "Investigation Timeline"), ("2", "Filter Timeline"), ("3", "Browse Entities"), ("4", "Pivot from Entity"))),
        ("RELATIONSHIPS", (("5", "Inspect Evidence Relationship"), ("6", "Inspect Hypothesis Relationships"), ("7", "View Query Limitations"))),
        ("WORKBENCH", (("8", "Refresh Workbench"),)),
    )


def test_timeline_preserves_order_origin_and_timed_sections(tmp_path):
    _analysis, _current, _context, timeline = _state(tmp_path)
    rendered, ordered = render_timeline(timeline, width=100, ansi=False)

    assert ordered == timeline.entries + timeline.untimed_entries
    positions = [rendered.index(entry.entry_id) for entry in ordered]
    assert positions == sorted(positions)
    assert "[MACHINE]" in rendered
    assert "[ANALYST]" in rendered
    assert "CHRONOLOGICAL ACTIVITY" in rendered
    assert "UNTIMED ACTIVITY" in rendered
    assert "SENSITIVE" in rendered


def test_timeline_detail_and_pivots_preserve_query_meaning(tmp_path):
    _analysis, _current, context, timeline = _state(tmp_path)
    entry = next(item for item in timeline.entries if item.source_id == "ALERT-001")
    detail = render_timeline_entry_detail(entry, width=100, ansi=False)
    pivots = InvestigationPivotService()
    result = pivots.evidence_for_entity(context, "host", "WS-LAB-01")
    related = pivots.related_entities(context, "host", "WS-LAB-01")
    pivot_text = render_pivot_result("Evidence", result, width=100, ansi=False)
    related_text = render_related_entities(related, width=100, ansi=False)

    assert entry.relationship_reason in detail
    assert entry.source_analysis_id in detail
    assert "Decision overlay" in detail
    assert "PIVOT RESULTS" in pivot_text
    assert str(len(result.matches)) in pivot_text
    assert "Analyst evidence: Supporting" in pivot_text
    assert "Why:" in pivot_text
    assert "RELATED ENTITIES" in related_text
    assert "Why:" in related_text
    assert PIVOT_MENU_OPTIONS == (
        ("1", "Events"), ("2", "Alerts"), ("3", "Cases"), ("4", "Evidence"),
        ("5", "Hypotheses"), ("6", "Related Entities"), ("7", "Timeline"),
    )


def test_handoff_workspace_preview_lifecycle_and_artifacts(tmp_path):
    _analysis, current, _context, _timeline = _state(tmp_path)
    workspace = render_handoff_workspace(
        current, source_available=True, last_result=None, width=100, ansi=False
    )
    preview = render_handoff_preview(_preview(), width=100, ansi=False)

    assert "INV-QUERY" in workspace and "HANDOFF" in workspace
    assert "HANDOFF STATE" in workspace
    assert "Read-only snapshot/export workflow" in workspace
    assert "[AVAILABLE]" in workspace
    assert "Last export" in workspace and "None" in workspace
    assert HANDOFF_MENU_GROUPS == (
        ("HANDOFF REVIEW", (("1", "Preview Handoff"), ("4", "View Last Handoff Result"))),
        ("HANDOFF OPERATIONS", (("2", "Export Handoff"), ("3", "Validate Handoff Bundle"))),
    )

    assert "ACTIVE FINDINGS" in preview
    assert "HISTORICAL / SUPERSEDED FINDINGS" in preview
    assert "[ACTIVE]" in preview and "[SUPERSEDED]" in preview
    assert "FIND-ACTIVE" in preview and "FIND-OLD" in preview
    assert "Later evidence refined the conclusion." in preview
    assert "Supersession author: Analyst" in preview
    assert "Superseded at: 2026-08-14T10:01:00Z" in preview
    assert "ARTIFACTS" in preview
    assert "[AVAILABLE]" in preview
    assert "hunts" in preview
    assert "sensitive telemetry" in preview
    assert "Terminal scrollback" in preview


def test_handoff_result_and_validation_are_explicit_and_read_only(tmp_path):
    manifest = _manifest(tmp_path)
    result = HandoffResult(
        handoff_id="HANDOFF-001",
        investigation_id="INV-QUERY",
        revision=8,
        output_path=Path("out/handoffs/INV-QUERY"),
        manifest_path=Path("out/handoffs/INV-QUERY/manifest.json"),
        files=manifest.files,
        warnings=(),
        validation_status="valid",
    )
    exported = render_handoff_result(result, width=100, ansi=False)
    validated = render_handoff_manifest(
        manifest, validation=True, width=100, ansi=False
    )

    assert "HANDOFF EXPORT COMPLETE" in exported
    assert "[VALID]" in exported
    assert "out/handoffs/INV-QUERY" in exported
    assert "Investigation state was not modified." in exported
    assert "HANDOFF VALIDATION" in validated
    assert "[VALID]" in validated
    assert "Schema version" in validated and "1.2" in validated
    assert "Digest status" in validated and "verified" in validated
    assert "Reference integrity" in validated and "verified" in validated


def test_no_color_preserves_timeline_and_handoff_statuses(monkeypatch, tmp_path):
    _analysis, current, _context, timeline = _state(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    timeline_text, _ordered = render_timeline(timeline, width=80)
    rendered = "\n".join(
        (
            render_timeline_workspace(current, timeline, source_mode="full", width=80),
            timeline_text,
            render_handoff_workspace(
                current, source_available=False, last_result=None, width=80
            ),
            render_handoff_preview(_preview(), width=80),
            render_handoff_manifest(_manifest(tmp_path), validation=True, width=80),
        )
    )

    assert "\x1b" not in rendered
    for state in (
        "[FULL]", "[MACHINE]", "[ANALYST]", "[OFFLINE]", "[ACTIVE]",
        "[SUPERSEDED]", "[AVAILABLE]", "[VALID]",
    ):
        assert state in rendered


def test_timeline_and_handoff_rendering_do_not_mutate_inputs(tmp_path):
    analysis, current, context, timeline = _state(tmp_path)
    preview = _preview()
    manifest = _manifest(tmp_path)
    before = deepcopy((analysis, current, timeline, preview, manifest))

    render_timeline_workspace(current, timeline, source_mode="full", ansi=False)
    render_timeline(timeline, ansi=False)
    for entry in timeline.entries + timeline.untimed_entries:
        render_timeline_entry_detail(entry, ansi=False)
    pivot_service = InvestigationPivotService()
    render_pivot_result(
        "Events",
        pivot_service.events_for_entity(context, "host", "WS-LAB-01"),
        ansi=False,
    )
    render_related_entities(
        pivot_service.related_entities(context, "host", "WS-LAB-01"),
        ansi=False,
    )
    render_handoff_workspace(
        current, source_available=True, last_result=None, ansi=False
    )
    render_handoff_preview(preview, ansi=False)
    render_handoff_manifest(manifest, validation=True, ansi=False)

    assert (analysis, current, timeline, preview, manifest) == before
