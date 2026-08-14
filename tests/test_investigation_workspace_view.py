from copy import deepcopy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.investigations.workspace_view import (
    INVESTIGATION_WORKSPACE_GROUPS,
    render_investigation_workspace,
)
from soc_forge.ui.terminal import strip_ansi, visible_length


def _finding(finding_id, *, lifecycle_state="active", **kwargs):
    return InvestigationFinding(
        finding_id=finding_id,
        investigation_id="INV-QUERY",
        title=f"Finding {finding_id}",
        conclusion="Bounded analyst conclusion.",
        status="substantiated",
        confidence="high",
        author="Analyst",
        created_at="2026-08-10T14:12:00Z",
        updated_at="2026-08-10T14:13:00Z",
        lifecycle_state=lifecycle_state,
        hypothesis_ids=("HYP-001",),
        **kwargs,
    )


def rich_workspace(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)
    historical = _finding(
        "FIND-OLD",
        lifecycle_state="superseded",
        superseded_by_finding_id="FIND-ACTIVE",
        supersession_reason="Later evidence refined the conclusion.",
        supersession_author="Analyst",
        superseded_at="2026-08-10T14:14:00Z",
    )
    active = _finding("FIND-ACTIVE", supersedes_finding_id="FIND-OLD")
    return analysis, WorkspaceResult(
        replace(investigation, findings=(historical, active)),
        revision=8,
    )


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_workspace_render_is_width_safe_and_preserves_identity(width, tmp_path):
    _, current = rich_workspace(tmp_path)
    rendered = render_investigation_workspace(current, width=width, ansi=False)
    expected_width = max(24, width)

    assert all(visible_length(line) <= expected_width for line in rendered.splitlines())
    assert "INVESTIGATION OV" in rendered
    assert "INVESTIGATION ST" in rendered
    assert "INV-QUERY" in rendered
    assert ("Query investigation" if width >= 60 else "Query inve") in rendered
    assert "Analyst" in rendered
    assert "[IN PROGRESS]" in rendered
    assert "8" in rendered
    if width >= 60:
        assert current.investigation.analysis_id[:20] in rendered
        assert "CASE-001" in rendered
    else:
        assert "SOC-FORGE" in rendered


def test_workspace_state_preserves_all_authoritative_counts(tmp_path):
    _, current = rich_workspace(tmp_path)
    rendered = render_investigation_workspace(current, width=100, ansi=False)

    assert "1 scope | 3 selected" in rendered
    assert "1 supporting | 1 contradicting | 1 context" in rendered
    assert "1 total | 1 open | 0 supported" in rendered
    assert "0 rejected | 0 inconclusive" in rendered
    assert "2 total | 1 active | 1 historical" in rendered
    assert "Decisions" in rendered and "3" in rendered
    assert "Annotations" in rendered and "1" in rendered


def test_workspace_narrow_state_keeps_each_count_meaningful(tmp_path):
    _, current = rich_workspace(tmp_path)
    rendered = render_investigation_workspace(current, width=60, ansi=False)

    for label, value in (
        ("Scope references", "1"),
        ("Analyst-selected", "3"),
        ("Supporting", "1"),
        ("Contradicting", "1"),
        ("Context", "1"),
        ("Hypotheses", "1"),
        ("Open", "1"),
        ("Supported", "0"),
        ("Rejected", "0"),
        ("Inconclusive", "0"),
        ("Findings", "2"),
        ("Active Findings", "1"),
        ("Finding history", "1"),
        ("Decisions", "3"),
        ("Annotations", "1"),
    ):
        assert any(label in line and value in line for line in rendered.splitlines())


def test_workspace_grouped_navigation_preserves_locked_numbers():
    assert INVESTIGATION_WORKSPACE_GROUPS == (
        ("ANALYSIS", (("1", "Investigation Summary"), ("10", "Evidence Workspace"), ("11", "Hypotheses and Decisions"), ("12", "Investigation Findings"), ("13", "Timeline and Pivot Workbench (Read Only)"))),
        ("RESPONSE", (("16", "Response Actions"),)),
        ("CASE MANAGEMENT", (("2", "Assign or Clear Owner"), ("3", "Change Status"), ("4", "Reopen Investigation"))),
        ("ANNOTATIONS & DECISIONS", (("5", "View Annotations"), ("6", "Add Annotation"), ("7", "Edit Annotation"), ("8", "Remove Annotation"), ("9", "View Decisions"))),
        ("OUTPUT & RECOVERY", (("14", "Investigation Handoff (Read Only)"), ("15", "Load Source Analysis Snapshot"))),
    )
    flattened = {
        number: label
        for _heading, options in INVESTIGATION_WORKSPACE_GROUPS
        for number, label in options
    }
    assert flattened == {
        "1": "Investigation Summary",
        "2": "Assign or Clear Owner",
        "3": "Change Status",
        "4": "Reopen Investigation",
        "5": "View Annotations",
        "6": "Add Annotation",
        "7": "Edit Annotation",
        "8": "Remove Annotation",
        "9": "View Decisions",
        "10": "Evidence Workspace",
        "11": "Hypotheses and Decisions",
        "12": "Investigation Findings",
        "13": "Timeline and Pivot Workbench (Read Only)",
        "14": "Investigation Handoff (Read Only)",
        "15": "Load Source Analysis Snapshot",
        "16": "Response Actions",
    }


def test_workspace_no_color_and_dumb_terminal_remain_meaningful(monkeypatch, tmp_path):
    _, current = rich_workspace(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    rendered = render_investigation_workspace(current, width=80)

    assert "\x1b" not in rendered
    assert "[IN PROGRESS]" in rendered
    assert "[0] Back" in rendered


def test_workspace_long_values_are_bounded_without_mutation(tmp_path):
    _, current = rich_workspace(tmp_path)
    metadata = replace(current.investigation.metadata, title="Long title " + "X" * 300)
    analysis_id = "analysis-" + "a" * 300
    references = tuple(
        replace(item, source_analysis_id=analysis_id)
        if item.origin == "analyst_selection"
        else item
        for item in current.investigation.evidence_references
    )
    investigation = replace(
        current.investigation,
        analysis_id=analysis_id,
        metadata=metadata,
        evidence_references=references,
    )
    long_current = WorkspaceResult(investigation, current.revision)
    before = deepcopy(long_current)

    rendered = render_investigation_workspace(long_current, width=60, ansi=False)

    assert long_current == before
    assert "..." in rendered
    assert all(visible_length(line) <= 60 for line in rendered.splitlines())


def test_workspace_render_is_passive_for_repository_analysis_and_artifacts(tmp_path):
    analysis, current = rich_workspace(tmp_path / "analysis")
    repository_file = tmp_path / "investigation.json"
    repository_file.write_text(json.dumps(current.investigation.to_dict(), sort_keys=True), encoding="utf-8")
    before_repository = repository_file.read_bytes()
    before_analysis = deepcopy(analysis)
    before_investigation = deepcopy(current.investigation)
    before_artifacts = {
        key: Path(path).read_bytes() for key, path in analysis.artifacts.items()
    }

    render_investigation_workspace(current, width=80, ansi=False)

    assert repository_file.read_bytes() == before_repository
    assert analysis == before_analysis
    assert current.revision == 8
    assert current.investigation == before_investigation
    assert {
        key: Path(path).read_bytes() for key, path in analysis.artifacts.items()
    } == before_artifacts


def test_workspace_renders_without_active_analysis_or_snapshot_loading(tmp_path):
    _, current = rich_workspace(tmp_path)

    rendered = render_investigation_workspace(current, width=80, ansi=False)

    assert current.investigation.analysis_id in rendered
    assert "Load Source Analysis Snapshot" in rendered


@pytest.mark.parametrize(
    ("choice", "expected"),
    (
        ("1", "summary"),
        ("2", "owner"),
        ("3", "status"),
        ("4", "reopen"),
        ("5", "view_annotations"),
        ("6", "add_annotation"),
        ("7", "edit_annotation"),
        ("8", "remove_annotation"),
        ("9", "view_decisions"),
        ("10", "evidence"),
        ("11", "reasoning"),
        ("12", "findings"),
        ("13", "timeline"),
        ("14", "handoff"),
        ("15", "snapshot"),
    ),
)
def test_visual_grouping_does_not_change_dispatch(
    monkeypatch, tmp_path, choice, expected
):
    from test_investigation_console import ScriptedInput, build_controller

    analysis, current = rich_workspace(tmp_path / "analysis")
    controller, _, _ = build_controller(tmp_path / "controller", analysis=analysis)
    calls = []

    class Nested:
        def __init__(self, name):
            self.name = name

        def run(self, value):
            calls.append(self.name)
            return value

    for attribute, name in (
        ("summary_controller", "summary"),
        ("evidence_controller", "evidence"),
        ("reasoning_controller", "reasoning"),
        ("finding_controller", "findings"),
        ("query_controller", "timeline"),
        ("handoff_controller", "handoff"),
    ):
        setattr(controller, attribute, Nested(name))

    for attribute, name in (
        ("_assign_owner", "owner"),
        ("_change_status", "status"),
        ("_reopen", "reopen"),
        ("_add_annotation", "add_annotation"),
        ("_edit_annotation", "edit_annotation"),
        ("_remove_annotation", "remove_annotation"),
    ):
        monkeypatch.setattr(
            controller,
            attribute,
            lambda value, name=name: calls.append(name) or value,
        )
    for attribute, name in (
        ("_view_annotations", "view_annotations"),
        ("_view_decisions", "view_decisions"),
        ("load_source_analysis", "snapshot"),
    ):
        monkeypatch.setattr(
            controller,
            attribute,
            lambda _value, name=name: calls.append(name),
        )

    controller.input = ScriptedInput((choice, "0"))

    returned = controller.workspace_loop(current)

    assert returned is current
    assert calls == [expected]
