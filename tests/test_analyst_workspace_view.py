from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.analyst_workspace_view import (
    EVIDENCE_MENU_GROUPS,
    FINDINGS_MENU_GROUPS,
    REASONING_MENU_GROUPS,
    render_decision,
    render_evidence_candidate,
    render_evidence_workspace,
    render_finding_detail,
    render_finding_list,
    render_findings_workspace,
    render_hypothesis,
    render_reasoning_workspace,
    render_selected_evidence,
)
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.terminal import strip_ansi, visible_length


def _finding(finding_id, *, lifecycle_state="active", evidence_ids=(), **kwargs):
    return InvestigationFinding(
        finding_id=finding_id,
        investigation_id="INV-QUERY",
        title=f"Finding {finding_id} with a deliberately descriptive analyst title",
        conclusion=(
            "Analyst concludes the observed activity warrants review while "
            "preserving uncertainty and avoiding machine-certainty language."
        ),
        status="substantiated",
        confidence="high",
        author="Analyst",
        created_at="2026-08-10T14:12:00Z",
        updated_at="2026-08-10T14:13:00Z",
        evidence_ids=evidence_ids,
        hypothesis_ids=("HYP-001",),
        decision_ids=("DEC-ASSESS",),
        attack_tactics=("Defense Evasion",),
        attack_techniques=("T1562.001",),
        limitations=("Command-line visibility is incomplete.",),
        lifecycle_state=lifecycle_state,
        **kwargs,
    )


def _workspace(tmp_path):
    analysis = build_query_analysis(tmp_path)
    investigation = build_query_investigation(analysis)
    evidence_id = next(
        item.reference_id
        for item in investigation.evidence_references
        if item.origin == "analyst_selection" and item.classification == "supporting"
    )
    historical = _finding(
        "FIND-OLD",
        lifecycle_state="superseded",
        evidence_ids=(evidence_id,),
        superseded_by_finding_id="FIND-ACTIVE",
        supersession_reason="Later evidence refined the analyst conclusion.",
        supersession_author="Analyst",
        superseded_at="2026-08-10T14:14:00Z",
    )
    active = _finding(
        "FIND-ACTIVE",
        evidence_ids=(evidence_id,),
        supersedes_finding_id="FIND-OLD",
    )
    return analysis, WorkspaceResult(
        replace(investigation, findings=(historical, active)),
        revision=8,
    )


def _summary():
    return SimpleNamespace(
        total_hypotheses=1,
        open=1,
        supported=0,
        rejected=0,
        inconclusive=0,
        decision_count=3,
    )


def _assert_width_safe(rendered, width):
    expected = max(24, width)
    assert all(visible_length(line) <= expected for line in rendered.splitlines())


@pytest.mark.parametrize("width", (100, 80, 60, 10))
def test_all_analyst_workspaces_are_width_safe(width, tmp_path):
    _analysis, current = _workspace(tmp_path)
    outputs = (
        render_evidence_workspace(current, width=width, ansi=False),
        render_reasoning_workspace(current, _summary(), width=width, ansi=False),
        render_findings_workspace(current, width=width, ansi=False),
        render_hypothesis(
            current, current.investigation.hypotheses[0], width=width, ansi=False
        ),
        render_decision(
            current.investigation.decisions[0], width=width, ansi=False
        ),
        render_finding_detail(
            current.investigation.findings[0], width=width, ansi=False
        ),
    )
    for rendered in outputs:
        _assert_width_safe(rendered, width)


def test_workspace_breadcrumbs_state_and_locked_menus(tmp_path):
    _analysis, current = _workspace(tmp_path)
    evidence = render_evidence_workspace(current, width=100, ansi=False)
    reasoning = render_reasoning_workspace(
        current, _summary(), width=100, ansi=False
    )
    findings = render_findings_workspace(current, width=100, ansi=False)

    assert "INV-QUERY" in evidence and "EVIDENCE" in evidence
    assert "EVIDENCE STATE" in evidence
    for label, value in (
        ("Scope references", "1"),
        ("Selected evidence", "3"),
        ("Supporting", "1"),
        ("Contradicting", "1"),
        ("Context", "1"),
    ):
        assert any(label in line and value in line for line in evidence.splitlines())

    assert "INV-QUERY" in reasoning and "REASONING" in reasoning
    assert "REASONING STATE" in reasoning
    assert "analyst assessment" in reasoning
    assert "Hypotheses" in reasoning and "Decisions" in reasoning
    assert "Terminal scrollback may retain analyst reasoning" in reasoning

    assert "INV-QUERY" in findings and "FINDINGS" in findings
    assert "FINDINGS STATE" in findings
    assert "Active" in findings and "Historical" in findings

    assert EVIDENCE_MENU_GROUPS == (
        ("EVIDENCE REVIEW", (("1", "Browse Evidence Candidates"), ("2", "View Selected Evidence"), ("3", "Inspect Selected Evidence"))),
        ("EVIDENCE MANAGEMENT", (("4", "Update Selected Evidence"), ("5", "Remove Selected Evidence"))),
    )
    assert REASONING_MENU_GROUPS == (
        ("REASONING REVIEW", (("1", "View Reasoning Summary"), ("2", "List Hypotheses"), ("4", "Open Hypothesis"), ("5", "View Decisions"))),
        ("REASONING AUTHORING", (("3", "Create Hypothesis"), ("6", "Record Investigation Decision"))),
    )
    assert FINDINGS_MENU_GROUPS == (
        ("FINDINGS REVIEW", (("1", "List Findings"), ("3", "Open Finding"))),
        ("FINDINGS AUTHORING", (("2", "Create Finding"),)),
    )


def test_evidence_candidates_and_selected_relationship_badges(tmp_path):
    analysis, current = _workspace(tmp_path)
    catalog = AnalysisEvidenceCatalog()
    candidates = catalog.list_candidates(analysis, case_ids=("CASE-001",))
    sensitive = next(item for item in candidates if item.sensitive_fields)
    candidate = render_evidence_candidate(1, sensitive, width=80, ansi=False)

    assert "Candidate" in candidate and "1" in candidate
    assert sensitive.evidence_id in candidate
    assert sensitive.evidence_type in candidate
    assert "[SENSITIVE]" in candidate
    assert "very-sensitive" not in candidate

    selected = [
        render_selected_evidence(item, width=80, ansi=False)
        for item in current.investigation.evidence_references
        if item.origin == "analyst_selection"
    ]
    rendered = "\n".join(selected)
    assert "[SUPPORTING]" in rendered
    assert "[CONTRADICTING]" in rendered
    assert "[CONTEXT]" in rendered
    assert "Rationale:" in rendered
    assert "Source identifier" in rendered


def test_hypothesis_and_decision_cards_preserve_reasoning_relationships(tmp_path):
    _analysis, current = _workspace(tmp_path)
    hypothesis = render_hypothesis(
        current, current.investigation.hypotheses[0], width=100, ansi=False
    )
    decision = render_decision(
        current.investigation.decisions[0], width=100, ansi=False
    )

    assert "ANALYST HYPOTHESIS" in hypothesis
    assert "Analyst assessment" in hypothesis and "[OPEN]" in hypothesis
    model = current.investigation.hypotheses[0]
    assert model.supporting_evidence_reference_ids[0] in hypothesis
    assert "supporting" in hypothesis
    assert model.contradicting_evidence_reference_ids[0] in hypothesis
    assert "contradicting" in hypothesis
    assert "DEC-GENERAL" in hypothesis

    assert "ANALYST DECISION" in decision
    assert "hypothesis_assessment" in decision
    assert "supported" in decision
    assert "Evidence supported the working hypothesis" in decision
    assert "HYP-001" in decision


def test_findings_keep_active_and_history_visually_distinct(tmp_path):
    _analysis, current = _workspace(tmp_path)
    rendered = render_finding_list(
        current.investigation.findings, width=100, ansi=False
    )
    historical = render_finding_detail(
        current.investigation.findings[0], width=100, ansi=False
    )

    assert rendered.index("ACTIVE FINDINGS") < rendered.index(
        "HISTORICAL / SUPERSEDED FINDINGS"
    )
    assert "[ACTIVE]" in rendered
    assert "[SUPERSEDED]" in rendered
    assert "FIND-ACTIVE" in rendered and "FIND-OLD" in rendered

    for value in (
        "ANALYST-AUTHORED FINDING",
        "substantiated",
        "high",
        current.investigation.findings[0].evidence_ids[0],
        "HYP-001",
        "DEC-ASSESS",
        "Defense Evasion",
        "T1562.001",
        "Command-line visibility is incomplete.",
        "FIND-ACTIVE",
        "Later evidence refined the analyst conclusion.",
        "Analyst",
        "2026-08-10T14:14:00Z",
    ):
        assert value.upper() in historical.upper()
    assert "not represent machine certainty" in historical


def test_long_analyst_text_wraps_without_information_loss(tmp_path):
    _analysis, current = _workspace(tmp_path)
    selected = next(
        item
        for item in current.investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    reference = replace(selected, rationale="reason " * 35)
    hypothesis = replace(
        current.investigation.hypotheses[0], statement="statement " * 35
    )
    finding = replace(
        current.investigation.findings[1], conclusion="conclusion " * 35
    )

    outputs = (
        render_selected_evidence(reference, width=60, ansi=False),
        render_hypothesis(current, hypothesis, width=60, ansi=False),
        render_finding_detail(finding, width=60, ansi=False),
    )
    for rendered in outputs:
        _assert_width_safe(rendered, 60)
    assert outputs[0].count("reason") == 35
    assert outputs[1].count("statement") == 35
    assert outputs[2].count("conclusion") == 35


def test_no_color_preserves_all_semantic_states(monkeypatch, tmp_path):
    _analysis, current = _workspace(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    rendered = "\n".join(
        (
            render_evidence_workspace(current, width=80),
            render_selected_evidence(
                current.investigation.evidence_references[1], width=80
            ),
            render_reasoning_workspace(current, _summary(), width=80),
            render_hypothesis(
                current, current.investigation.hypotheses[0], width=80
            ),
            render_findings_workspace(current, width=80),
            render_finding_list(current.investigation.findings, width=80),
        )
    )

    assert "\x1b" not in rendered
    for state in ("[SUPPORTING]", "[OPEN]", "[ACTIVE]", "[SUPERSEDED]"):
        assert state in rendered


def test_rendering_is_passive_and_does_not_mutate_domain_or_analysis(tmp_path):
    analysis, current = _workspace(tmp_path)
    analysis_before = deepcopy(analysis)
    current_before = deepcopy(current)

    render_evidence_workspace(current, width=80, ansi=False)
    for reference in current.investigation.evidence_references:
        render_selected_evidence(reference, width=80, ansi=False)
    render_reasoning_workspace(current, _summary(), width=80, ansi=False)
    render_hypothesis(
        current, current.investigation.hypotheses[0], width=80, ansi=False
    )
    for decision in current.investigation.decisions:
        render_decision(decision, width=80, ansi=False)
    render_findings_workspace(current, width=80, ansi=False)
    render_finding_list(current.investigation.findings, width=80, ansi=False)
    for finding in current.investigation.findings:
        render_finding_detail(finding, width=80, ansi=False)

    assert analysis == analysis_before
    assert current == current_before
