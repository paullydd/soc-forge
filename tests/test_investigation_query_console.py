import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.evidence_catalog import EvidenceCatalogError
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_console import InvestigationQueryConsoleController
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.query_models import InvestigationTimelineFilters
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


class ScriptedInput:
    def __init__(self, values=()):
        self.values = iter(values)
        self.calls = 0

    def __call__(self, _prompt=""):
        self.calls += 1
        return next(self.values)


class EvidenceDetails:
    def __init__(self):
        self.calls = []
        self.workspace_calls = []

    def show_candidate_details(self, analysis, candidate):
        self.calls.append((analysis, candidate.evidence_id))

    def show_evidence_details(self, current, evidence_id):
        self.workspace_calls.append((current.revision, evidence_id))


class ReasoningDetails:
    def __init__(self):
        self.hypotheses = []
        self.decisions = []

    def show_hypothesis_details(self, current, hypothesis_id):
        self.hypotheses.append((current.revision, hypothesis_id))

    def show_decision_details(self, current, decision_id):
        self.decisions.append((current.revision, decision_id))


def build_workbench(tmp_path, inputs=(), analysis_marker=True):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    current = service.get_investigation(investigation.investigation_id)
    evidence = EvidenceDetails()
    reasoning = ReasoningDetails()
    messages = []
    active = analysis if analysis_marker is True else analysis_marker
    controller = InvestigationQueryConsoleController(
        workspace_service=service,
        analysis_provider=lambda: active,
        evidence_controller=evidence,
        reasoning_controller=reasoning,
        input_func=ScriptedInput(inputs),
        output_func=messages.append,
        screen_func=lambda _title: None,
    )
    context = InvestigationQueryContext(analysis, investigation)
    return controller, analysis, service, current, context, evidence, reasoning, messages


def artifact_hashes(analysis):
    return {
        key: sha256(path.read_bytes()).hexdigest()
        for key, path in analysis.artifacts.items()
    }


def repository_bytes(tmp_path):
    return next((tmp_path / "workspace" / "investigations").glob("*.json")).read_bytes()


def test_workbench_menu_is_read_only_and_back_returns_unchanged(tmp_path):
    controller, _, _, current, _, _, _, messages = build_workbench(tmp_path, ["0"])

    assert controller.run(current) == current

    output = "\n".join(messages)
    assert "Timeline/Pivot Workbench - Read Only" in output
    assert "[1] Investigation timeline" in output
    assert "[8] Refresh workbench" in output


def test_no_active_analysis_returns_without_touching_workspace(tmp_path):
    controller, _, _, current, _, _, _, messages = build_workbench(
        tmp_path, analysis_marker=None
    )
    before = repository_bytes(tmp_path)

    assert controller.run(current) == current
    assert repository_bytes(tmp_path) == before
    assert any("matching completed analysis" in item for item in messages)


def test_missing_active_analysis_diagnostic_waits_for_acknowledgement(tmp_path):
    controller, _, _, current, _, _, _, messages = build_workbench(
        tmp_path, analysis_marker=None
    )
    pause_views = []
    controller.pause = lambda: pause_views.append(tuple(messages))

    assert controller.run(current) == current

    assert len(pause_views) == 1
    assert any("matching completed analysis" in line for line in pause_views[0])


def test_provenance_mismatch_diagnostic_waits_for_acknowledgement(tmp_path):
    controller, _, _, current, _, _, _, messages = build_workbench(tmp_path)
    other = build_query_analysis(tmp_path / "other-runtime")
    other.input_name = "different-runtime.jsonl"
    controller.analysis_provider = lambda: other
    pause_views = []
    controller.pause = lambda: pause_views.append(tuple(messages))

    assert controller.run(current) == current

    assert len(pause_views) == 1
    assert any("does not match" in line for line in pause_views[0])


def test_provenance_mismatch_is_concise_and_safe(tmp_path):
    controller, _, _, current, _, _, _, messages = build_workbench(tmp_path)
    other = build_query_analysis(tmp_path / "other")
    other.input_name = "different.jsonl"
    controller.analysis_provider = lambda: other

    assert controller.run(current) == current
    output = "\n".join(messages)
    assert "does not match" in output
    assert str(tmp_path) not in output


def test_matching_context_opens_and_refresh_uses_latest_revision(tmp_path):
    controller, _, service, current, _, _, _, messages = build_workbench(
        tmp_path, ["8", "0"]
    )
    latest = service.assign_owner(
        current.investigation.investigation_id,
        "other-session",
        expected_revision=current.revision,
    )

    returned = controller.run(current)

    assert returned == latest
    assert any("refreshed to revision 2" in item for item in messages)


def test_stale_revision_blocks_queries_until_refresh(tmp_path):
    controller, _, service, current, _, _, _, messages = build_workbench(
        tmp_path, ["1", "8", "0"]
    )
    service.assign_owner(
        current.investigation.investigation_id,
        "other-session",
        expected_revision=current.revision,
    )
    calls = []
    controller.timeline_screen = lambda *_args: calls.append("timeline")

    controller.run(current)

    assert calls == []
    assert "Refresh Workbench is required before running this query." in messages


def test_render_timeline_preserves_service_order_and_separates_untimed(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    timeline = InvestigationTimelineService().timeline(context)

    rendered = controller.render_timeline(timeline)

    assert rendered == timeline.entries + timeline.untimed_entries
    assert messages.index("Chronological Activity") < messages.index(
        "Untimed Investigation Context"
    )
    rows = [item for item in messages if item.startswith("[")]
    for index, (entry, row) in enumerate(zip(rendered, rows), start=1):
        short_id = entry.entry_id if len(entry.entry_id) <= 28 else entry.entry_id[:25]
        assert row.startswith(f"[{index}] ")
        assert short_id in row


def test_timeline_lists_hide_sensitive_payloads_and_rationales(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)

    controller.render_timeline(InvestigationTimelineService().timeline(context))

    output = "\n".join(messages)
    assert "powershell.exe -enc sensitive" not in output
    assert "Supports defense-evasion hypothesis" not in output
    assert "Senior review required" not in output
    assert "Sensitive annotation body" not in output
    assert "SENSITIVE" in output
    assert "Analyst evidence: Supporting" in output
    assert "Hypothesis overlay" in output
    assert "Decision overlay" in output


def test_timeline_distinguishes_machine_and_analyst_entries(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    controller.render_timeline(InvestigationTimelineService().timeline(context))
    output = "\n".join(messages)
    assert "| MACHINE |" in output
    assert "| ANALYST |" in output


def test_entry_detail_renders_query_reason_without_invention(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    entry = next(
        item
        for item in InvestigationTimelineService().timeline(context).entries
        if item.source_id == "ALERT-001"
    )

    controller.render_entry_detail(entry)

    output = "\n".join(messages)
    assert f"Why this entry is present: {entry.relationship_reason}" in output
    assert "Source analysis ID:" in output
    assert "Evidence classification: supporting" in output
    assert "Decision overlay: DEC-ASSESS | hypothesis_assessment" in output
    assert "Rationale:" not in output


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("start_time", "2026-08-10T14:00:00Z", "2026-08-10T14:00:00Z"),
        ("end_time", "2026-08-10T14:10:00Z", "2026-08-10T14:10:00Z"),
        ("entry_types", "alert", ("alert",)),
        ("host", "WS-LAB-01", "WS-LAB-01"),
        ("user", "DOMAIN\\alice", "DOMAIN\\alice"),
        ("ip", "10.0.0.5", "10.0.0.5"),
        ("process", "powershell.exe", "powershell.exe"),
        ("rule_id", "SOCF-021", "SOCF-021"),
        ("attack_tactic", "Defense Evasion", "Defense Evasion"),
        ("attack_technique", "T1562.001", "T1562.001"),
        ("severity", "high", "high"),
        ("evidence_classification", "supporting", "supporting"),
        ("hypothesis_id", "HYP-001", "HYP-001"),
        ("case_id", "CASE-001", "CASE-001"),
    ],
)
def test_each_controlled_filter_is_forwarded_to_timeline_service(
    tmp_path, field, value, expected
):
    controller, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    controller.adjust_filter(field, value)

    timeline = controller.timeline_service.timeline(context, filters=controller.filters)

    assert getattr(timeline.applied_filters, field) == expected


def test_multiple_filters_keep_service_and_semantics(tmp_path):
    controller, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    controller.adjust_filter("host", "WS-LAB-01")
    controller.adjust_filter("rule_id", "SOCF-021")

    timeline = controller.timeline_service.timeline(context, filters=controller.filters)

    assert timeline.entries
    assert all(item.host == "WS-LAB-01" for item in timeline.entries)
    assert all(item.rule_id == "SOCF-021" for item in timeline.entries)


def test_adjust_and_clear_filters_are_transient(tmp_path):
    controller, _, _, current, _, _, _, _ = build_workbench(tmp_path)
    controller.adjust_filter("host", "WS-LAB-01")
    assert controller.filters.host == "WS-LAB-01"
    controller.filters = InvestigationTimelineFilters()
    assert controller.filters == InvestigationTimelineFilters()
    assert current.revision == 1


def test_invalid_filter_is_rejected_by_query_service(tmp_path):
    controller, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    controller.adjust_filter("entry_types", "unsupported")
    with pytest.raises(Exception):
        controller.timeline_service.timeline(context, filters=controller.filters)


@pytest.mark.parametrize(
    "entity_type",
    [
        "host",
        "user",
        "ip",
        "process",
        "service",
        "rule",
        "attack_technique",
        "case",
        "evidence",
        "hypothesis",
    ],
)
def test_entity_browser_discovers_each_supported_type(tmp_path, entity_type):
    controller, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    assert any(item.entity_type == entity_type for item in controller.entities(context))


def test_entity_browser_preserves_query_normalization(tmp_path):
    controller, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    entities = controller.entities(context)
    user = next(item for item in entities if item.entity_type == "user")
    process = next(
        item
        for item in entities
        if item.entity_type == "process" and item.secondary_key == "powershell.exe"
    )
    ip = next(item for item in entities if item.entity_type == "ip")
    assert user.display_value == "DOMAIN\\alice"
    assert user.normalized_value == "domain\\alice"
    assert process.secondary_key == "powershell.exe"
    assert ip.normalized_value == "10.0.0.5"


@pytest.mark.parametrize(
    ("entity_type", "value"),
    [
        ("host", "WS-LAB-01"),
        ("user", "DOMAIN\\alice"),
        ("ip", "10.0.0.5"),
        ("process", "powershell.exe"),
        ("rule", "SOCF-021"),
        ("attack_technique", "T1562.001"),
        ("case", "CASE-001"),
        ("evidence", "evidence:alert:ALERT-001"),
        ("hypothesis", "HYP-001"),
    ],
)
def test_pivot_categories_use_query_service(tmp_path, entity_type, value):
    _, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    service = InvestigationPivotService()
    assert service.evidence_for_entity(context, entity_type, value).entity.entity_type == entity_type
    assert service.hypotheses_for_entity(context, entity_type, value).entity.entity_type == entity_type
    assert service.timeline_for_entity(context, entity_type, value).investigation_id == "INV-QUERY"


def test_pivot_rendering_includes_relationship_reason_and_overlays(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    result = controller.pivot_service.evidence_for_entity(context, "host", "WS-LAB-01")

    controller.render_pivot_result("Evidence", result)

    output = "\n".join(messages)
    assert "Relationship:" in output
    assert "Why:" in output
    assert "Analyst evidence: Supporting" in output
    assert "Hypothesis: HYP-001" in output
    assert "Evidence supported the working hypothesis" not in output


def test_related_entities_are_observed_not_causal_and_deduplicated(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    result = controller.pivot_service.related_entities(context, "host", "WS-LAB-01")
    controller.render_related_entities(result)
    output = "\n".join(messages)
    assert "Observed relationships" in output
    assert "Directly observed on the same source record" in output
    assert "caused by" not in output
    keys = [
        (item.entity.entity_type, item.entity.normalized_value, item.entity.secondary_key)
        for item in result.relationships
    ]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize(
    ("choice", "expected"),
    [
        ("1", "Events"),
        ("2", "Alerts"),
        ("3", "Cases"),
        ("4", "Evidence"),
        ("5", "Hypotheses"),
        ("6", "Observed relationships"),
        ("7", "Chronological Activity"),
    ],
)
def test_pivot_read_results_remain_visible_until_one_pause(tmp_path, choice, expected):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    scripted_input = ScriptedInput([choice])
    pause_views = []
    controller.input = scripted_input
    controller.pause = lambda: pause_views.append(tuple(messages))
    entity = next(item for item in controller.entities(context) if item.entity_type == "host")

    controller.pivot_screen(context, entity)

    assert scripted_input.calls == 1
    assert len(pause_views) == 1
    assert any(expected in line for line in pause_views[0])


def test_related_entities_empty_state_remains_visible_until_pause(tmp_path):
    controller, _, _, _, context, _, _, messages = build_workbench(tmp_path)
    entity = next(item for item in controller.entities(context) if item.entity_type == "host")
    populated = controller.pivot_service.related_entities(context, entity.entity_type, entity.value)
    controller.pivot_service.related_entities = lambda *_args: replace(
        populated, relationships=()
    )
    controller.input = ScriptedInput(["6"])
    pause_views = []
    controller.pause = lambda: pause_views.append(tuple(messages))

    controller.pivot_screen(context, entity)

    assert len(pause_views) == 1
    assert "  None" in pause_views[0]


def test_direct_timeline_entity_pivot_uses_shared_result_pause(tmp_path):
    controller, _, _, current, context, _, _, messages = build_workbench(tmp_path)
    entry = next(
        item
        for item in InvestigationTimelineService().timeline(context).entries
        if item.source_id == "ALERT-001"
    )
    source = context.sources[entry.evidence_id]
    host_offset = next(
        index for index, item in enumerate(source.entities) if item.entity_type == "host"
    )
    navigation_choice = 4 + host_offset
    scripted_input = ScriptedInput([str(navigation_choice), "6"])
    pause_views = []
    controller.input = scripted_input
    controller.pause = lambda: pause_views.append(tuple(messages))

    controller.entry_navigation(current, context, entry)

    assert scripted_input.calls == 2
    assert len(pause_views) == 1
    assert any("Observed relationships" in line for line in pause_views[0])


def test_pivot_pause_does_not_mutate_workspace_or_analysis(tmp_path):
    controller, analysis, _, current, context, _, _, _ = build_workbench(tmp_path)
    repository_before = repository_bytes(tmp_path)
    artifacts_before = artifact_hashes(analysis)
    analysis_before = deepcopy(analysis)
    entity = next(item for item in controller.entities(context) if item.entity_type == "host")
    controller.input = ScriptedInput(["6"])
    controller.pause = lambda: None

    controller.pivot_screen(context, entity)

    assert repository_bytes(tmp_path) == repository_before
    assert artifact_hashes(analysis) == artifacts_before
    assert analysis == analysis_before
    assert current.revision == 1


def test_nearby_unrelated_source_is_not_added_to_host_pivot(tmp_path):
    _, _, _, _, context, _, _, _ = build_workbench(tmp_path)
    result = InvestigationPivotService().events_for_entity(
        context, "host", "WS-LAB-01"
    )
    assert {item.source_id for item in result.matches} == {"EVENT-001"}


def test_evidence_navigation_reuses_existing_detail_controller(tmp_path):
    controller, analysis, _, current, context, evidence, _, _ = build_workbench(
        tmp_path, ["1"]
    )
    controller.inspect_evidence(current, context)
    assert evidence.workspace_calls
    assert evidence.workspace_calls[0][0] == current.revision


def test_hypothesis_and_decision_navigation_reuse_reasoning_controller(tmp_path):
    controller, _, _, current, _, _, reasoning, _ = build_workbench(tmp_path, ["1"])
    controller.inspect_hypothesis(current)
    controller.show_decision(current, "DEC-GENERAL")
    assert reasoning.hypotheses == [(1, "HYP-001")]
    assert reasoning.decisions == [(1, "DEC-GENERAL")]


@pytest.mark.parametrize(
    ("choice", "expected"),
    [("1", "evidence"), ("2", "hypothesis"), ("3", "decision")],
)
def test_timeline_entry_navigation_reuses_existing_detail_controllers(
    tmp_path, choice, expected
):
    controller, _, _, current, context, evidence, reasoning, _ = build_workbench(
        tmp_path, [choice]
    )
    entry = next(
        item
        for item in InvestigationTimelineService().timeline(context).entries
        if item.source_id == "ALERT-001"
    )

    controller.entry_navigation(current, context, entry)

    if expected == "evidence":
        assert evidence.workspace_calls == [(1, entry.evidence_id)]
    elif expected == "hypothesis":
        assert reasoning.hypotheses == [(1, "HYP-001")]
    else:
        assert reasoning.decisions == [(1, "DEC-ASSESS")]


def test_missing_source_details_are_handled_without_payloads(tmp_path):
    controller, _, _, current, context, _, _, messages = build_workbench(tmp_path)
    controller.input = ScriptedInput(["1"])

    class SourceDetails:
        def show_candidate_details(self, _analysis, _candidate):
            raise AssertionError("missing candidate must not render")

    controller.evidence_controller = SourceDetails()
    context.evidence_catalog.get_candidate = lambda *_args: (_ for _ in ()).throw(
        EvidenceCatalogError("private parser detail /tmp/source")
    )
    controller.inspect_evidence(current, context)
    output = "\n".join(messages)
    assert "not currently available" in output
    assert "/tmp/source" not in output


def test_workbench_operations_leave_repository_analysis_and_artifacts_unchanged(tmp_path):
    controller, analysis, _, current, context, _, _, _ = build_workbench(tmp_path)
    repository_before = repository_bytes(tmp_path)
    artifacts_before = artifact_hashes(analysis)
    analysis_before = deepcopy(analysis)
    investigation_before = deepcopy(current.investigation)

    controller.render_timeline(controller.timeline_service.timeline(context))
    controller.adjust_filter("host", "WS-LAB-01")
    controller.timeline_service.timeline(context, filters=controller.filters)
    controller.pivot_service.related_entities(context, "host", "WS-LAB-01")

    assert repository_bytes(tmp_path) == repository_before
    assert artifact_hashes(analysis) == artifacts_before
    assert analysis == analysis_before
    assert current.investigation == investigation_before
    assert current.revision == 1


def test_timeline_entry_back_returns_to_timeline_before_workbench(tmp_path):
    controller, _, _, current, _, _, _, _ = build_workbench(tmp_path)
    scripted_input = ScriptedInput(["1", "1", "", "", "0"])
    screens = []
    controller.input = scripted_input
    controller.screen = screens.append

    assert controller.run(current) == current

    assert screens[:5] == [
        "TIMELINE/PIVOT WORKBENCH - READ ONLY",
        "INVESTIGATION TIMELINE - READ ONLY",
        "TIMELINE ENTRY DETAILS - READ ONLY",
        "INVESTIGATION TIMELINE - READ ONLY",
        "TIMELINE/PIVOT WORKBENCH - READ ONLY",
    ]
    assert scripted_input.calls == 5


@pytest.mark.parametrize(
    ("inputs", "expected_output"),
    [
        (["3", "host", "1", "0"], "Observed in:"),
        (["5", "1", "0"], "supporting"),
        (["6", "1", "0"], "HYP-001"),
        (["7", "0"], "Query Limitations"),
        (["8", "0"], "Workbench refreshed"),
    ],
)
def test_workbench_read_actions_remain_visible_until_pause(
    tmp_path, inputs, expected_output
):
    controller, _, _, current, _, _, _, messages = build_workbench(tmp_path)
    scripted_input = ScriptedInput(inputs)
    pause_views = []
    controller.input = scripted_input
    controller.pause = lambda: pause_views.append(tuple(messages))

    assert controller.run(current) == current

    assert len(pause_views) == 1
    assert any(expected_output in line for line in pause_views[0])
    assert scripted_input.calls == len(inputs)


@pytest.mark.parametrize("kind", ["evidence", "hypothesis", "decision"])
def test_timeline_detail_reads_pause_before_returning_to_timeline(tmp_path, kind):
    controller, _, _, current, context, evidence, reasoning, messages = build_workbench(
        tmp_path
    )
    entry = next(
        item
        for item in InvestigationTimelineService().timeline(context).entries
        if item.source_id == "ALERT-001"
    )
    actions = []
    if entry.evidence_id:
        actions.append("evidence")
    actions.extend("hypothesis" for _item in entry.related_hypothesis_ids)
    actions.extend("decision" for _item in entry.related_decision_ids)
    selection = actions.index(kind) + 1
    controller.input = ScriptedInput([str(selection)])
    pause_views = []
    controller.pause = lambda: pause_views.append(tuple(messages))

    controller.entry_navigation(current, context, entry)

    assert len(pause_views) == 1
    if kind == "evidence":
        assert evidence.workspace_calls
    elif kind == "hypothesis":
        assert reasoning.hypotheses
    else:
        assert reasoning.decisions


def test_workbench_navigation_matrix_is_read_only(tmp_path):
    controller, analysis, _, current, _, _, _, _ = build_workbench(tmp_path)
    before_repository = repository_bytes(tmp_path)
    before_artifacts = artifact_hashes(analysis)
    before_analysis = deepcopy(analysis)
    scripted_input = ScriptedInput(
        [
            "1", "",       # timeline -> workbench
            "3", "",       # entity selector -> workbench
            "4", "",       # pivot entity selector -> workbench
            "5", "",       # evidence selector -> workbench
            "6", "",       # hypothesis selector -> workbench
            "7",           # limitations
            "8",           # refresh
            "0",           # workbench -> workspace
        ]
    )
    controller.input = scripted_input
    controller.pause = lambda: None

    assert controller.run(current) == current

    assert scripted_input.calls == 13
    assert repository_bytes(tmp_path) == before_repository
    assert artifact_hashes(analysis) == before_artifacts
    assert analysis == before_analysis
    assert current.revision == 1


def test_console_has_no_repository_writes_or_raw_analysis_traversal():
    path = Path(__file__).parents[1] / "soc_forge/investigations/query_console.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert called.isdisjoint(
        {
            "save",
            "delete",
            "assign_owner",
            "change_status",
            "replace_evidence_references",
            "record_decision",
        }
    )
    assert ".analysis.events" not in source
    assert ".analysis.alerts" not in source
    assert ".analysis.cases" not in source
    assert "relationship_reason=" not in source
