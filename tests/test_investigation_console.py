import ast
from pathlib import Path

import pytest

from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.repository import (
    InvestigationNotFoundError,
    InvestigationRepository,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceError,
    InvestigationWorkspaceService,
)
from soc_forge.pipeline import AnalysisResult


class ScriptedInput:
    def __init__(self, values):
        self.values = iter(values)

    def __call__(self, _prompt=""):
        return next(self.values)


def build_analysis(tmp_path):
    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    artifacts = {}
    for key in ("alerts", "cases", "hunts", "reconstructions", "report"):
        path = output_dir / ("report.html" if key == "report" else f"{key}.json")
        path.write_text(f"original-{key}", encoding="utf-8")
        artifacts[key] = path
    return AnalysisResult(
        input_name="detection_lab.jsonl",
        input_path=tmp_path / "detection_lab.jsonl",
        output_dir=output_dir,
        alerts_path=artifacts["alerts"],
        report_path=artifacts["report"],
        cases_output_dir=output_dir,
        hunts_path=artifacts["hunts"],
        reconstructions_path=artifacts["reconstructions"],
        events_path=None,
        event_count=1,
        events=[{"event_id": 4688}],
        alerts=[{"rule_id": "SOCF-021"}],
        legacy_alerts=[],
        yaml_alerts=[{"rule_id": "SOCF-021"}],
        correlations={"total": 0, "by_rule": []},
        hunt_findings=[],
        risk_summary={"level": "high"},
        cases=[
            {"case_id": "CASE-A", "title": "Security control tampering"},
            {"case_id": "CASE-B", "title": "Collection activity"},
        ],
        reconstructions=[],
        mitre_coverage=[],
        artifacts=artifacts,
        ingest_diagnostics=[],
    )


def build_controller(tmp_path, inputs=(), analysis=None):
    repository = InvestigationRepository(tmp_path / "workspace")
    clock_values = iter(
        f"2026-08-03T12:{minute:02d}:00Z" for minute in range(60)
    )
    service = InvestigationWorkspaceService(
        repository, clock=lambda: next(clock_values)
    )
    adapter = InvestigationBootstrapAdapter(
        service, clock=lambda: "2026-08-03T11:59:00Z"
    )
    messages = []
    controller = InvestigationConsoleController(
        bootstrap_adapter=adapter,
        workspace_service=service,
        analysis_provider=lambda: analysis,
        workspace_root=tmp_path / "workspace",
        input_func=ScriptedInput(inputs),
        output_func=messages.append,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
    )
    return controller, service, messages


def create_workspace(controller):
    result = controller.create_flow()
    assert result is not None
    return result


@pytest.mark.parametrize(
    ("choice", "handler_name"),
    [
        (" 1 ", "create_flow"),
        ("2", "list_screen"),
        ("3", "open_flow"),
        ("4", "delete_flow"),
    ],
)
def test_workspace_menu_dispatches_each_handler_once_and_pauses(
    tmp_path, choice, handler_name
):
    analysis = build_analysis(tmp_path)
    controller, _, messages = build_controller(tmp_path, analysis=analysis)
    calls = []
    pauses = []
    screens = []
    controller.input = ScriptedInput([choice, "0"])
    controller.screen = screens.append
    controller.pause = lambda: pauses.append(tuple(messages))
    setattr(controller, handler_name, lambda: calls.append(handler_name))

    controller.run()

    assert calls == [handler_name]
    assert len(pauses) == 1
    assert len(screens) == 2


def test_workspace_menu_back_and_invalid_input_are_not_consumed_twice(tmp_path):
    controller, _, messages = build_controller(tmp_path)
    screens = []
    pauses = []
    controller.input = ScriptedInput([" invalid ", "0"])
    controller.screen = screens.append
    controller.pause = lambda: pauses.append("paused")

    controller.run()

    assert messages.count("Invalid option.") == 1
    assert len(screens) == 2
    assert pauses == []


def test_workspace_menu_create_uses_active_analysis(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, service, _ = build_controller(
        tmp_path,
        ["1", "1", "INV-MENU", "", "", "y", "0"],
        analysis,
    )

    controller.run()

    created = service.get_investigation("INV-MENU")
    assert created.investigation.provenance.normalized_input_name == analysis.input_name
    assert [item.source_id for item in created.investigation.evidence_references if item.origin == "scope"] == ["CASE-A"]


def test_workspace_menu_list_does_not_require_active_analysis(tmp_path):
    controller, _, messages = build_controller(tmp_path, ["2", "0"])

    controller.run()

    assert "No durable investigations found." in messages


def test_workspace_evidence_and_reasoning_options_still_dispatch(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, _ = build_controller(
        tmp_path,
        ["1", "INV-NESTED", "", "", "y"],
        analysis,
    )
    current = create_workspace(controller)
    calls = []

    class NestedController:
        def __init__(self, name):
            self.name = name

        def run(self, value):
            calls.append(self.name)
            return value

        def render_workspace_counts(self, _value):
            return None

        def render_counts(self, _value):
            return None

    controller.evidence_controller = NestedController("evidence")
    controller.reasoning_controller = NestedController("reasoning")
    controller.input = ScriptedInput(["10", "11", "0"])

    assert controller.workspace_loop(current) == current
    assert calls == ["evidence", "reasoning"]


def test_workspace_timeline_and_pivot_option_dispatches_read_only_controller(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, _ = build_controller(
        tmp_path,
        ["1", "INV-QUERY", "", "", "y"],
        analysis,
    )
    current = create_workspace(controller)
    calls = []

    class QueryController:
        def run(self, value):
            calls.append(value.revision)
            return value

    controller.query_controller = QueryController()
    controller.input = ScriptedInput(["13", "0"])

    assert controller.workspace_loop(current) == current
    assert calls == [current.revision]



def test_workspace_handoff_option_dispatches_read_only_controller(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, _ = build_controller(
        tmp_path,
        ["1", "INV-HANDOFF", "", "", "y"],
        analysis,
    )
    current = create_workspace(controller)
    calls = []

    class HandoffController:
        def run(self, value):
            calls.append(value.revision)
            return value

    controller.handoff_controller = HandoffController()
    controller.input = ScriptedInput(["14", "0"])

    assert controller.workspace_loop(current) == current
    assert calls == [current.revision]


def test_create_list_and_open_completed_analysis_workspace(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, service, messages = build_controller(
        tmp_path, ["2", "INV-001", "", "alice", "y"], analysis
    )

    result = create_workspace(controller)
    assert result.revision == 1
    assert result.investigation.metadata.title == "Collection activity"
    assert result.investigation.metadata.owner == "alice"
    assert result.investigation.metadata.status == "open"
    assert result.investigation.evidence_references[0].source_id == "CASE-B"
    assert service.get_investigation("INV-001") == result

    summaries = controller.list_screen()
    assert summaries[0].investigation_id == "INV-001"
    assert any("INV-001 | Collection activity | open | alice" in line for line in messages)

    controller.input = ScriptedInput(["INV-001", "0"])
    opened = controller.open_flow()
    assert opened == result
    assert any("Source analysis ID" in line for line in messages)
    assert any("Selected case IDs" in line and "CASE-B" in line for line in messages)
    assert any("Annotations" in line and "0" in line for line in messages)
    assert any("Decisions" in line and "0" in line for line in messages)
    assert any("Investigation Summary" in line for line in messages)
    assert any("Evidence Workspace" in line for line in messages)
    assert any("Hypotheses and Decisions" in line for line in messages)
    assert any("Investigation Findings" in line for line in messages)
    assert any("Timeline and Pivot Workbench (Read Only)" in line for line in messages)
    assert any("Investigation Handoff (Read Only)" in line for line in messages)
    assert "[9] Record decision" not in messages


def test_create_override_cancel_and_missing_analysis_paths(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, _ = build_controller(
        tmp_path, ["1", "INV-002", "Priority review", "", "y"], analysis
    )
    result = create_workspace(controller)
    assert result.investigation.metadata.title == "Priority review"
    assert result.investigation.metadata.owner is None

    cancelled, _, messages = build_controller(tmp_path / "cancel", ["0"], analysis)
    assert cancelled.create_flow() is None
    assert "Creation cancelled." in messages

    missing, _, messages = build_controller(tmp_path / "missing")
    assert missing.create_flow() is None
    assert messages == ["No completed analysis is available. Run or load analysis first."]


def test_owner_status_reopen_and_revision_refresh(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, _ = build_controller(
        tmp_path, ["1", "INV-003", "", "", "y"], analysis
    )
    current = create_workspace(controller)

    controller.input = ScriptedInput(["bob"])
    current = controller._assign_owner(current)
    assert (current.revision, current.investigation.metadata.owner) == (2, "bob")
    controller.input = ScriptedInput([""])
    current = controller._assign_owner(current)
    assert (current.revision, current.investigation.metadata.owner) == (3, None)

    controller.input = ScriptedInput(["2"])
    current = controller._change_status(current)
    assert (current.revision, current.investigation.metadata.status) == (4, "in_progress")
    controller.input = ScriptedInput(["1"])
    current = controller._change_status(current)
    assert (current.revision, current.investigation.metadata.status) == (5, "closed")
    current = controller._reopen(current)
    assert (current.revision, current.investigation.metadata.status) == (6, "in_progress")


def test_annotation_crud_and_decision_display(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, messages = build_controller(
        tmp_path, ["1", "INV-004", "", "", "y"], analysis
    )
    current = create_workspace(controller)
    controller.input = ScriptedInput(["NOTE-1", "alice", "Initial note"])
    current = controller._add_annotation(current)
    assert current.investigation.annotations[0].body == "Initial note"

    controller._view_annotations(current)
    controller.input = ScriptedInput(["NOTE-1", "Updated note"])
    current = controller._edit_annotation(current)
    assert current.investigation.annotations[0].body == "Updated note"

    current = controller.workspace_service.record_decision(
        current.investigation.investigation_id,
        decision_id="DEC-1",
        decision_type="disposition",
        outcome="escalate",
        rationale="Needs review",
        author="alice",
        evidence_reference_ids=("case:CASE-A",),
        hypothesis_ids=(),
        expected_revision=current.revision,
    )
    controller._view_decisions(current)
    assert current.investigation.decisions[0].evidence_reference_ids == ("case:CASE-A",)
    assert any("DEC-1 | alice | disposition:escalate" in line for line in messages)

    controller.input = ScriptedInput(["NOTE-1", "y"])
    current = controller._remove_annotation(current)
    assert current.revision == 5
    assert current.investigation.annotations == ()


def test_annotation_deletion_requires_confirmation(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, _, messages = build_controller(
        tmp_path, ["1", "INV-005", "", "", "y"], analysis
    )
    current = create_workspace(controller)
    controller.input = ScriptedInput(["NOTE-1", "alice", "Keep me"])
    current = controller._add_annotation(current)
    controller.input = ScriptedInput(["NOTE-1", "n"])
    assert controller._remove_annotation(current) == current
    assert "Annotation deletion cancelled." in messages


def test_stale_revision_reloads_without_overwrite(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, service, messages = build_controller(
        tmp_path, ["1", "INV-006", "", "", "y"], analysis
    )
    stale = create_workspace(controller)
    service.assign_owner("INV-006", "other-session", expected_revision=1)
    controller.input = ScriptedInput(["local-session"])
    reloaded = controller._assign_owner(stale)
    assert reloaded.revision == 2
    assert reloaded.investigation.metadata.owner == "other-session"
    assert any("No overwrite was attempted" in line for line in messages)
    assert any("Reloaded latest revision 2" in line for line in messages)


def test_delete_preserves_artifacts_and_new_service_can_reload(tmp_path):
    analysis = build_analysis(tmp_path)
    originals = {
        key: path.read_text(encoding="utf-8") for key, path in analysis.artifacts.items()
    }
    controller, _, _ = build_controller(
        tmp_path, ["1", "INV-007", "", "", "y"], analysis
    )
    created = create_workspace(controller)
    reloaded_service = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace")
    )
    assert reloaded_service.get_investigation("INV-007") == created

    controller.input = ScriptedInput(["INV-007", "y"])
    assert controller.delete_flow() is True
    with pytest.raises(InvestigationNotFoundError):
        reloaded_service.get_investigation("INV-007")
    assert {
        key: path.read_text(encoding="utf-8") for key, path in analysis.artifacts.items()
    } == originals


def test_console_never_edits_investigation_json_directly():
    source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "investigations"
        / "console.py"
    )
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "json" not in imports
    assert "open" not in calls
    assert {"write_text", "write_bytes"}.isdisjoint(attributes)


def test_service_owns_status_choices(tmp_path):
    service = InvestigationWorkspaceService(InvestigationRepository(tmp_path))
    assert service.available_status_transitions("open") == ("closed", "in_progress")
    assert service.available_status_transitions("closed") == ()
    with pytest.raises(InvestigationWorkspaceError, match="Status"):
        service.available_status_transitions("unknown")


def test_investigations_menu_delegates_workspace_and_preserves_back(monkeypatch):
    from soc_forge.menus import investigations as menu_module

    class RecordingController:
        calls = 0

        def run(self):
            self.calls += 1

    controller = RecordingController()
    values = iter(["6", "0"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(values))
    monkeypatch.setattr(menu_module, "begin_screen", lambda _title: None)
    monkeypatch.setattr(menu_module, "menu_option", lambda *_args: None)
    menu_module.investigations_menu(
        lambda: None,
        lambda: None,
        lambda: [],
        lambda: None,
        lambda: None,
        lambda: None,
        workspace_controller=controller,
    )
    assert controller.calls == 1


def test_console_analysis_action_retains_completed_result(monkeypatch, tmp_path):
    import analyst_console

    expected = build_analysis(tmp_path)
    prompts = iter([str(tmp_path / "events.jsonl"), "n", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(prompts))
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "run_analysis", lambda _options: expected)
    monkeypatch.setattr(analyst_console, "success", lambda _message: None)
    analyst_console.analyze_log_file()
    assert analyst_console.get_current_analysis_result() is expected


@pytest.mark.parametrize(
    ("choice", "scenario"),
    [
        ("1", "brute_force"),
        ("2", "password_spray"),
        ("3", "privilege_escalation"),
    ],
)
def test_console_simulation_retains_completed_analysis(
    monkeypatch, tmp_path, choice, scenario
):
    import analyst_console

    expected = build_analysis(tmp_path)
    commands = []
    options = []
    monkeypatch.setattr(analyst_console, "_current_analysis_result", None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": choice)
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "pause", lambda: None)
    monkeypatch.setattr(analyst_console, "success", lambda _message: None)
    monkeypatch.setattr(
        analyst_console,
        "run_command",
        lambda command: commands.append(command),
    )
    monkeypatch.setattr(
        analyst_console,
        "run_analysis",
        lambda value: options.append(value) or expected,
    )

    analyst_console.run_attack_simulation()

    assert analyst_console.get_current_analysis_result() is expected
    assert analyst_console.get_current_analysis_result().cases == expected.cases
    assert commands == [
        "python -m soc_forge.cli "
        f"--simulate {scenario} "
        f"--sim-output out/{scenario}_events.jsonl"
    ]
    assert len(options) == 1
    assert options[0].input_path == Path(f"out/{scenario}_events.jsonl")
    assert options[0].output_dir == Path("out")
    assert options[0].report_path == Path(f"out/{scenario}_report.html")
    assert options[0].write_report is True


def test_simulation_result_is_immediately_available_to_investigation_workspace(
    monkeypatch, tmp_path
):
    import analyst_console

    expected = build_analysis(tmp_path)
    monkeypatch.setattr(analyst_console, "_current_analysis_result", None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "pause", lambda: None)
    monkeypatch.setattr(analyst_console, "success", lambda _message: None)
    monkeypatch.setattr(analyst_console, "run_command", lambda _command: None)
    monkeypatch.setattr(analyst_console, "run_analysis", lambda _options: expected)

    analyst_console.run_attack_simulation()

    controller = analyst_console.build_investigation_console_controller(
        tmp_path / "workspace"
    )
    assert controller.analysis_provider() is expected
    controller.input = ScriptedInput(["1", "INV-SIMULATION", "", "", "y"])
    controller.output = lambda _message: None
    controller.screen = lambda _title: None
    controller.pause = lambda: None

    created = controller.create_flow()

    assert created is not None
    assert created.investigation.provenance.normalized_input_name == expected.input_name
    assert [
        item.source_id
        for item in created.investigation.evidence_references
        if item.origin == "scope"
    ] == ["CASE-A"]


def test_main_runtime_opens_durable_workbench_with_live_analysis(
    monkeypatch, tmp_path
):
    import analyst_console
    from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog

    analysis = build_analysis(tmp_path)
    workspace_root = tmp_path / "runtime-workspace"
    repository = InvestigationRepository(workspace_root)
    service = InvestigationWorkspaceService(repository)
    adapter = InvestigationBootstrapAdapter(service)
    created = adapter.bootstrap_investigation(
        analysis,
        "INV-RUNTIME",
        ["CASE-A"],
    )
    workspace_file = next((workspace_root / "investigations").glob("*.json"))
    repository_before = workspace_file.read_bytes()
    analysis_id = AnalysisEvidenceCatalog().source_analysis_id(analysis)
    prompts = ScriptedInput(
        [
            "2", "6", "3", "INV-RUNTIME", "13",
            "0", "0", "", "0", "0", "0",
        ]
    )
    screens = []
    observed = []
    controllers = []
    original_builder = analyst_console.build_investigation_console_controller

    def tracked_builder(*args, **kwargs):
        controller = original_builder(*args, **kwargs)
        controllers.append(controller)
        original_run = controller.query_controller.run

        def tracked_run(current):
            observed.append(
                (
                    current,
                    controller.analysis_provider(),
                    controller.workspace_service,
                    controller.workspace_root,
                    controller.query_controller.pause,
                )
            )
            return original_run(current)

        controller.query_controller.run = tracked_run
        return controller

    monkeypatch.setattr(analyst_console, "_current_analysis_result", analysis)
    monkeypatch.setattr(analyst_console, "WORKSPACE_ROOT", workspace_root)
    monkeypatch.setattr("builtins.input", prompts)
    monkeypatch.setattr(analyst_console, "begin_screen", screens.append)
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "show_dashboard", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_group", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_option", lambda *_args: None)
    monkeypatch.setattr(
        "soc_forge.menus.investigations.begin_screen",
        screens.append,
    )
    monkeypatch.setattr(
        analyst_console,
        "build_investigation_console_controller",
        tracked_builder,
    )

    with pytest.raises(SystemExit):
        analyst_console.main_menu()

    assert len(controllers) == 1
    assert len(observed) == 1
    current, active, runtime_service, root, pause_callback = observed[0]
    assert current == created
    assert current.revision == created.revision
    assert current.investigation.analysis_id == analysis_id
    assert active is analysis
    assert runtime_service.repository.storage_root == workspace_root
    assert root == workspace_root
    assert callable(pause_callback)
    assert "TIMELINE/PIVOT WORKBENCH - READ ONLY" in screens
    assert workspace_file.read_bytes() == repository_before
    assert service.get_investigation("INV-RUNTIME").revision == created.revision


def test_workspace_does_not_swallow_query_controller_exception(tmp_path):
    analysis = build_analysis(tmp_path)
    controller, service, _ = build_controller(tmp_path, analysis=analysis)
    current = service.create_investigation(
        investigation_id="INV-QUERY-ERROR",
        title="Query error boundary",
        analysis_id="ANALYSIS-QUERY-ERROR",
    )

    class FailingQueryController:
        def run(self, _current):
            raise RuntimeError("query-controller-contract")

    controller.query_controller = FailingQueryController()
    controller.input = ScriptedInput(["13"])

    with pytest.raises(RuntimeError, match="query-controller-contract"):
        controller.workspace_loop(current)


def test_returning_through_main_menus_preserves_active_analysis(monkeypatch, tmp_path):
    import analyst_console

    expected = build_analysis(tmp_path)
    monkeypatch.setattr(analyst_console, "_current_analysis_result", expected)
    choices = iter(["1", "2", "0"])
    observed = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "show_dashboard", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_group", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_option", lambda *_args: None)
    monkeypatch.setattr(
        analyst_console,
        "detection_menu",
        lambda *_args: observed.append(analyst_console.get_current_analysis_result()),
    )
    monkeypatch.setattr(
        analyst_console,
        "investigations_menu",
        lambda *_args: observed.append(analyst_console.get_current_analysis_result()),
    )

    with pytest.raises(SystemExit):
        analyst_console.main_menu()

    assert observed == [expected, expected]
    assert analyst_console.get_current_analysis_result() is expected

def test_main_menu_analysis_dispatch_uses_current_contract(monkeypatch):
    import analyst_console

    calls = []
    choices = iter(["3", "0"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "show_dashboard", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_group", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_option", lambda *_args: None)
    monkeypatch.setattr(
        analyst_console,
        "build_investigation_console_controller",
        lambda: object(),
    )
    overview = object()
    entity = object()
    attack = object()
    monkeypatch.setattr(
        analyst_console, "build_threat_activity_controller", lambda _workspace: overview
    )
    monkeypatch.setattr(
        analyst_console, "build_entity_explorer_controller", lambda _workspace: entity
    )
    monkeypatch.setattr(
        analyst_console, "build_attack_activity_controller", lambda _workspace: attack
    )
    cross = object()
    monkeypatch.setattr(
        analyst_console, "build_cross_investigation_controller",
        lambda _workspace: cross
    )
    temporal = object()
    monkeypatch.setattr(
        analyst_console, "build_temporal_analysis_controller",
        lambda _workspace: temporal
    )
    hunt = object()
    monkeypatch.setattr(
        analyst_console, "build_hunt_workspace_controller",
        lambda _workspace: hunt
    )
    monkeypatch.setattr(
        analyst_console,
        "analysis_menu",
        lambda pause, stories, graph, overview, entity, attack, cross, temporal, hunt: calls.append((pause, stories, graph, overview, entity, attack, cross, temporal, hunt)),
    )

    with pytest.raises(SystemExit):
        analyst_console.main_menu()

    assert calls == [
        (
            analyst_console.pause,
            analyst_console.attack_stories,
            analyst_console.attack_graph_viewer,
            overview,
            entity,
            attack,
            cross,
            temporal,
            hunt,
        ),
    ]


def test_analysis_menu_back_returns_without_dispatch(monkeypatch):
    from soc_forge.menus import analysis as menu_module

    calls = []
    monkeypatch.setattr("builtins.input", lambda _prompt="": " 0 ")
    monkeypatch.setattr(menu_module, "begin_screen", lambda _title: None)
    monkeypatch.setattr(menu_module, "menu_option", lambda *_args: None)

    menu_module.analysis_menu(
        lambda: calls.append("pause"),
        lambda: calls.append("stories"),
        lambda: calls.append("graph"),
    )

    assert calls == []


@pytest.mark.parametrize(
    ("choice", "menu_name"),
    [
        ("1", "detection_menu"),
        ("2", "investigations_menu"),
        ("4", "reporting_menu"),
        ("5", "system_menu"),
    ],
)
def test_main_menu_other_dispatch_remains_available(monkeypatch, choice, menu_name):
    import analyst_console

    calls = []
    choices = iter([choice, "0"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analyst_console, "clear_screen", lambda: None)
    monkeypatch.setattr(analyst_console, "show_dashboard", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_group", lambda *_args: None)
    monkeypatch.setattr(analyst_console, "menu_option", lambda *_args: None)
    monkeypatch.setattr(
        analyst_console,
        "build_investigation_console_controller",
        lambda: object(),
    )
    monkeypatch.setattr(
        analyst_console,
        "build_reporting_controller",
        lambda _workspace: object(),
    )
    monkeypatch.setattr(
        analyst_console,
        menu_name,
        lambda *_args: calls.append(menu_name),
    )

    with pytest.raises(SystemExit):
        analyst_console.main_menu()

    assert calls == [menu_name]

def test_workspace_views_pause_with_persisted_annotations_and_decisions(tmp_path):
    controller, service, messages = build_controller(tmp_path)
    current = service.create_investigation(
        investigation_id="INV-VIEWS",
        title="Persistent views",
        analysis_id="ANALYSIS-VIEWS",
    )
    current = service.add_annotation(
        "INV-VIEWS",
        annotation_id="NOTE-1",
        body="Persisted annotation body",
        author="alice",
        expected_revision=current.revision,
    )
    current = service.record_decision(
        "INV-VIEWS",
        decision_id="DEC-1",
        decision_type="disposition",
        outcome="monitor",
        rationale="Persisted decision rationale",
        author="alice",
        expected_revision=current.revision,
    )
    pauses = []
    controller.input = ScriptedInput(["5", "9", "0"])
    controller.pause = lambda: pauses.append(tuple(messages))

    assert controller.workspace_loop(current) == current

    assert len(pauses) == 2
    assert any("Persisted annotation body" in line for line in pauses[0])
    assert any("DEC-1" in line for line in pauses[1])


def test_workspace_annotation_add_and_edit_refresh_and_persist(tmp_path):
    controller, service, _ = build_controller(tmp_path)
    current = service.create_investigation(
        investigation_id="INV-ANNOTATIONS",
        title="Annotation mutations",
        analysis_id="ANALYSIS-ANNOTATIONS",
    )
    controller.input = ScriptedInput([
        "6", "NOTE-1", "alice", "Original text",
        "7", "NOTE-1", "Edited text",
        "0",
    ])
    pauses = []
    controller.pause = lambda: pauses.append("paused")

    updated = controller.workspace_loop(current)
    reloaded = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace")
    ).get_investigation("INV-ANNOTATIONS")
    annotation = reloaded.investigation.annotations[0]

    assert updated == reloaded
    assert updated.revision == current.revision + 2
    assert annotation.body == "Edited text"
    assert annotation.created_at != annotation.updated_at
    assert pauses == ["paused", "paused"]

def test_workspace_menu_invalid_choice_and_back(tmp_path):
    controller, _, messages = build_controller(tmp_path, ["bad", "0"])
    controller.run()
    assert "Invalid option." in messages
