from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore
from soc_forge.investigations.summary import InvestigationSummaryService
from soc_forge.investigations.summary_console import (
    InvestigationSummaryConsoleController,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


class ScriptedInput:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = 0

    def __call__(self, _prompt=""):
        self.calls += 1
        return next(self.values)


class NestedController:
    def __init__(self, name, calls):
        self.name = name
        self.calls = calls

    def run(self, current):
        self.calls.append((self.name, current.revision))
        return current


def _hashes(analysis):
    return {
        name: sha256(Path(path).read_bytes()).hexdigest()
        for name, path in analysis.artifacts.items()
    }


def _build(tmp_path, analysis_marker=True, investigation=None, inputs=("0",)):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = investigation or build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    current = service.get_investigation(investigation.investigation_id)
    active = {"value": analysis if analysis_marker else None}
    messages = []
    screens = []
    pauses = []
    calls = []
    input_func = ScriptedInput(inputs)
    controller = InvestigationSummaryConsoleController(
        summary_service=InvestigationSummaryService(service),
        analysis_provider=lambda: active["value"],
        evidence_controller=NestedController("evidence", calls),
        reasoning_controller=NestedController("reasoning", calls),
        query_controller=NestedController("query", calls),
        handoff_controller=NestedController("handoff", calls),
        finding_controller=NestedController("finding", calls),
        snapshot_loader=lambda _current: None,
        input_func=input_func,
        output_func=messages.append,
        screen_func=screens.append,
        pause_func=lambda: pauses.append("pause"),
    )
    return (
        analysis, investigation, repository, service, current, active,
        controller, messages, screens, pauses, calls, input_func,
    )


def test_full_summary_renders_authoritative_projection_without_mutation(tmp_path):
    (
        analysis, investigation, repository, service, current, _active,
        controller, messages, screens, _pauses, _calls, _input,
    ) = _build(tmp_path)
    before_repository = next(repository.investigations_root.glob("*.json")).read_bytes()
    before_analysis = deepcopy(analysis)
    before_artifacts = _hashes(analysis)
    expected = InvestigationSummaryService(service).summarize(
        investigation.investigation_id, analysis
    )

    assert controller.run(current) == current

    rendered = "\n".join(messages)
    assert screens == ["INVESTIGATION SUMMARY"]
    assert "Summary mode     : FULL" in rendered
    assert expected.narrative in rendered
    assert "MACHINE-GENERATED DETECTION CONTEXT" in rendered
    assert expected.findings[0].case_id in rendered
    assert "Analyst assessment: open" in rendered
    assert "TIMELINE SUMMARY" in rendered
    assert "powershell.exe -enc sensitive" not in rendered
    assert "Confirmed attack" not in rendered
    assert next(repository.investigations_root.glob("*.json")).read_bytes() == before_repository
    assert service.get_investigation(investigation.investigation_id).revision == 1
    assert analysis == before_analysis
    assert _hashes(analysis) == before_artifacts


def test_offline_and_wrong_analysis_render_persisted_state_without_machine_context(tmp_path):
    values = _build(tmp_path, analysis_marker=False)
    analysis, investigation, _repo, _service, current, active, controller, messages = values[:8]

    assert controller.run(current) == current
    rendered = "\n".join(messages)
    assert "Summary mode     : OFFLINE" in rendered
    assert "Source analysis is not active." in rendered
    selected_id = next(
        item.reference_id for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    assert selected_id in rendered
    assert "HYP-001" in rendered
    assert "DEC-" in rendered
    assert "SOCF-021" not in rendered

    messages.clear()
    wrong = build_query_analysis(tmp_path / "wrong")
    wrong.events[0]["host"] = "WRONG-HOST"
    active["value"] = wrong
    controller.input = ScriptedInput(["0"])
    assert controller.run(current) == current
    rendered = "\n".join(messages)
    assert "Summary mode     : OFFLINE" in rendered
    assert "SOCF-021" not in rendered
    assert investigation.analysis_id in rendered


def test_summary_drilldowns_delegate_and_return_to_summary_once(tmp_path):
    values = _build(tmp_path, inputs=("1", "2", "3", "4", "5", "0"))
    current, controller, screens, calls, input_func = (
        values[4], values[6], values[8], values[10], values[11]
    )

    assert controller.run(current) == current

    assert calls == [
        ("evidence", 1),
        ("reasoning", 1),
        ("query", 1),
        ("handoff", 1),
        ("finding", 1),
    ]
    assert screens == ["INVESTIGATION SUMMARY"] * 6
    assert input_func.calls == 6


def test_invalid_input_pauses_and_renders_again_without_double_consumption(tmp_path):
    values = _build(tmp_path, inputs=(" bad ", "0"))
    current, controller, messages, screens, pauses, input_func = (
        values[4], values[6], values[7], values[8], values[9], values[11]
    )

    assert controller.run(current) == current

    assert messages.count("Invalid option.") == 1
    assert screens == ["INVESTIGATION SUMMARY", "INVESTIGATION SUMMARY"]
    assert pauses == ["pause"]
    assert input_func.calls == 2


def test_existing_snapshot_loader_recovers_full_summary_without_revision_change(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    snapshot_store = CompletedAnalysisSnapshotStore(analysis.output_dir)
    snapshot_store.publish(analysis)
    active = {"value": None}
    messages = []
    screens = []
    input_func = ScriptedInput(["6", "0"])
    parent = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(service),
        workspace_service=service,
        analysis_provider=lambda: active["value"],
        workspace_root=tmp_path / "workspace",
        input_func=input_func,
        output_func=messages.append,
        screen_func=screens.append,
        pause_func=lambda: None,
        snapshot_store=snapshot_store,
        analysis_activator=lambda value: active.__setitem__("value", value),
    )
    current = service.get_investigation("INV-QUERY")
    before = next(repository.investigations_root.glob("*.json")).read_bytes()

    assert parent.summary_controller.run(current) == current

    modes = [line for line in messages if "Summary mode" in line]
    assert modes == ["  Summary mode     : OFFLINE", "  Summary mode     : FULL"]
    assert active["value"] is not None
    assert service.get_investigation("INV-QUERY").revision == 1
    assert next(repository.investigations_root.glob("*.json")).read_bytes() == before
    assert input_func.calls == 2


def test_workspace_option_one_dispatches_summary_and_back_returns_one_level(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    service = InvestigationWorkspaceService(repository)
    messages = []
    calls = []

    class SummaryController:
        def run(self, current):
            calls.append(current)
            return current

    controller = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(service),
        workspace_service=service,
        analysis_provider=lambda: analysis,
        workspace_root=tmp_path / "workspace",
        input_func=ScriptedInput(["1", "0"]),
        output_func=messages.append,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
        summary_controller=SummaryController(),
    )
    current = service.get_investigation("INV-QUERY")

    assert controller.workspace_loop(current) == current
    assert calls == [current]
    assert "[1] Investigation Summary" in messages


def test_empty_summary_state_renders_safely(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    empty = replace(
        investigation,
        evidence_references=tuple(
            item for item in investigation.evidence_references
            if item.origin == "scope"
        ),
        annotations=(),
        hypotheses=(),
        decisions=(),
    )
    values = _build(tmp_path / "empty", investigation=empty)
    current, controller, messages = values[4], values[6], values[7]

    assert controller.run(current) == current
    rendered = "\n".join(messages)
    assert "No analyst-selected evidence." in rendered
    assert "No analyst hypotheses." in rendered
    assert "No analyst decisions." in rendered
