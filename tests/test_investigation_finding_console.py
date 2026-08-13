from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.finding_console import InvestigationFindingConsoleController
from soc_forge.investigations.finding_service import InvestigationFindingService
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


class ScriptedInput:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = 0

    def __call__(self, _prompt=""):
        self.calls += 1
        return next(self.values)


class Nested:
    def __init__(self, name, calls):
        self.name = name
        self.calls = calls

    def run(self, current):
        self.calls.append(self.name)
        return current


def _fixture(tmp_path, inputs):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    times = iter(("2026-08-12T12:00:00Z", "2026-08-12T12:05:00Z"))
    workspace = InvestigationWorkspaceService(repository)
    service = InvestigationFindingService(workspace, clock=lambda: next(times))
    messages, screens, pauses, calls = [], [], [], []
    input_func = ScriptedInput(inputs)
    controller = InvestigationFindingConsoleController(
        finding_service=service,
        evidence_controller=Nested("evidence", calls),
        reasoning_controller=Nested("reasoning", calls),
        input_func=input_func,
        output_func=messages.append,
        screen_func=screens.append,
        pause_func=lambda: pauses.append("pause"),
    )
    return analysis, repository, workspace, service, workspace.get_investigation("INV-QUERY"), controller, messages, screens, pauses, calls, input_func


def _create_inputs():
    return (
        "2", "1", "", "", "FIND-001", "Analyst conclusion",
        "Evidence supports a bounded conclusion.", "1", "2", "alice",
        "Defense Evasion", "T1562.001", "Visibility is limited", "0",
    )


def test_console_empty_create_list_and_offline_read(tmp_path):
    values = _fixture(tmp_path, _create_inputs())
    _analysis, repository, workspace, service, current, controller, messages, *_ = values
    before = next(repository.investigations_root.glob("*.json")).read_bytes()

    result = controller.run(current)

    assert result.revision == 2
    finding = service.get_finding("INV-QUERY", "FIND-001")
    assert finding.status == "draft"
    assert finding.confidence == "medium"
    assert len(finding.evidence_ids) == 1
    rendered = "\n".join(messages)
    assert "Finding created." in rendered
    assert "No available references." not in rendered
    assert "powershell.exe -enc sensitive" not in rendered
    assert next(repository.investigations_root.glob("*.json")).read_bytes() != before

    restarted = InvestigationFindingService(
        InvestigationWorkspaceService(InvestigationRepository(tmp_path / "workspace"))
    )
    assert restarted.get_finding("INV-QUERY", "FIND-001") == finding


def test_console_empty_state_and_back_consume_input_once(tmp_path):
    values = _fixture(tmp_path, ("1", "0"))
    current, controller, messages, input_func = values[4], values[5], values[6], values[10]

    assert controller.run(current) == current

    assert "No analyst-authored findings." in messages
    assert input_func.calls == 2


def test_console_invalid_creation_remains_visible_until_pause(tmp_path):
    values = _fixture(
        tmp_path,
        ("2", "", "", "", "BAD ID", "Title", "Conclusion", "1", "1", "alice", "", "", "", "0"),
    )
    current, controller, messages, pauses = values[4], values[5], values[6], values[8]

    assert controller.run(current) == current

    assert any("Unable to create finding:" in item for item in messages)
    assert pauses == ["pause"]


def test_console_detail_edit_noop_and_relationship_drilldowns(tmp_path):
    values = _fixture(tmp_path, _create_inputs())
    current, controller = values[4], values[5]
    created = controller.run(current)
    controller.input = ScriptedInput((
        "3", "FIND-001",
        "1", "", "", "", "", "", "n", "", "", "",
        "2", "3", "4", "0",
        "0",
    ))
    values[6].clear()

    returned = controller.run(created)

    assert returned.revision == created.revision
    assert values[9] == ["evidence", "reasoning", "reasoning"]
    rendered = "\n".join(values[6])
    assert "ANALYST-AUTHORED FINDING" in values[7]
    assert "Confidence reflects analyst assessment" in rendered
    assert "Evidence IDs:" in rendered
    assert "Finding unchanged." in rendered


def test_console_real_edit_increments_once_and_preserves_created_at(tmp_path):
    values = _fixture(tmp_path, _create_inputs())
    current, controller, service = values[4], values[5], values[3]
    created = controller.run(current)
    original = service.get_finding("INV-QUERY", "FIND-001")
    controller.input = ScriptedInput((
        "3", "FIND-001", "1", "Updated title", "", "substantiated", "high", "", "n", "", "", "",
        "0", "0",
    ))

    updated = controller.run(created)
    finding = service.get_finding("INV-QUERY", "FIND-001")

    assert updated.revision == created.revision + 1
    assert finding.title == "Updated title"
    assert finding.created_at == original.created_at
    assert finding.updated_at != original.updated_at


def test_workspace_findings_option_dispatches_nested_controller_once(tmp_path):
    from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
    from soc_forge.investigations.console import InvestigationConsoleController

    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    workspace = InvestigationWorkspaceService(repository)
    current = workspace.get_investigation("INV-QUERY")
    calls = []

    class Findings:
        def run(self, value):
            calls.append(value)
            return value

    controller = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(workspace),
        workspace_service=workspace,
        analysis_provider=lambda: analysis,
        workspace_root=tmp_path / "workspace",
        input_func=ScriptedInput(("12", "0")),
        output_func=lambda _message: None,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
        finding_controller=Findings(),
    )

    assert controller.workspace_loop(current) == current
    assert calls == [current]
