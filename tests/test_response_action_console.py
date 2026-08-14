from dataclasses import replace

from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.response_action_console import InvestigationResponseActionConsoleController
from soc_forge.investigations.response_action_service import InvestigationResponseActionService
from soc_forge.investigations.response_action_view import (
    render_response_action_detail,
    render_response_action_list,
    render_response_actions_workspace,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.ui.terminal import strip_ansi
from test_response_actions import NOW, _create, _fixture


class ScriptedInput:
    def __init__(self, values):
        self.values = iter(values)
        self.calls = 0

    def __call__(self, _prompt=""):
        self.calls += 1
        return next(self.values)


class Findings:
    def __init__(self, service):
        self.finding_service = service
        self.rendered = []

    def render_finding(self, finding):
        self.rendered.append(finding)


class FindingService:
    def __init__(self, workspace):
        self.workspace = workspace

    def get_finding(self, investigation_id, finding_id):
        current = self.workspace.get_investigation(investigation_id)
        return next(item for item in current.investigation.findings if item.finding_id == finding_id)


def _controller(tmp_path, inputs):
    repository, workspace, service = _fixture(tmp_path)
    service.transition_id_factory = lambda: "TRANS-CONSOLE-001"
    finding_controller = Findings(FindingService(workspace))
    messages, screens, pauses = [], [], []
    scripted = ScriptedInput(inputs)
    controller = InvestigationResponseActionConsoleController(
        response_action_service=service,
        finding_controller=finding_controller,
        input_func=scripted,
        output_func=messages.append,
        screen_func=screens.append,
        pause_func=lambda: pauses.append("pause"),
    )
    return repository, workspace, service, controller, messages, screens, pauses, scripted, finding_controller


def test_console_create_list_detail_transition_offline_and_back(tmp_path):
    values = _controller(
        tmp_path,
        (
            "2", "1", "", "Reset credentials", "Coordinate reset work.",
            "2", "3", "Reduce access risk.", "identity", "alice",
            "1", "3", "ACT-GENERATED001", "1", "alice", "Approved by analyst.",
            "0", "0",
        ),
    )
    repository, workspace, service, controller, messages, screens, pauses, scripted, _ = values
    current = workspace.get_investigation("INV-A")

    result = controller.run(current)

    action = service.get_action("INV-A", "ACT-GENERATED001")
    assert result.revision == 3
    assert action.status == "approved"
    assert action.transition_history[0].transition_id == "TRANS-CONSOLE-001"
    rendered = strip_ansi("\n".join(messages))
    assert "Action created." in rendered
    assert "OPEN ACTIONS" in rendered
    assert "TRANSITION HISTORY" in rendered
    assert "SOC-FORGE" in rendered
    assert "EXECUTE THIS ACTION" in rendered
    assert "Previous status: proposed" in rendered
    assert screens.count("RESPONSE ACTIONS") >= 2
    assert pauses == ["pause", "pause", "pause", "pause"]
    assert scripted.calls == 18
    assert repository.load("INV-A").response_actions == (action,)


def test_console_empty_state_active_selector_and_related_finding_drilldown(tmp_path):
    values = _controller(tmp_path, ("1", "0"))
    _repo, workspace, service, controller, messages, *_rest = values
    current = workspace.get_investigation("INV-A")
    assert controller.run(current) == current
    assert "No response actions recorded." in strip_ansi("\n".join(messages))

    created = _create(service)
    controller.input = ScriptedInput(("3", "ACT-GENERATED001", "3", "0", "0"))
    returned = controller.run(created)
    assert returned.revision == created.revision
    assert values[-1].rendered[0].finding_id == "FIND-001"


def test_console_superseded_findings_excluded_but_existing_action_remains_mutable(tmp_path):
    values = _controller(tmp_path, ())
    _repo, workspace, service, controller, messages, *_ = values
    created = _create(service)
    current = created.investigation
    old = replace(
        current.findings[0], lifecycle_state="superseded",
        superseded_by_finding_id="FIND-002", supersession_reason="Refined",
        supersession_author="alice", superseded_at=NOW,
    )
    new = replace(
        old, finding_id="FIND-002", lifecycle_state="active",
        supersedes_finding_id="FIND-001", superseded_by_finding_id=None,
        supersession_reason=None, supersession_author=None, superseded_at=None,
    )
    superseded = workspace.replace_findings("INV-A", (old, new), expected_revision=2)
    controller.input = ScriptedInput(("2", "1", "ACT-NEW", "New action", "New work.", "1", "2", "Reason.", "soc", "alice", "0"))
    result = controller.run(superseded)
    assert result.investigation.response_actions[-1].finding_ids == ("FIND-002",)
    assert "FIND-001 |" not in "\n".join(messages[-20:])


def test_response_views_support_no_color_and_narrow_width_without_mutation(tmp_path, monkeypatch):
    _repository, workspace, service = _fixture(tmp_path)
    created = _create(service)
    action = created.investigation.response_actions[0]
    monkeypatch.setenv("NO_COLOR", "1")
    before = created.investigation
    for width in (100, 80, 60, 32):
        rendered = "\n".join((
            render_response_actions_workspace(created, width=width),
            render_response_action_list((action,), width=width),
            render_response_action_detail(action, width=width),
        ))
        assert "\x1b[" not in rendered
        assert "RESPONSE" in rendered
    assert workspace.get_investigation("INV-A").investigation == before


def test_investigation_workspace_option_16_dispatches_once_and_existing_numbers_remain(tmp_path):
    repository, workspace, _service = _fixture(tmp_path)
    current = workspace.get_investigation("INV-A")
    calls = []

    class Response:
        def run(self, value):
            calls.append(value)
            return value

    controller = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(workspace),
        workspace_service=workspace,
        analysis_provider=lambda: None,
        workspace_root=tmp_path / "workspace",
        input_func=ScriptedInput(("16", "0")),
        output_func=lambda _message: None,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
        response_action_controller=Response(),
    )
    assert controller.workspace_loop(current) == current
    assert calls == [current]
    assert repository.load_record("INV-A").revision == 1

def test_empty_transition_history_renders_as_one_normal_line(tmp_path):
    _repository, _workspace, service = _fixture(tmp_path)
    action = _create(service).investigation.response_actions[0]

    rendered = strip_ansi(render_response_action_detail(action, width=80))
    lines = rendered.splitlines()

    assert any("No lifecycle transitions recorded." in line for line in lines)
    assert not all(
        len(line.strip(" |│")) <= 1
        for line in lines
        if line.startswith(("|", "│"))
    )


def test_populated_transition_history_still_renders_chronologically(tmp_path):
    _repository, _workspace, service = _fixture(tmp_path)
    created = _create(service)
    service.clock = lambda: "2026-08-14T13:00:00Z"
    service.transition_id_factory = lambda: "TRANS-RENDER-001"
    updated = service.transition_action(
        "INV-A",
        "ACT-GENERATED001",
        target_status="approved",
        author="alice",
        rationale="Approved for analyst-coordinated work.",
        expected_revision=created.revision,
    )

    rendered = strip_ansi(
        render_response_action_detail(
            updated.investigation.response_actions[0], width=80
        )
    )

    assert "TRANS-RENDER-001" in rendered
    assert "proposed -> approved" in rendered
    assert "Approved for analyst-coordinated work." in rendered
