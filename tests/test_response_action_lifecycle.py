import json
from dataclasses import FrozenInstanceError, replace

import pytest

from soc_forge.investigations.finding_service import InvestigationFindingService
from soc_forge.investigations.models import (
    FINDING_CONCLUSION_LIMIT,
    ResponseAction,
    ResponseActionTransition,
)
from soc_forge.investigations.repository import InvestigationConflictError, InvestigationRepository
from soc_forge.investigations.response_action_service import (
    InvalidResponseActionFindingError,
    InvalidResponseActionTransitionError,
    InvestigationResponseActionService,
    ResponseActionNotFoundError,
    TerminalResponseActionError,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from test_response_actions import NOW, _create, _fixture


LATER = "2026-08-14T13:00:00Z"


def _created(tmp_path):
    repository, workspace, service = _fixture(tmp_path)
    created = _create(service)
    service.clock = lambda: LATER
    transition_ids = iter(
        ["TRANS-001", "TRANS-002", "TRANS-003", "TRANS-004"]
    )
    service.transition_id_factory = lambda: next(transition_ids)
    return repository, workspace, service, created


def _transition(service, revision, target, **overrides):
    values = dict(
        target_status=target,
        author="alice",
        rationale=f"Analyst moved response work to {target}.",
        expected_revision=revision,
    )
    values.update(overrides)
    return service.transition_action("INV-A", "ACT-GENERATED001", **values)


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("proposed", "approved"),
        ("proposed", "dismissed"),
        ("approved", "in_progress"),
        ("approved", "dismissed"),
        ("in_progress", "completed"),
        ("in_progress", "dismissed"),
    ],
)
def test_allowed_transition_graph(tmp_path, source, target):
    _repository, _workspace, service, current = _created(tmp_path)
    if source == "approved":
        current = _transition(service, current.revision, "approved")
    elif source == "in_progress":
        current = _transition(service, current.revision, "approved")
        current = _transition(service, current.revision, "in_progress")

    result = _transition(service, current.revision, target)
    action = result.investigation.response_actions[0]
    transition = action.transition_history[-1]

    assert result.revision == current.revision + 1
    assert action.status == target
    assert (transition.from_status, transition.to_status) == (source, target)
    assert transition.author == "alice"
    assert transition.timestamp == action.updated_at == LATER
    assert action.created_at == NOW
    assert action.owner == "identity-team"


@pytest.mark.parametrize(
    ("preparation", "target"),
    [
        ((), "completed"),
        ((), "in_progress"),
        (("approved", "in_progress", "completed"), "approved"),
        (("dismissed",), "in_progress"),
    ],
)
def test_invalid_and_terminal_transitions_are_atomic(tmp_path, preparation, target):
    repository, workspace, service, current = _created(tmp_path)
    for state in preparation:
        current = _transition(service, current.revision, state)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    error = TerminalResponseActionError if preparation and preparation[-1] in {"completed", "dismissed"} else InvalidResponseActionTransitionError

    with pytest.raises(error):
        _transition(service, current.revision, target)

    assert workspace.get_investigation("INV-A").revision == current.revision
    assert path.read_bytes() == before


def test_same_status_unknown_malformed_and_stale_are_atomic(tmp_path):
    repository, workspace, service, current = _created(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(InvalidResponseActionTransitionError):
        _transition(service, current.revision, "proposed")
    with pytest.raises(ResponseActionNotFoundError):
        service.transition_action(
            "INV-A", "ACT-MISSING", target_status="approved", author="alice",
            rationale="Approve.", expected_revision=current.revision,
        )
    with pytest.raises(ValueError, match="valid ACT-"):
        service.transition_action(
            "INV-A", "../bad", target_status="approved", author="alice",
            rationale="Approve.", expected_revision=current.revision,
        )
    with pytest.raises(InvestigationConflictError):
        _transition(service, 99, "approved")
    assert workspace.get_investigation("INV-A").revision == current.revision
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value"),
    [("author", ""), ("rationale", ""),
     ("rationale", "x" * (FINDING_CONCLUSION_LIMIT + 1))],
)
def test_transition_attribution_is_required_and_bounded(tmp_path, field, value):
    repository, workspace, service, current = _created(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        _transition(service, current.revision, "approved", **{field: value})
    assert workspace.get_investigation("INV-A").revision == current.revision
    assert path.read_bytes() == before


def test_complete_history_is_ordered_immutable_and_survives_reload(tmp_path):
    repository, _workspace, service, current = _created(tmp_path)
    for target in ("approved", "in_progress", "completed"):
        current = _transition(service, current.revision, target)
    action = current.investigation.response_actions[0]
    assert [item.transition_id for item in action.transition_history] == [
        "TRANS-001", "TRANS-002", "TRANS-003"
    ]
    assert [item.to_status for item in action.transition_history] == [
        "approved", "in_progress", "completed"
    ]
    assert action.status == action.transition_history[-1].to_status
    assert InvestigationRepository(repository.storage_root).load("INV-A").response_actions == (action,)
    with pytest.raises(FrozenInstanceError):
        action.transition_history[0].author = "mallory"


def test_model_rejects_noncontiguous_duplicate_or_mismatched_history(tmp_path):
    _repository, _workspace, _service, current = _created(tmp_path)
    action = current.investigation.response_actions[0]
    first = ResponseActionTransition(
        transition_id="TRANS-001", from_status="proposed", to_status="approved",
        author="alice", rationale="Approved.", timestamp=LATER,
    )
    wrong = replace(first, transition_id="TRANS-002", from_status="in_progress", to_status="completed")
    with pytest.raises(ValueError, match="not contiguous"):
        replace(action, status="completed", transition_history=(first, wrong))
    with pytest.raises(ValueError, match="duplicate IDs"):
        replace(action, status="approved", transition_history=(first, first))
    with pytest.raises(ValueError, match="final transition"):
        replace(action, status="in_progress", transition_history=(first,))


def test_slice_one_action_without_history_loads_without_rewrite(tmp_path):
    repository, workspace, _service, current = _created(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    payload = json.loads(path.read_text())
    payload["investigation"]["response_actions"][0].pop("transition_history", None)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    before = path.read_bytes()
    loaded = workspace.get_investigation("INV-A")
    assert loaded.investigation.response_actions[0].status == "proposed"
    assert loaded.investigation.response_actions[0].transition_history == ()
    assert path.read_bytes() == before
    assert loaded.revision == current.revision


def test_read_operations_preserve_bytes_and_revision(tmp_path):
    repository, workspace, service, current = _created(tmp_path)
    current = _transition(service, current.revision, "approved")
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    assert service.get_action("INV-A", "ACT-GENERATED001").status == "approved"
    assert service.list_actions("INV-A")[0].transition_history
    assert path.read_bytes() == before
    assert workspace.get_investigation("INV-A").revision == current.revision


def test_lifecycle_remains_available_after_finding_supersession(tmp_path):
    _repository, workspace, service, current = _created(tmp_path)
    finding_service = InvestigationFindingService(workspace, clock=lambda: LATER)
    old = current.investigation.findings[0]
    replacement = finding_service.create_finding(
        "INV-A", finding_id="FIND-002", title="Refined finding",
        conclusion="Refined analyst conclusion.", status="substantiated",
        confidence="high", author="alice", expected_revision=current.revision,
        decision_ids=("DECISION-001",),
    )
    superseded = finding_service.supersede_finding(
        "INV-A", "FIND-001", "FIND-002", reason="Analysis refined.",
        author="alice", expected_revision=replacement.revision,
    )
    unchanged = service.get_action("INV-A", "ACT-GENERATED001")
    assert unchanged.finding_ids == ("FIND-001",)
    assert unchanged.status == "proposed"

    transitioned = _transition(service, superseded.revision, "approved")
    action = transitioned.investigation.response_actions[0]
    assert action.finding_ids == ("FIND-001",)
    assert action.status == "approved"

    with pytest.raises(InvalidResponseActionFindingError):
        _create(service, action_id="ACT-OLD", finding_ids=("FIND-001",), expected_revision=transitioned.revision)
    separate = _create(service, action_id="ACT-NEW", finding_ids=("FIND-002",), expected_revision=transitioned.revision)
    assert separate.investigation.response_actions[-1].finding_ids == ("FIND-002",)


def test_transition_mutates_only_action_and_workspace_metadata(tmp_path):
    _repository, _workspace, service, current = _created(tmp_path)
    before = current.investigation
    result = _transition(service, current.revision, "approved")
    after = result.investigation
    assert after.analysis_id == before.analysis_id
    assert after.evidence_references == before.evidence_references
    assert after.hypotheses == before.hypotheses
    assert after.decisions == before.decisions
    assert after.findings == before.findings
    assert after.timeline_selections == before.timeline_selections
    assert after.annotations == before.annotations
    assert after.handoff_manifest == before.handoff_manifest
    assert after.provenance == before.provenance
    assert after.response_actions != before.response_actions