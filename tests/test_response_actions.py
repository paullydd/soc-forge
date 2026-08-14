import json
from dataclasses import replace

import pytest

from soc_forge.investigations.finding_service import InvestigationFindingService
from soc_forge.investigations.models import InvestigationFinding, ResponseAction
from soc_forge.investigations.repository import (
    InvestigationNotFoundError,
    InvestigationRepository,
)
from soc_forge.investigations.response_action_service import (
    DuplicateResponseActionError,
    InvalidResponseActionFindingError,
    InvestigationResponseActionService,
    ResponseActionNotFoundError,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from test_investigation_repository import build_investigation


NOW = "2026-08-14T12:00:00Z"


def _fixture(tmp_path, *, investigation_id="INV-A"):
    repository = InvestigationRepository(tmp_path / "workspace")
    workspace = InvestigationWorkspaceService(repository, clock=lambda: NOW)
    base = build_investigation(investigation_id)
    finding = InvestigationFinding(
        finding_id="FIND-001", investigation_id=investigation_id,
        title="Credential attack", conclusion="Password spraying was observed.",
        status="substantiated", confidence="high", author="alice",
        created_at=NOW, updated_at=NOW, decision_ids=("DECISION-001",),
    )
    investigation = replace(base, findings=(finding,), handoff_manifest=None)
    assert repository.save(investigation) == 1
    service = InvestigationResponseActionService(
        workspace, clock=lambda: NOW, id_factory=lambda: "ACT-GENERATED001"
    )
    return repository, workspace, service


def _create(service, investigation_id="INV-A", **overrides):
    values = dict(
        finding_ids=("FIND-001",), title="Reset affected credentials",
        description="Coordinate a password reset for affected accounts.",
        action_type="credential_action", priority="high",
        rationale="Reduce continued unauthorized access risk.", owner="identity-team",
        created_by="alice", expected_revision=1,
    )
    values.update(overrides)
    return service.create_action(investigation_id, **values)


def test_action_id_namespace_and_existing_investigation_id_contract():
    with pytest.raises(ValueError, match="ACT- prefix"):
        ResponseAction(
            action_id="ACTION-001", investigation_id="Investigation With Spaces",
            finding_ids=("FIND-001",), title="Contain", description="Contain host.",
            action_type="containment", priority="high", status="proposed",
            rationale="Limit impact.", owner="soc", created_by="alice",
            created_at=NOW, updated_at=NOW,
        )
    action = ResponseAction(
        action_id="ACT-001", investigation_id="Investigation With Spaces",
        finding_ids=("FIND-001",), title="Contain", description="Contain host.",
        action_type="containment", priority="high", status="proposed",
        rationale="Limit impact.", owner="soc", created_by="alice",
        created_at=NOW, updated_at=NOW,
    )
    assert action.investigation_id == "Investigation With Spaces"


def test_unknown_investigation_is_rejected_without_creating_storage(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    service = InvestigationResponseActionService(InvestigationWorkspaceService(repository))
    with pytest.raises(InvestigationNotFoundError, match="was not found"):
        service.create_action(
            "INV-MISSING", finding_ids=("FIND-001",), title="Contain",
            description="Contain host.", action_type="containment", priority="high",
            rationale="Limit impact.", owner="soc", created_by="alice",
            expected_revision=1,
        )
    assert not repository.investigations_root.exists()

def test_create_generated_action_is_durable_and_increments_once(tmp_path):
    repository, _workspace, service = _fixture(tmp_path)
    result = _create(service)
    action = result.investigation.response_actions[0]
    assert result.revision == 2
    assert action.action_id == "ACT-GENERATED001"
    assert action.status == "proposed"
    assert action.created_at == action.updated_at == NOW
    assert InvestigationRepository(repository.storage_root).load("INV-A").response_actions == (action,)


def test_explicit_id_multiple_findings_and_round_trip(tmp_path):
    repository, workspace, service = _fixture(tmp_path)
    current = workspace.get_investigation("INV-A")
    second = replace(current.investigation.findings[0], finding_id="FIND-002")
    workspace.replace_findings("INV-A", current.investigation.findings + (second,), expected_revision=1)
    result = _create(service, action_id="ACT-EXPLICIT", finding_ids=("FIND-001", "FIND-002"), expected_revision=2)
    action = result.investigation.response_actions[0]
    assert action.finding_ids == ("FIND-001", "FIND-002")
    assert ResponseAction.from_dict(action.to_dict()) == action
    assert repository.load("INV-A").response_actions[0].action_id == "ACT-EXPLICIT"


@pytest.mark.parametrize(
    ("field", "value"),
    [("action_type", "execute"), ("priority", "urgent"), ("status", "running")],
)
def test_invalid_controlled_values_are_atomic(tmp_path, field, value):
    repository, workspace, service = _fixture(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        _create(service, **{field: value})
    assert workspace.get_investigation("INV-A").revision == 1
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value"),
    [("finding_ids", ()), ("title", " "), ("description", ""),
     ("rationale", ""), ("owner", ""), ("created_by", "")],
)
def test_required_fields_are_rejected_atomically(tmp_path, field, value):
    repository, workspace, service = _fixture(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(ValueError):
        _create(service, **{field: value})
    assert workspace.get_investigation("INV-A").revision == 1
    assert path.read_bytes() == before


def test_unknown_duplicate_and_superseded_findings_are_rejected(tmp_path):
    repository, workspace, service = _fixture(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    with pytest.raises(InvalidResponseActionFindingError, match="unknown"):
        _create(service, finding_ids=("FIND-MISSING",))
    with pytest.raises(ValueError, match="duplicates"):
        _create(service, finding_ids=("FIND-001", "FIND-001"))
    current = workspace.get_investigation("INV-A")
    historical = replace(
        current.investigation.findings[0], lifecycle_state="superseded",
        superseded_by_finding_id="FIND-002", supersession_reason="Refined",
        supersession_author="alice", superseded_at=NOW,
    )
    replacement = replace(historical, finding_id="FIND-002", lifecycle_state="active",
                          supersedes_finding_id="FIND-001", superseded_by_finding_id=None,
                          supersession_reason=None, supersession_author=None, superseded_at=None)
    workspace.replace_findings("INV-A", (historical, replacement), expected_revision=1)
    with pytest.raises(InvalidResponseActionFindingError, match="superseded"):
        _create(service, finding_ids=("FIND-001",), expected_revision=2)
    assert workspace.get_investigation("INV-A").revision == 2
    assert path.read_bytes() != before


def test_cross_investigation_finding_is_rejected(tmp_path):
    repository, workspace, service = _fixture(tmp_path)
    other = replace(build_investigation("INV-B"), findings=(), handoff_manifest=None)
    repository.save(other)
    with pytest.raises(InvalidResponseActionFindingError, match="unknown"):
        service.create_action(
            "INV-B", finding_ids=("FIND-001",), title="Contain",
            description="Contain affected endpoint.", action_type="containment",
            priority="critical", rationale="Limit impact.", owner="soc",
            created_by="bob", expected_revision=1,
        )
    assert workspace.get_investigation("INV-B").revision == 1


def test_collision_and_missing_action_errors(tmp_path):
    _repository, _workspace, service = _fixture(tmp_path)
    created = _create(service)
    with pytest.raises(DuplicateResponseActionError):
        _create(service, action_id="ACT-GENERATED001", expected_revision=created.revision)
    with pytest.raises(ResponseActionNotFoundError):
        service.get_action("INV-A", "ACT-MISSING")


def test_list_and_get_are_read_only(tmp_path):
    repository, workspace, service = _fixture(tmp_path)
    created = _create(service)
    path = next(repository.investigations_root.glob("*.json"))
    before = path.read_bytes()
    assert service.get_action("INV-A", "ACT-GENERATED001") == created.investigation.response_actions[0]
    assert service.list_actions("INV-A") == created.investigation.response_actions
    assert path.read_bytes() == before
    assert workspace.get_investigation("INV-A").revision == 2


def test_existing_record_without_response_actions_loads_without_rewrite(tmp_path):
    repository, workspace, _service = _fixture(tmp_path)
    path = next(repository.investigations_root.glob("*.json"))
    payload = json.loads(path.read_text())
    payload["investigation"].pop("response_actions", None)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    before = path.read_bytes()
    loaded = workspace.get_investigation("INV-A")
    assert loaded.investigation.response_actions == ()
    assert path.read_bytes() == before


def test_existing_action_survives_later_finding_supersession(tmp_path):
    _repository, workspace, service = _fixture(tmp_path)
    created = _create(service)
    current = created.investigation
    old = replace(current.findings[0], lifecycle_state="superseded",
                  superseded_by_finding_id="FIND-002", supersession_reason="Refined",
                  supersession_author="alice", superseded_at=NOW)
    new = replace(old, finding_id="FIND-002", lifecycle_state="active",
                  supersedes_finding_id="FIND-001", superseded_by_finding_id=None,
                  supersession_reason=None, supersession_author=None, superseded_at=None)
    result = workspace.replace_findings("INV-A", (old, new), expected_revision=2)
    assert result.investigation.response_actions[0].finding_ids == ("FIND-001",)