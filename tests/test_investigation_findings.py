import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.finding_service import (
    DuplicateFindingError,
    FindingNotFoundError,
    InvalidFindingReferenceError,
    InvestigationFindingService,
    FindingLifecycleError,
    SupersededFindingReadOnlyError,
)
from soc_forge.investigations.models import (
    FINDING_CONCLUSION_LIMIT,
    FINDING_LIMITATION_LIMIT,
    FINDING_TITLE_LIMIT,
    Investigation,
    InvestigationFinding,
)
from soc_forge.investigations.repository import (
    InvestigationConflictError, InvestigationRepository,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService


def _fixture(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(tmp_path / "workspace")
    assert repository.save(investigation) == 1
    times = iter(
        (
            "2026-08-12T10:00:00Z", "2026-08-12T10:05:00Z",
            "2026-08-12T10:10:00Z", "2026-08-12T10:15:00Z",
            "2026-08-12T10:20:00Z", "2026-08-12T10:25:00Z",
        )
    )
    workspace = InvestigationWorkspaceService(
        repository, clock=lambda: "2026-08-12T09:59:00Z"
    )
    service = InvestigationFindingService(workspace, clock=lambda: next(times))
    selected = tuple(
        item.reference_id for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    hypotheses = tuple(item.hypothesis_id for item in investigation.hypotheses)
    decisions = tuple(item.decision_id for item in investigation.decisions)
    return analysis, investigation, repository, workspace, service, selected, hypotheses, decisions


def _create(service, investigation, selected, hypotheses, decisions):
    return service.create_finding(
        investigation.investigation_id,
        finding_id="FIND-001",
        title="Security controls were modified",
        conclusion="Analyst review links the selected evidence to control tampering.",
        status="draft",
        confidence="medium",
        author="alice",
        expected_revision=1,
        evidence_ids=selected[:1],
        hypothesis_ids=hypotheses[:1],
        decision_ids=decisions[:1],
        attack_tactics=("Defense Evasion",),
        attack_techniques=("T1562.001",),
        limitations=("Command-line visibility may be incomplete.",),
    )


def _hashes(analysis):
    return {
        key: sha256(Path(path).read_bytes()).hexdigest()
        for key, path in analysis.artifacts.items()
    }


def test_create_get_list_and_update_finding_are_revisioned_and_immutable(tmp_path):
    values = _fixture(tmp_path)
    analysis, investigation, repository, workspace, service, selected, hypotheses, decisions = values
    created = _create(service, investigation, selected, hypotheses, decisions)

    assert created.revision == 2
    finding = service.get_finding("INV-QUERY", "FIND-001")
    assert service.list_findings("INV-QUERY") == (finding,)
    assert finding.investigation_id == "INV-QUERY"
    assert finding.status == "draft"
    assert finding.confidence == "medium"
    assert finding.created_at == finding.updated_at == "2026-08-12T10:00:00Z"
    with pytest.raises(FrozenInstanceError):
        finding.title = "changed"

    updated = service.update_finding(
        "INV-QUERY",
        "FIND-001",
        title="Updated analyst finding",
        status="substantiated",
        confidence="high",
        evidence_ids=selected[:2],
        expected_revision=created.revision,
    )
    revised = service.get_finding("INV-QUERY", "FIND-001")
    assert updated.revision == 3
    assert revised.created_at == "2026-08-12T10:00:00Z"
    assert revised.updated_at == "2026-08-12T10:05:00Z"
    assert revised.status == "substantiated"
    assert revised.confidence == "high"
    assert len(revised.evidence_ids) == 2

    reloaded = InvestigationWorkspaceService(
        InvestigationRepository(tmp_path / "workspace")
    ).get_investigation("INV-QUERY")
    assert reloaded.investigation.findings == (revised,)
    assert json.dumps(revised.to_dict(), sort_keys=True)


def test_noop_update_does_not_increment_revision_or_change_bytes(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, _workspace, service, selected, hypotheses, decisions = values
    created = _create(service, investigation, selected, hypotheses, decisions)
    record = next(repository.investigations_root.glob("*.json"))
    before = record.read_bytes()

    result = service.update_finding(
        "INV-QUERY", "FIND-001", title="Security controls were modified",
        expected_revision=created.revision,
    )

    assert result.revision == created.revision
    assert record.read_bytes() == before


@pytest.mark.parametrize("status", ["draft", "substantiated", "unsubstantiated", "inconclusive"])
@pytest.mark.parametrize("confidence", ["low", "medium", "high"])
def test_controlled_status_and_confidence_values(tmp_path, status, confidence):
    values = _fixture(tmp_path)
    _analysis, investigation, _repo, _workspace, service, selected, hypotheses, decisions = values
    result = service.create_finding(
        "INV-QUERY", finding_id="FIND-CONTROLLED", title="Controlled",
        conclusion="Analyst-authored conclusion.", status=status,
        confidence=confidence, author="alice", expected_revision=1,
        evidence_ids=selected[:1],
    )
    finding = result.investigation.findings[0]
    assert (finding.status, finding.confidence) == (status, confidence)


@pytest.mark.parametrize(
    ("field", "value"),
    [("status", "confirmed"), ("confidence", "certain")],
)
def test_invalid_controlled_values_are_rejected_without_save(tmp_path, field, value):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, workspace, service, selected, hypotheses, decisions = values
    kwargs = dict(
        finding_id="FIND-BAD", title="Bad", conclusion="Analyst conclusion",
        status="draft", confidence="low", author="alice", expected_revision=1,
        evidence_ids=selected[:1],
    )
    kwargs[field] = value
    before = next(repository.investigations_root.glob("*.json")).read_bytes()
    with pytest.raises(ValueError):
        service.create_finding("INV-QUERY", **kwargs)
    assert workspace.get_investigation("INV-QUERY").revision == 1
    assert next(repository.investigations_root.glob("*.json")).read_bytes() == before


@pytest.mark.parametrize(
    ("relationship", "kwargs"),
    [
        ("evidence", {"evidence_ids": ("EVIDENCE-MISSING",)}),
        ("hypothesis", {"hypothesis_ids": ("HYP-MISSING",)}),
        ("decision", {"decision_ids": ("DEC-MISSING",)}),
    ],
)
def test_invalid_relationships_are_rejected(tmp_path, relationship, kwargs):
    values = _fixture(tmp_path)
    _analysis, investigation, _repo, workspace, service, selected, hypotheses, decisions = values
    base = dict(
        finding_id="FIND-BAD-REF", title="Bad reference",
        conclusion="Analyst conclusion", status="draft", confidence="low",
        author="alice", expected_revision=1,
    )
    base.update(kwargs)
    with pytest.raises(InvalidFindingReferenceError, match=relationship):
        service.create_finding("INV-QUERY", **base)
    assert workspace.get_investigation("INV-QUERY").revision == 1


def test_scope_evidence_and_cross_investigation_reference_are_rejected(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, workspace, service, selected, hypotheses, decisions = values
    scope_id = next(
        item.reference_id for item in investigation.evidence_references
        if item.origin == "scope"
    )
    with pytest.raises(InvalidFindingReferenceError):
        service.create_finding(
            "INV-QUERY", finding_id="FIND-SCOPE", title="Scope only",
            conclusion="Conclusion", status="draft", confidence="low",
            author="alice", expected_revision=1, evidence_ids=(scope_id,),
        )

    other = replace(
        investigation,
        investigation_id="INV-OTHER",
        metadata=replace(investigation.metadata, title="Other"),
        evidence_references=tuple(
            item for item in investigation.evidence_references if item.origin == "scope"
        ),
        hypotheses=(),
        decisions=(),
        timeline_selections=(),
        annotations=(),
        findings=(),
    )
    assert repository.save(other) == 1
    other_service = InvestigationFindingService(workspace)
    with pytest.raises(InvalidFindingReferenceError):
        other_service.create_finding(
            "INV-OTHER", finding_id="FIND-CROSS", title="Cross",
            conclusion="Conclusion", status="draft", confidence="low",
            author="alice", expected_revision=1, evidence_ids=selected[:1],
        )


@pytest.mark.parametrize("finding_id", ["../FIND", "FIND/ONE", "FIND ONE", ""])
def test_malformed_finding_ids_are_rejected(tmp_path, finding_id):
    with pytest.raises(ValueError):
        InvestigationFinding(
            finding_id=finding_id, investigation_id="INV-001", title="Title",
            conclusion="Conclusion", status="draft", confidence="low",
            author="alice", created_at="2026-08-12T10:00:00Z",
            updated_at="2026-08-12T10:00:00Z", evidence_ids=("EVIDENCE-1",),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "x" * (FINDING_TITLE_LIMIT + 1)),
        ("conclusion", "x" * (FINDING_CONCLUSION_LIMIT + 1)),
        ("limitations", ("x" * (FINDING_LIMITATION_LIMIT + 1),)),
    ],
)
def test_free_text_is_bounded(field, value):
    kwargs = dict(
        finding_id="FIND-001", investigation_id="INV-001", title="Title",
        conclusion="Conclusion", status="draft", confidence="low",
        author="alice", created_at="2026-08-12T10:00:00Z",
        updated_at="2026-08-12T10:00:00Z", evidence_ids=("EVIDENCE-1",),
    )
    kwargs[field] = value
    with pytest.raises(ValueError):
        InvestigationFinding(**kwargs)


def test_duplicate_relationships_and_missing_basis_are_rejected():
    base = dict(
        finding_id="FIND-001", investigation_id="INV-001", title="Title",
        conclusion="Conclusion", status="draft", confidence="low",
        author="alice", created_at="2026-08-12T10:00:00Z",
        updated_at="2026-08-12T10:00:00Z",
    )
    with pytest.raises(ValueError, match="duplicates"):
        InvestigationFinding(**base, evidence_ids=("E-1", "E-1"))
    with pytest.raises(ValueError, match="at least one"):
        InvestigationFinding(**base)


def test_reads_and_offline_restart_do_not_mutate_any_analysis_owned_state(tmp_path):
    values = _fixture(tmp_path)
    analysis, investigation, repository, workspace, service, selected, hypotheses, decisions = values
    created = _create(service, investigation, selected, hypotheses, decisions)
    record = next(repository.investigations_root.glob("*.json"))
    repository_before = record.read_bytes()
    analysis_before = deepcopy(analysis)
    artifacts_before = _hashes(analysis)

    restarted_service = InvestigationFindingService(
        InvestigationWorkspaceService(
            InvestigationRepository(tmp_path / "workspace")
        )
    )
    assert restarted_service.list_findings("INV-QUERY")[0].finding_id == "FIND-001"
    assert restarted_service.get_finding("INV-QUERY", "FIND-001").conclusion
    assert record.read_bytes() == repository_before
    assert workspace.get_investigation("INV-QUERY").revision == created.revision
    assert analysis == analysis_before
    assert _hashes(analysis) == artifacts_before


def test_old_record_without_findings_loads_as_empty_collection(tmp_path):
    values = _fixture(tmp_path)
    _analysis, _investigation, repository, workspace, _service, *_rest = values
    record = next(repository.investigations_root.glob("*.json"))
    payload = json.loads(record.read_text())
    payload["investigation"].pop("findings", None)
    record.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    loaded = workspace.get_investigation("INV-QUERY")

    assert loaded.investigation.findings == ()
    assert loaded.revision == 1


def test_duplicate_and_missing_finding_errors(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, _repo, _workspace, service, selected, hypotheses, decisions = values
    created = _create(service, investigation, selected, hypotheses, decisions)
    with pytest.raises(DuplicateFindingError):
        service.create_finding(
            "INV-QUERY", finding_id="FIND-001", title="Duplicate",
            conclusion="Duplicate", status="draft", confidence="low",
            author="alice", expected_revision=created.revision,
            evidence_ids=selected[:1],
        )
    with pytest.raises(FindingNotFoundError):
        service.get_finding("INV-QUERY", "FIND-MISSING")


def _create_replacement(service, revision, evidence_id, finding_id="FIND-002"):
    return service.create_finding(
        "INV-QUERY", finding_id=finding_id, title="Replacement conclusion",
        conclusion="A later analyst conclusion.", status="inconclusive",
        confidence="low", author="bob", expected_revision=revision,
        evidence_ids=(evidence_id,),
    )


def test_legacy_finding_defaults_active_without_rewrite(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, _workspace, service, selected, hypotheses, decisions = values
    created = _create(service, investigation, selected, hypotheses, decisions)
    path = next(repository.investigations_root.glob("*.json"))
    payload = json.loads(path.read_text())
    finding = payload["investigation"]["findings"][0]
    for key in (
        "lifecycle_state", "supersedes_finding_id", "superseded_by_finding_id",
        "supersession_reason", "supersession_author", "superseded_at",
    ):
        finding.pop(key, None)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    before = path.read_bytes()

    loaded = InvestigationRepository(tmp_path / "workspace").load_record("INV-QUERY")

    assert loaded.investigation.findings[0].lifecycle_state == "active"
    assert path.read_bytes() == before


def test_supersession_is_atomic_persistent_chain_safe_and_historical_read_only(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, _workspace, service, selected, hypotheses, decisions = values
    first = _create(service, investigation, selected, hypotheses, decisions)
    second = _create_replacement(service, first.revision, selected[0])

    result = service.supersede_finding(
        "INV-QUERY", "FIND-001", "FIND-002", reason="Evidence changed",
        author="alice", expected_revision=second.revision,
    )

    assert result.revision == second.revision + 1
    old = service.get_finding("INV-QUERY", "FIND-001")
    new = service.get_finding("INV-QUERY", "FIND-002")
    assert old.status == "draft"
    assert old.lifecycle_state == "superseded"
    assert old.superseded_by_finding_id == "FIND-002"
    assert old.supersession_reason == "Evidence changed"
    assert old.supersession_author == "alice"
    assert old.superseded_at
    assert new.status == "inconclusive"
    assert new.lifecycle_state == "active"
    assert new.supersedes_finding_id == "FIND-001"
    assert service.list_active_findings("INV-QUERY") == (new,)
    assert service.list_historical_findings("INV-QUERY") == (old,)
    assert service.resolve_current_finding("INV-QUERY", "FIND-001") == new
    with pytest.raises(SupersededFindingReadOnlyError):
        service.update_finding("INV-QUERY", "FIND-001", title="rewrite", expected_revision=result.revision)
    assert InvestigationRepository(tmp_path / "workspace").load_record("INV-QUERY").investigation.findings == (old, new)


@pytest.mark.parametrize("mode", ["self", "unknown", "duplicate", "stale"])
def test_invalid_supersession_is_rejected_without_revision_change(tmp_path, mode):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, workspace, service, selected, hypotheses, decisions = values
    first = _create(service, investigation, selected, hypotheses, decisions)
    second = _create_replacement(service, first.revision, selected[0])
    before = next(repository.investigations_root.glob("*.json")).read_bytes()
    kwargs = dict(reason="Reason", author="alice", expected_revision=second.revision)
    with pytest.raises((FindingLifecycleError, FindingNotFoundError, InvestigationConflictError)):
        if mode == "self":
            service.supersede_finding("INV-QUERY", "FIND-001", "FIND-001", **kwargs)
        elif mode == "unknown":
            service.supersede_finding("INV-QUERY", "FIND-001", "FIND-MISSING", **kwargs)
        elif mode == "stale":
            service.supersede_finding("INV-QUERY", "FIND-001", "FIND-002", **{**kwargs, "expected_revision": 1})
        else:
            done = service.supersede_finding("INV-QUERY", "FIND-001", "FIND-002", **kwargs)
            before = next(repository.investigations_root.glob("*.json")).read_bytes()
            service.supersede_finding("INV-QUERY", "FIND-001", "FIND-002", reason="Again", author="alice", expected_revision=done.revision)
    if mode != "duplicate":
        assert workspace.get_investigation("INV-QUERY").revision == second.revision
        assert next(repository.investigations_root.glob("*.json")).read_bytes() == before


def test_supersession_chain_resolves_to_current_finding(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, _repository, _workspace, service, selected, hypotheses, decisions = values
    first = _create(service, investigation, selected, hypotheses, decisions)
    second = _create_replacement(service, first.revision, selected[0])
    linked = service.supersede_finding(
        "INV-QUERY", "FIND-001", "FIND-002", reason="First revision",
        author="alice", expected_revision=second.revision,
    )
    third = _create_replacement(
        service, linked.revision, selected[0], finding_id="FIND-003"
    )

    chained = service.supersede_finding(
        "INV-QUERY", "FIND-002", "FIND-003", reason="Second revision",
        author="bob", expected_revision=third.revision,
    )

    assert chained.revision == third.revision + 1
    assert service.resolve_current_finding("INV-QUERY", "FIND-001").finding_id == "FIND-003"
    assert service.resolve_current_finding("INV-QUERY", "FIND-002").finding_id == "FIND-003"
    assert [item.finding_id for item in service.list_historical_findings("INV-QUERY")] == [
        "FIND-001", "FIND-002"
    ]


def test_foreign_investigation_replacement_is_not_resolved(tmp_path):
    values = _fixture(tmp_path)
    _analysis, investigation, repository, _workspace, service, selected, hypotheses, decisions = values
    first = _create(service, investigation, selected, hypotheses, decisions)
    foreign = replace(
        investigation, investigation_id="INV-OTHER", annotations=(), findings=()
    )
    assert repository.save(foreign) == 1
    foreign_service = InvestigationFindingService(
        InvestigationWorkspaceService(repository),
        clock=lambda: "2026-08-12T11:00:00Z",
    )
    foreign_created = foreign_service.create_finding(
        "INV-OTHER", finding_id="FIND-FOREIGN", title="Foreign",
        conclusion="Foreign conclusion.", status="draft", confidence="low",
        author="bob", evidence_ids=(selected[0],), expected_revision=1,
    )
    before = next(
        path for path in repository.investigations_root.glob("*.json")
        if "INV-QUERY" in path.read_text()
    ).read_bytes()

    with pytest.raises(FindingNotFoundError):
        service.supersede_finding(
            "INV-QUERY", "FIND-001", "FIND-FOREIGN", reason="Invalid scope",
            author="alice", expected_revision=first.revision,
        )

    assert repository.load_record("INV-QUERY").revision == first.revision
    assert foreign_created.revision == 2
    assert next(
        path for path in repository.investigations_root.glob("*.json")
        if "INV-QUERY" in path.read_text()
    ).read_bytes() == before
