import pytest

from soc_forge.investigations.repository import (
    InvestigationAlreadyExistsError,
    InvestigationConflictError,
    InvestigationRepository,
)
from soc_forge.investigations.workspace_service import (
    AnnotationNotFoundError,
    DuplicateAnnotationError,
    DuplicateDecisionError,
    InvalidOwnerError,
    InvalidStatusTransitionError,
    InvalidWorkspaceOperationError,
    InvalidWorkspaceReferenceError,
    InvestigationWorkspaceService,
    WorkspaceDeletionResult,
    WorkspaceResult,
)


class FixedClock:
    def __init__(self, *timestamps):
        self.timestamps = list(timestamps)
        self.calls = 0

    def __call__(self):
        timestamp = self.timestamps[self.calls]
        self.calls += 1
        return timestamp


def build_service(tmp_path, *timestamps):
    clock = FixedClock(
        *(
            timestamps
            or (
                "2026-08-01T12:00:00Z",
                "2026-08-01T12:05:00Z",
                "2026-08-01T12:10:00Z",
                "2026-08-01T12:15:00Z",
                "2026-08-01T12:20:00Z",
                "2026-08-01T12:25:00Z",
            )
        )
    )
    repository = InvestigationRepository(tmp_path)
    return InvestigationWorkspaceService(repository, clock=clock), repository, clock


def create_workspace(service, **overrides):
    values = {
        "investigation_id": "INVESTIGATION-001",
        "title": "Endpoint investigation",
        "analysis_id": "ANALYSIS-001",
        "case_ids": ("CASE-001", "CASE-002"),
        "artifact_keys": ("alerts", "cases", "reconstructions"),
        "owner": " analyst ",
        "initial_status": "open",
    }
    values.update(overrides)
    return service.create_investigation(**values)


def test_create_returns_revision_one_and_stores_only_analysis_references(tmp_path):
    service, repository, _ = build_service(tmp_path)

    result = create_workspace(service)

    assert isinstance(result, WorkspaceResult)
    assert result.revision == 1
    assert result.investigation.metadata.created_at == "2026-08-01T12:00:00Z"
    assert result.investigation.metadata.updated_at == "2026-08-01T12:00:00Z"
    assert result.investigation.metadata.status == "open"
    assert result.investigation.metadata.owner == "analyst"
    assert result.investigation.analysis_id == "ANALYSIS-001"
    assert result.investigation.analysis_artifact_keys == (
        "alerts",
        "cases",
        "reconstructions",
    )
    assert [reference.source_id for reference in result.investigation.evidence_references] == [
        "CASE-001",
        "CASE-002",
    ]
    assert repository.load("INVESTIGATION-001") == result.investigation


def test_duplicate_creation_fails_through_repository_contract(tmp_path):
    service, _, _ = build_service(tmp_path)
    create_workspace(service)

    with pytest.raises(InvestigationAlreadyExistsError):
        create_workspace(service)


def test_get_returns_aggregate_and_current_revision(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    loaded = service.get_investigation("INVESTIGATION-001")

    assert loaded == created


def test_list_returns_typed_summaries_in_repository_order(tmp_path):
    service, _, _ = build_service(
        tmp_path,
        "2026-08-01T12:00:00Z",
        "2026-08-01T13:00:00Z",
    )
    create_workspace(
        service,
        investigation_id="INVESTIGATION-OLD",
        title="Older",
    )
    create_workspace(
        service,
        investigation_id="INVESTIGATION-NEW",
        title="Newer",
        initial_status="escalated",
    )

    summaries = service.list_investigations()

    assert [summary.investigation_id for summary in summaries] == [
        "INVESTIGATION-NEW",
        "INVESTIGATION-OLD",
    ]
    assert summaries[0].status == "escalated"
    assert summaries[0].revision == 1


def test_assign_reassign_and_clear_owner_preserve_unrelated_state(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service, owner=None)
    original = created.investigation

    assigned = service.assign_owner(
        "INVESTIGATION-001",
        " alice ",
        expected_revision=created.revision,
    )
    reassigned = service.assign_owner(
        "INVESTIGATION-001",
        "bob",
        expected_revision=assigned.revision,
    )
    cleared = service.assign_owner(
        "INVESTIGATION-001",
        None,
        expected_revision=reassigned.revision,
    )

    assert assigned.investigation.metadata.owner == "alice"
    assert reassigned.investigation.metadata.owner == "bob"
    assert cleared.investigation.metadata.owner is None
    assert [assigned.revision, reassigned.revision, cleared.revision] == [2, 3, 4]
    assert cleared.investigation.analysis_id == original.analysis_id
    assert cleared.investigation.evidence_references == original.evidence_references
    assert original.metadata.owner is None
    assert original.metadata.updated_at == "2026-08-01T12:00:00Z"


def test_unchanged_owner_is_idempotent(tmp_path):
    service, _, clock = build_service(tmp_path)
    created = create_workspace(service)

    unchanged = service.assign_owner(
        "INVESTIGATION-001",
        "analyst",
        expected_revision=created.revision,
    )

    assert unchanged == created
    assert clock.calls == 1


@pytest.mark.parametrize("owner", ["", "   ", 7])
def test_invalid_owner_fails(owner, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    with pytest.raises(InvalidOwnerError):
        service.assign_owner(
            "INVESTIGATION-001",
            owner,
            expected_revision=created.revision,
        )


@pytest.mark.parametrize(
    ("initial_status", "target_status"),
    [
        ("open", "in_progress"),
        ("open", "closed"),
        ("in_progress", "escalated"),
        ("in_progress", "closed"),
        ("escalated", "in_progress"),
        ("escalated", "closed"),
    ],
)
def test_valid_status_transitions(initial_status, target_status, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service, initial_status=initial_status)

    updated = service.change_status(
        "INVESTIGATION-001",
        target_status,
        expected_revision=created.revision,
    )

    assert updated.investigation.metadata.status == target_status
    assert updated.revision == 2


@pytest.mark.parametrize(
    ("initial_status", "target_status"),
    [("open", "escalated"), ("closed", "in_progress"), ("closed", "open")],
)
def test_invalid_status_transitions_fail(initial_status, target_status, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service, initial_status=initial_status)

    with pytest.raises(InvalidStatusTransitionError):
        service.change_status(
            "INVESTIGATION-001",
            target_status,
            expected_revision=created.revision,
        )


def test_closed_investigation_reopens_only_through_explicit_operation(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service, initial_status="closed")

    reopened = service.reopen_investigation(
        "INVESTIGATION-001",
        expected_revision=created.revision,
    )

    assert reopened.investigation.metadata.status == "in_progress"
    assert reopened.revision == 2

    with pytest.raises(InvalidStatusTransitionError, match="must be closed"):
        service.reopen_investigation(
            "INVESTIGATION-001",
            expected_revision=reopened.revision,
        )


def test_unchanged_status_is_idempotent_without_timestamp_or_revision_change(tmp_path):
    service, _, clock = build_service(tmp_path)
    created = create_workspace(service)

    unchanged = service.change_status(
        "INVESTIGATION-001",
        "OPEN",
        expected_revision=created.revision,
    )

    assert unchanged == created
    assert clock.calls == 1


def test_add_annotation_appends_durable_analyst_owned_note(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    updated = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body=" Validate with the endpoint owner. ",
        author="alice",
        expected_revision=created.revision,
    )

    annotation = updated.investigation.annotations[0]
    assert annotation.annotation_id == "ANNOTATION-001"
    assert annotation.body == "Validate with the endpoint owner."
    assert annotation.created_by == "alice"
    assert annotation.target_type == "investigation"
    assert annotation.target_id == "INVESTIGATION-001"
    assert annotation.created_at == "2026-08-01T12:05:00Z"
    assert annotation.updated_at == annotation.created_at
    assert updated.investigation.metadata.updated_at == annotation.updated_at
    assert created.investigation.annotations == ()


def test_duplicate_annotation_id_fails_without_replacement(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    added = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body="First",
        author="alice",
        expected_revision=created.revision,
    )

    with pytest.raises(DuplicateAnnotationError):
        service.add_annotation(
            "INVESTIGATION-001",
            annotation_id="ANNOTATION-001",
            body="Replacement",
            author="bob",
            expected_revision=added.revision,
        )

    assert service.get_investigation("INVESTIGATION-001") == added


def test_update_annotation_preserves_creation_and_order(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    first = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body="First",
        author="alice",
        expected_revision=created.revision,
    )
    second = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-002",
        body="Second",
        author="bob",
        expected_revision=first.revision,
    )

    updated = service.update_annotation(
        "INVESTIGATION-001",
        "ANNOTATION-001",
        "Edited",
        expected_revision=second.revision,
    )

    assert [item.annotation_id for item in updated.investigation.annotations] == [
        "ANNOTATION-001",
        "ANNOTATION-002",
    ]
    edited = updated.investigation.annotations[0]
    assert edited.body == "Edited"
    assert edited.created_at == "2026-08-01T12:05:00Z"
    assert edited.created_by == "alice"
    assert edited.updated_at == "2026-08-01T12:15:00Z"
    assert updated.investigation.annotations[1] == second.investigation.annotations[1]


def test_remove_annotation_preserves_unrelated_annotations(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    first = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body="First",
        author="alice",
        expected_revision=created.revision,
    )
    second = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-002",
        body="Second",
        author="bob",
        expected_revision=first.revision,
    )

    updated = service.remove_annotation(
        "INVESTIGATION-001",
        "ANNOTATION-001",
        expected_revision=second.revision,
    )

    assert updated.investigation.annotations == (second.investigation.annotations[1],)


@pytest.mark.parametrize("operation", ["update", "remove"])
def test_missing_annotation_operations_fail(operation, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    with pytest.raises(AnnotationNotFoundError):
        if operation == "update":
            service.update_annotation(
                "INVESTIGATION-001",
                "ANNOTATION-MISSING",
                "Updated",
                expected_revision=created.revision,
            )
        else:
            service.remove_annotation(
                "INVESTIGATION-001",
                "ANNOTATION-MISSING",
                expected_revision=created.revision,
            )


@pytest.mark.parametrize("body", ["", "   "])
def test_empty_annotation_text_is_rejected(body, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    with pytest.raises(InvalidWorkspaceOperationError, match="annotation body"):
        service.add_annotation(
            "INVESTIGATION-001",
            annotation_id="ANNOTATION-001",
            body=body,
            author="alice",
            expected_revision=created.revision,
        )


def test_record_decision_appends_analyst_decision_without_status_side_effect(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    updated = service.record_decision(
        "INVESTIGATION-001",
        decision_id="DECISION-001",
        decision_type="disposition",
        outcome="escalate",
        rationale="Endpoint confirmation is required.",
        author="alice",
        evidence_reference_ids=("case:CASE-001",),
        hypothesis_ids=(),
        expected_revision=created.revision,
    )

    decision = updated.investigation.decisions[0]
    assert decision.decision_id == "DECISION-001"
    assert decision.rationale == "Endpoint confirmation is required."
    assert decision.decided_by == "alice"
    assert decision.decided_at == "2026-08-01T12:05:00Z"
    assert decision.evidence_reference_ids == ("case:CASE-001",)
    assert updated.investigation.metadata.status == "open"
    assert created.investigation.decisions == ()


def test_duplicate_decision_id_fails_without_replacement(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    recorded = service.record_decision(
        "INVESTIGATION-001",
        decision_id="DECISION-001",
        decision_type="triage",
        outcome="continue",
        rationale="More context is required.",
        author="alice",
        expected_revision=created.revision,
    )

    with pytest.raises(DuplicateDecisionError):
        service.record_decision(
            "INVESTIGATION-001",
            decision_id="DECISION-001",
            decision_type="triage",
            outcome="close",
            rationale="Replacement",
            author="bob",
            expected_revision=recorded.revision,
        )


def test_decisions_remain_in_append_order(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    first = service.record_decision(
        "INVESTIGATION-001",
        decision_id="DECISION-001",
        decision_type="triage",
        outcome="continue",
        rationale="Collect more context.",
        author="alice",
        expected_revision=created.revision,
    )
    second = service.record_decision(
        "INVESTIGATION-001",
        decision_id="DECISION-002",
        decision_type="disposition",
        outcome="escalate",
        rationale="Endpoint review is required.",
        author="bob",
        expected_revision=first.revision,
    )

    assert [decision.decision_id for decision in second.investigation.decisions] == [
        "DECISION-001",
        "DECISION-002",
    ]


@pytest.mark.parametrize("rationale", ["", "   "])
def test_decision_requires_rationale(rationale, tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    with pytest.raises(InvalidWorkspaceOperationError, match="decision rationale"):
        service.record_decision(
            "INVESTIGATION-001",
            decision_id="DECISION-001",
            decision_type="triage",
            outcome="continue",
            rationale=rationale,
            author="alice",
            expected_revision=created.revision,
        )


def test_stale_revision_fails_for_every_modification_category(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)
    added = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body="Existing",
        author="alice",
        expected_revision=created.revision,
    )
    stale_revision = created.revision

    operations = (
        lambda: service.assign_owner(
            "INVESTIGATION-001", "bob", expected_revision=stale_revision
        ),
        lambda: service.change_status(
            "INVESTIGATION-001", "in_progress", expected_revision=stale_revision
        ),
        lambda: service.add_annotation(
            "INVESTIGATION-001",
            annotation_id="ANNOTATION-002",
            body="New",
            author="bob",
            expected_revision=stale_revision,
        ),
        lambda: service.update_annotation(
            "INVESTIGATION-001",
            "ANNOTATION-001",
            "Changed",
            expected_revision=stale_revision,
        ),
        lambda: service.remove_annotation(
            "INVESTIGATION-001",
            "ANNOTATION-001",
            expected_revision=stale_revision,
        ),
        lambda: service.record_decision(
            "INVESTIGATION-001",
            decision_id="DECISION-001",
            decision_type="triage",
            outcome="continue",
            rationale="Need context.",
            author="alice",
            expected_revision=stale_revision,
        ),
        lambda: service.delete_investigation(
            "INVESTIGATION-001",
            expected_revision=stale_revision,
        ),
    )

    for operation in operations:
        with pytest.raises(InvestigationConflictError, match="revision 2"):
            operation()

    assert service.get_investigation("INVESTIGATION-001") == added


def test_two_services_observe_shared_revisions_without_automatic_merge(tmp_path):
    repository_a = InvestigationRepository(tmp_path)
    repository_b = InvestigationRepository(tmp_path)
    service_a = InvestigationWorkspaceService(
        repository_a,
        clock=FixedClock("2026-08-01T12:00:00Z", "2026-08-01T12:05:00Z"),
    )
    service_b = InvestigationWorkspaceService(
        repository_b,
        clock=FixedClock("2026-08-01T12:10:00Z"),
    )
    created = create_workspace(service_a)
    observed = service_b.get_investigation("INVESTIGATION-001")
    updated = service_a.assign_owner(
        "INVESTIGATION-001",
        "alice",
        expected_revision=created.revision,
    )

    assert observed.revision == 1
    assert service_b.get_investigation("INVESTIGATION-001") == updated
    with pytest.raises(InvestigationConflictError):
        service_b.assign_owner(
            "INVESTIGATION-001",
            "bob",
            expected_revision=observed.revision,
        )


def test_delete_removes_only_investigation_owned_record(tmp_path):
    artifact = tmp_path / "artifacts" / "alerts.json"
    artifact.parent.mkdir()
    artifact.write_text('[{"rule_id": "SOCF-021"}]', encoding="utf-8")
    service, repository, _ = build_service(tmp_path)
    created = create_workspace(service)

    deleted = service.delete_investigation(
        "INVESTIGATION-001",
        expected_revision=created.revision,
    )

    assert deleted == WorkspaceDeletionResult(
        investigation_id="INVESTIGATION-001",
        deleted_revision=1,
    )
    assert repository.exists("INVESTIGATION-001") is False
    assert artifact.read_text(encoding="utf-8") == '[{"rule_id": "SOCF-021"}]'


def test_injected_clock_makes_all_timestamp_updates_deterministic(tmp_path):
    service, _, clock = build_service(
        tmp_path,
        "2026-08-01T00:00:00Z",
        "2026-08-01T00:01:00Z",
        "2026-08-01T00:02:00Z",
    )
    created = create_workspace(service)
    assigned = service.assign_owner(
        "INVESTIGATION-001",
        "alice",
        expected_revision=created.revision,
    )
    annotated = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-001",
        body="Fixed time",
        author="alice",
        expected_revision=assigned.revision,
    )

    assert created.investigation.metadata.updated_at == "2026-08-01T00:00:00Z"
    assert assigned.investigation.metadata.updated_at == "2026-08-01T00:01:00Z"
    assert annotated.investigation.metadata.updated_at == "2026-08-01T00:02:00Z"
    assert clock.calls == 3

@pytest.mark.parametrize(
    ("evidence_ids", "hypothesis_ids", "missing_id"),
    [
        (("EVIDENCE-MISSING",), (), "EVIDENCE-MISSING"),
        ((), ("HYPOTHESIS-MISSING",), "HYPOTHESIS-MISSING"),
    ],
)
def test_invalid_decision_reference_does_not_save_or_increment_revision(
    evidence_ids,
    hypothesis_ids,
    missing_id,
    tmp_path,
):
    service, repository, _ = build_service(tmp_path)
    created = create_workspace(service)
    before = repository.load_record("INVESTIGATION-001")

    with pytest.raises(InvalidWorkspaceReferenceError, match=missing_id):
        service.record_decision(
            "INVESTIGATION-001",
            decision_id="DECISION-INVALID",
            decision_type="triage",
            outcome="escalate",
            rationale="Invalid reference",
            author="alice",
            evidence_reference_ids=evidence_ids,
            hypothesis_ids=hypothesis_ids,
            expected_revision=created.revision,
        )

    after = repository.load_record("INVESTIGATION-001")
    assert after == before
    assert after.revision == 1


def test_invalid_annotation_target_does_not_save_or_increment_revision(tmp_path):
    service, repository, _ = build_service(tmp_path)
    created = create_workspace(service)
    before = repository.load_record("INVESTIGATION-001")

    with pytest.raises(InvalidWorkspaceReferenceError, match="EVIDENCE-MISSING"):
        service.add_annotation(
            "INVESTIGATION-001",
            annotation_id="ANNOTATION-INVALID",
            target_type="evidence",
            target_id="EVIDENCE-MISSING",
            body="Invalid target",
            author="alice",
            expected_revision=created.revision,
        )

    assert repository.load_record("INVESTIGATION-001") == before


def test_external_case_annotation_is_explicitly_supported(tmp_path):
    service, _, _ = build_service(tmp_path)
    created = create_workspace(service)

    updated = service.add_annotation(
        "INVESTIGATION-001",
        annotation_id="ANNOTATION-CASE",
        target_type="case",
        target_id="CASE-EXTERNAL",
        body="External case reference",
        author="alice",
        expected_revision=created.revision,
    )

    assert updated.revision == 2
    assert updated.investigation.annotations[0].target_type == "case"
    assert updated.investigation.annotations[0].target_id == "CASE-EXTERNAL"
