import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest

from soc_forge.investigations.bootstrap import (
    InvalidAnalysisResultError,
    InvalidBootstrapTitleError,
    InvestigationBootstrap,
    InvestigationBootstrapAdapter,
    MissingArtifactReferenceError,
    NoCasesSelectedError,
    UnknownCaseIdError,
)
from soc_forge.investigations.repository import (
    InvestigationAlreadyExistsError,
    InvestigationRepository,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)
from soc_forge.pipeline import AnalysisResult


FIXED_TIME = "2026-08-02T12:00:00Z"


def build_analysis_result(tmp_path, *, artifact_keys=None):
    artifact_root = tmp_path / "analysis-artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    available_keys = artifact_keys or (
        "events",
        "alerts",
        "cases",
        "hunts",
        "reconstructions",
        "report",
    )
    artifacts = {}
    for key in available_keys:
        suffix = ".html" if key == "report" else ".json"
        path = artifact_root / f"{key}{suffix}"
        path.write_text(f"{key}-content", encoding="utf-8")
        artifacts[key] = path

    cases = [
        {
            "case_id": "CASE-B",
            "title": "Credential access investigation",
            "severity": "critical",
            "items": [{"rule_id": "SOCF-021", "details": {"command_line": "sensitive"}}],
        },
        {
            "case_id": "CASE-A",
            "title": "Collection activity investigation",
            "severity": "high",
            "items": [{"rule_id": "SOCF-020"}],
        },
    ]
    return AnalysisResult(
        input_name="/unstable/source/detection_lab.jsonl",
        input_path=tmp_path / "source" / "detection_lab.jsonl",
        output_dir=artifact_root,
        alerts_path=artifacts.get("alerts"),
        report_path=artifacts.get("report"),
        cases_output_dir=artifact_root,
        hunts_path=artifacts.get("hunts"),
        reconstructions_path=artifacts.get("reconstructions"),
        events_path=artifacts.get("events"),
        event_count=6,
        events=[{"event_id": 4688, "command_line": "sensitive"}],
        alerts=[{"rule_id": "SOCF-021", "details": {"command_line": "sensitive"}}],
        legacy_alerts=[],
        yaml_alerts=[{"rule_id": "SOCF-021"}],
        correlations={"total": 0, "by_rule": []},
        hunt_findings=[{"hunt_id": "HUNT-001"}],
        risk_summary={"level": "critical"},
        cases=cases,
        reconstructions=[{"case_id": "CASE-B", "attack_path": []}],
        mitre_coverage=[],
        artifacts=artifacts,
        ingest_diagnostics=[],
    )


def build_adapter(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    service = InvestigationWorkspaceService(
        repository,
        clock=lambda: pytest.fail("service clock should not run for explicit bootstrap time"),
    )
    adapter = InvestigationBootstrapAdapter(
        service,
        clock=lambda: FIXED_TIME,
    )
    return adapter, service, repository


def test_bootstrap_one_case_uses_case_title_and_returns_revision_one(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, repository = build_adapter(tmp_path)

    result = adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-B"],
    )

    assert isinstance(result, WorkspaceResult)
    assert result.revision == 1
    assert result.investigation.metadata.title == "Credential access investigation"
    assert result.investigation.metadata.status == "open"
    assert result.investigation.metadata.created_at == FIXED_TIME
    assert result.investigation.evidence_references[0].source_id == "CASE-B"
    assert repository.load("INVESTIGATION-001") == result.investigation


def test_bootstrap_multiple_cases_has_deterministic_order_and_title(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    request = adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-B", "CASE-A"],
    )

    assert request.case_ids == ("CASE-A", "CASE-B")
    assert request.title == "Collection activity investigation and 1 related case(s)"


def test_caller_title_and_owner_override_defaults(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    result = adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
        title="  Priority endpoint review  ",
        owner="alice",
    )

    assert result.investigation.metadata.title == "Priority endpoint review"
    assert result.investigation.metadata.owner == "alice"


@pytest.mark.parametrize("case_ids", [[], (), set()])
def test_no_selected_cases_fails(case_ids, tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    with pytest.raises(NoCasesSelectedError, match="At least one"):
        adapter.build_creation_request(
            analysis,
            "INVESTIGATION-001",
            case_ids,
        )


def test_unknown_case_id_fails_with_logical_id(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    with pytest.raises(UnknownCaseIdError, match="CASE-MISSING"):
        adapter.build_creation_request(
            analysis,
            "INVESTIGATION-001",
            ["CASE-MISSING"],
        )


def test_duplicate_case_ids_are_normalized_and_sorted(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    request = adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-B", "CASE-A", "CASE-B"],
    )

    assert request.case_ids == ("CASE-A", "CASE-B")


def test_only_present_logical_artifact_keys_are_included(tmp_path):
    analysis = build_analysis_result(
        tmp_path,
        artifact_keys=("cases", "alerts", "reconstructions"),
    )
    adapter, _, _ = build_adapter(tmp_path)

    request = adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
    )

    assert request.artifact_keys == ("alerts", "cases", "reconstructions")
    assert all(not Path(key).is_absolute() for key in request.artifact_keys)


def test_missing_optional_artifacts_are_allowed(tmp_path):
    analysis = build_analysis_result(tmp_path, artifact_keys=("cases",))
    adapter, _, _ = build_adapter(tmp_path)

    result = adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
    )

    assert result.investigation.analysis_artifact_keys == ("cases",)


def test_missing_required_cases_artifact_fails(tmp_path):
    analysis = build_analysis_result(tmp_path, artifact_keys=("alerts",))
    adapter, _, _ = build_adapter(tmp_path)

    with pytest.raises(MissingArtifactReferenceError, match="'cases'"):
        adapter.build_creation_request(
            analysis,
            "INVESTIGATION-001",
            ["CASE-A"],
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda result: setattr(result, "input_name", ""),
        lambda result: setattr(result, "event_count", -1),
        lambda result: setattr(result, "cases", "not-a-list"),
        lambda result: setattr(result, "artifacts", "not-a-mapping"),
    ],
)
def test_invalid_completed_analysis_shape_fails(mutator, tmp_path):
    analysis = build_analysis_result(tmp_path)
    mutator(analysis)
    adapter, _, _ = build_adapter(tmp_path)

    with pytest.raises(InvalidAnalysisResultError):
        adapter.build_creation_request(
            analysis,
            "INVESTIGATION-001",
            ["CASE-A"],
        )


@pytest.mark.parametrize("title", ["", "   ", "line one\nline two"])
def test_invalid_caller_title_fails(title, tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    with pytest.raises(InvalidBootstrapTitleError):
        adapter.build_creation_request(
            analysis,
            "INVESTIGATION-001",
            ["CASE-A"],
            title=title,
        )


def test_duplicate_investigation_id_uses_existing_service_repository_error(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)
    adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
    )

    with pytest.raises(InvestigationAlreadyExistsError):
        adapter.bootstrap_investigation(
            analysis,
            "INVESTIGATION-001",
            ["CASE-B"],
        )


def test_bootstrap_does_not_mutate_analysis_cases_or_artifact_mapping(tmp_path):
    analysis = build_analysis_result(tmp_path)
    snapshot = deepcopy(analysis)
    cases_snapshot = deepcopy(analysis.cases)
    artifacts_snapshot = dict(analysis.artifacts)
    artifact_contents = {
        key: path.read_text(encoding="utf-8")
        for key, path in analysis.artifacts.items()
    }
    adapter, _, _ = build_adapter(tmp_path)

    adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A", "CASE-B"],
    )

    assert analysis == snapshot
    assert analysis.cases == cases_snapshot
    assert analysis.artifacts == artifacts_snapshot
    assert {
        key: path.read_text(encoding="utf-8")
        for key, path in analysis.artifacts.items()
    } == artifact_contents


def test_persisted_investigation_contains_references_not_analysis_payloads(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, repository = build_adapter(tmp_path)
    adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A", "CASE-B"],
    )
    record = (
        repository.investigations_root / "INVESTIGATION-001.json"
    ).read_text(encoding="utf-8")
    payload = json.loads(record)["investigation"]

    assert payload["analysis_artifact_keys"] == [
        "alerts",
        "cases",
        "events",
        "hunts",
        "reconstructions",
        "report",
    ]
    assert [item["source_id"] for item in payload["evidence_references"]] == [
        "CASE-A",
        "CASE-B",
    ]
    assert "events" not in payload
    assert "alerts" not in payload
    assert "cases" not in payload
    assert "reconstructions" not in payload
    assert "items" not in payload["evidence_references"][0]


def test_adapter_calls_workspace_service_not_repository_directly(tmp_path):
    analysis = build_analysis_result(tmp_path)

    class RecordingService:
        def __init__(self):
            self.calls = []

        def create_investigation(self, **kwargs):
            self.calls.append(kwargs)
            return "workspace-result"

    service = RecordingService()
    adapter = InvestigationBootstrapAdapter(service, clock=lambda: FIXED_TIME)

    result = adapter.bootstrap_investigation(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
    )

    assert result == "workspace-result"
    assert service.calls[0]["analysis_id"].startswith("analysis-")
    assert service.calls[0]["case_ids"] == ("CASE-A",)


def imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_pipeline_import_is_isolated_to_bootstrap_adapter():
    package = Path(__file__).parents[1] / "soc_forge" / "investigations"

    assert "soc_forge.pipeline" in imported_modules(package / "bootstrap.py")
    for filename in ("models.py", "repository.py", "workspace_service.py"):
        assert "soc_forge.pipeline" not in imported_modules(package / filename)


def test_identical_inputs_and_fixed_time_produce_equal_requests(tmp_path):
    analysis = build_analysis_result(tmp_path)
    first_adapter, _, _ = build_adapter(tmp_path / "first")
    second_adapter, _, _ = build_adapter(tmp_path / "second")

    first = first_adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-B", "CASE-A"],
        created_at=FIXED_TIME,
    )
    second = second_adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A", "CASE-B"],
        created_at=FIXED_TIME,
    )

    assert isinstance(first, InvestigationBootstrap)
    assert first == second


def test_selected_case_sets_change_bootstrap_id_not_source_analysis_id(tmp_path):
    analysis = build_analysis_result(tmp_path)
    adapter, _, _ = build_adapter(tmp_path)

    first = adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-A"],
        created_at=FIXED_TIME,
    )
    second = adapter.build_creation_request(
        analysis,
        "INVESTIGATION-001",
        ["CASE-B"],
        created_at=FIXED_TIME,
    )

    assert first.analysis_id == second.analysis_id
    assert first.bootstrap_id != second.bootstrap_id


def test_source_identity_ignores_absolute_paths(tmp_path):
    first = build_analysis_result(tmp_path / "first")
    second = deepcopy(first)
    second.input_name = r"C:\different\location\detection_lab.jsonl"
    second.input_path = Path("/different/location/detection_lab.jsonl")
    second.output_dir = Path("/different/output")
    second.artifacts = {
        key: Path("/moved") / path.name for key, path in first.artifacts.items()
    }
    adapter, _, _ = build_adapter(tmp_path)

    first_request = adapter.build_creation_request(
        first,
        "INVESTIGATION-001",
        ["CASE-A"],
        created_at=FIXED_TIME,
    )
    second_request = adapter.build_creation_request(
        second,
        "INVESTIGATION-001",
        ["CASE-A"],
        created_at=FIXED_TIME,
    )

    assert first_request.analysis_id == second_request.analysis_id
