import json
import threading
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.console import InvestigationConsoleController
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.models import EvidenceReference
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.web.app import make_server


def _start(out_dir, workspace_root):
    server = make_server(
        "127.0.0.1",
        0,
        out_dir,
        workspace_root=workspace_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, {"host": host, "port": port, "server": server}


def _stop(server, thread):
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    assert not thread.is_alive()


def _request(info, method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    connection = HTTPConnection(info["host"], info["port"], timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        content_type = response.getheader("Content-Type") or ""
        parsed = (
            json.loads(data.decode("utf-8"))
            if data and content_type.startswith("application/json")
            else data
        )
        return response.status, dict(response.getheaders()), parsed
    finally:
        connection.close()


def _hashes(paths):
    return {
        key: sha256(Path(path).read_bytes()).hexdigest()
        for key, path in paths.items()
    }


def _prepare(tmp_path, investigation=None):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    analysis = build_query_analysis(out_dir)
    investigation = investigation or build_query_investigation(analysis)
    repository = InvestigationRepository(workspace_root)
    assert repository.save(investigation) == 1
    CompletedAnalysisSnapshotStore(out_dir).publish(analysis)
    return analysis, investigation, out_dir, workspace_root


def test_real_http_restart_explicitly_restores_source_dependent_workflows(tmp_path):
    analysis, investigation, out_dir, workspace_root = _prepare(tmp_path)
    repository_file = next((workspace_root / "investigations").glob("*.json"))
    repository_before = repository_file.read_bytes()
    artifacts_before = _hashes(analysis.artifacts)

    first, first_thread, first_info = _start(out_dir, workspace_root)
    first.active_analysis_result = analysis
    try:
        status, _, original_timeline = _request(
            first_info, "GET", "/api/investigations/INV-QUERY/timeline"
        )
        assert status == 200
        status, _, original_entities = _request(
            first_info, "GET", "/api/investigations/INV-QUERY/entities"
        )
        assert status == 200
    finally:
        _stop(first, first_thread)

    restarted, restarted_thread, restarted_info = _start(out_dir, workspace_root)
    try:
        assert restarted.active_analysis_result is None
        status, _, summaries = _request(
            restarted_info, "GET", "/api/investigations"
        )
        assert status == 200
        assert [item["investigation_id"] for item in summaries] == ["INV-QUERY"]

        status, _, detail = _request(
            restarted_info, "GET", "/api/investigations/INV-QUERY"
        )
        assert status == 200
        assert detail["source_analysis"] == {
            "source_analysis_id": investigation.analysis_id,
            "available": False,
            "status": "unavailable",
        }
        assert detail["investigation"]["metadata"]["title"]
        assert detail["revision"] == 1

        status, _, unavailable = _request(
            restarted_info, "GET", "/api/investigations/INV-QUERY/timeline"
        )
        assert status == 409
        assert unavailable["error"]["code"] == "analysis_unavailable"

        status, headers, activated = _request(
            restarted_info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert activated == {
            "investigation_id": "INV-QUERY",
            "source_analysis_id": investigation.analysis_id,
            "loaded": True,
            "event_count": len(analysis.events),
            "alert_count": len(analysis.alerts),
            "case_count": len(analysis.cases),
            "reconstruction_count": len(analysis.reconstructions),
            "message": "Source analysis is available in this server session.",
        }
        assert AnalysisEvidenceCatalog().source_analysis_id(
            restarted.active_analysis_result
        ) == investigation.analysis_id

        status, _, recovered_timeline = _request(
            restarted_info, "GET", "/api/investigations/INV-QUERY/timeline"
        )
        assert status == 200
        assert recovered_timeline["timed_entries"] == original_timeline["timed_entries"]
        assert recovered_timeline["untimed_entries"] == original_timeline["untimed_entries"]

        status, _, recovered_entities = _request(
            restarted_info, "GET", "/api/investigations/INV-QUERY/entities"
        )
        assert status == 200
        assert recovered_entities == original_entities

        status, _, candidates = _request(
            restarted_info,
            "GET",
            "/api/investigations/INV-QUERY/evidence/candidates?type=alert",
        )
        assert status == 200
        candidate_id = candidates["candidates"][0]["evidence_id"]
        status, _, evidence = _request(
            restarted_info,
            "GET",
            "/api/investigations/INV-QUERY/evidence/candidates/" + candidate_id,
        )
        assert status == 200
        assert evidence["candidate"]["evidence_id"] == candidate_id

        status, _, preview = _request(
            restarted_info,
            "GET",
            "/api/investigations/INV-QUERY/handoff/preview",
        )
        assert status == 200
        assert preview["source_analysis_id"] == investigation.analysis_id
        status, _, exported = _request(
            restarted_info,
            "POST",
            "/api/investigations/INV-QUERY/handoff/export",
            {
                "expected_revision": 1,
                "output_root": "handoffs",
                "overwrite": False,
                "sensitive_data_acknowledged": True,
            },
        )
        assert status == 200
        assert exported["validation_status"] == "valid"

        status, _, available_detail = _request(
            restarted_info, "GET", "/api/investigations/INV-QUERY"
        )
        assert status == 200
        assert available_detail["source_analysis"]["available"] is True
        assert available_detail["revision"] == 1
    finally:
        _stop(restarted, restarted_thread)

    assert repository_file.read_bytes() == repository_before
    assert _hashes(analysis.artifacts) == artifacts_before


def test_different_active_analysis_does_not_satisfy_investigation(tmp_path):
    analysis, investigation, out_dir, workspace_root = _prepare(tmp_path)
    different = build_query_analysis(tmp_path / "different")
    different.events[0]["timestamp"] = "2030-01-01T00:00:00Z"
    server, thread, info = _start(out_dir, workspace_root)
    server.active_analysis_result = different
    try:
        status, _, payload = _request(
            info, "GET", "/api/investigations/INV-QUERY/timeline"
        )
        assert status == 409
        assert payload["error"]["code"] == "analysis_provenance_mismatch"

        status, _, loaded = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 200
        assert loaded["source_analysis_id"] == investigation.analysis_id
        assert AnalysisEvidenceCatalog().source_analysis_id(
            server.active_analysis_result
        ) == AnalysisEvidenceCatalog().source_analysis_id(analysis)
    finally:
        _stop(server, thread)


def test_missing_and_corrupt_snapshots_return_controlled_errors_without_activation(
    tmp_path,
):
    analysis, investigation, out_dir, workspace_root = _prepare(tmp_path)
    source_id = investigation.analysis_id
    store = CompletedAnalysisSnapshotStore(out_dir)
    snapshot_path = store.root / source_id
    server, thread, info = _start(out_dir, workspace_root)
    try:
        snapshot_path.rename(store.root / ("analysis-" + "f" * 20))
        status, headers, missing = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 404
        assert headers["Cache-Control"] == "no-store"
        assert missing["error"]["code"] == "snapshot_not_found"
        assert str(tmp_path) not in json.dumps(missing)
        assert server.active_analysis_result is None

        moved = store.root / ("analysis-" + "f" * 20)
        moved.rename(snapshot_path)
        (snapshot_path / "events.json").write_text("[]\n")
        status, _, corrupt = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 422
        assert corrupt["error"]["code"] == "snapshot_integrity_error"
        rendered = json.dumps(corrupt)
        assert str(tmp_path) not in rendered
        assert "EVENT-001" not in rendered
        assert "traceback" not in rendered.casefold()
        assert server.active_analysis_result is None
    finally:
        _stop(server, thread)


def test_reference_validation_failure_never_rebinds_or_mutates_workspace(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    analysis = build_query_analysis(out_dir)
    investigation = build_query_investigation(analysis)
    bad_reference = EvidenceReference(
        reference_id="SCOPE-MISSING",
        source_type="case",
        source_id="CASE-MISSING",
        case_id="CASE-MISSING",
        origin="scope",
    )
    investigation = investigation.__class__(
        schema_version=investigation.schema_version,
        investigation_id=investigation.investigation_id,
        analysis_id=investigation.analysis_id,
        metadata=investigation.metadata,
        evidence_references=investigation.evidence_references + (bad_reference,),
        hypotheses=investigation.hypotheses,
        decisions=investigation.decisions,
        timeline_selections=investigation.timeline_selections,
        annotations=investigation.annotations,
        handoff_manifest=investigation.handoff_manifest,
        provenance=investigation.provenance,
    )
    repository = InvestigationRepository(workspace_root)
    assert repository.save(investigation) == 1
    CompletedAnalysisSnapshotStore(out_dir).publish(analysis)
    repository_file = next((workspace_root / "investigations").glob("*.json"))
    before = repository_file.read_bytes()

    server, thread, info = _start(out_dir, workspace_root)
    try:
        status, _, payload = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 409
        assert payload["error"]["code"] == "source_reference_not_found"
        assert server.active_analysis_result is None
    finally:
        _stop(server, thread)
    assert repository_file.read_bytes() == before


def test_console_and_web_snapshot_recovery_are_semantically_equivalent(tmp_path):
    analysis, investigation, out_dir, workspace_root = _prepare(tmp_path)
    repository = InvestigationRepository(workspace_root)
    service = InvestigationWorkspaceService(repository)
    current = service.get_investigation(investigation.investigation_id)
    console_state = {"analysis": None}
    values = iter(["14", "0"])
    controller = InvestigationConsoleController(
        bootstrap_adapter=InvestigationBootstrapAdapter(service),
        workspace_service=service,
        analysis_provider=lambda: console_state["analysis"],
        workspace_root=workspace_root,
        input_func=lambda _prompt="": next(values),
        output_func=lambda _message: None,
        screen_func=lambda _title: None,
        pause_func=lambda: None,
        snapshot_store=CompletedAnalysisSnapshotStore(out_dir),
        analysis_activator=lambda result: console_state.update(analysis=result),
    )
    controller.workspace_loop(current)
    console_analysis = console_state["analysis"]
    console_context = InvestigationQueryContext(console_analysis, investigation)

    server, thread, info = _start(out_dir, workspace_root)
    try:
        status, _, payload = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 200
        web_analysis = server.active_analysis_result
        web_context = InvestigationQueryContext(web_analysis, investigation)

        timeline_service = InvestigationTimelineService()
        assert timeline_service.timeline(web_context) == timeline_service.timeline(
            console_context
        )
        pivot_service = InvestigationPivotService()
        assert pivot_service.entities(web_context) == pivot_service.entities(
            console_context
        )
        selected = next(
            item
            for item in investigation.evidence_references
            if item.origin == "analyst_selection"
        )
        assert web_context.evidence_catalog.get_candidate(
            web_analysis, selected.reference_id
        ) == console_context.evidence_catalog.get_candidate(
            console_analysis, selected.reference_id
        )
        status, _, handoff = _request(
            info, "GET", "/api/investigations/INV-QUERY/handoff/preview"
        )
        assert status == 200
        assert handoff["source_analysis_id"] == payload["source_analysis_id"]
        assert payload["source_analysis_id"] == console_context.source_analysis_id
    finally:
        _stop(server, thread)


def test_browser_exposes_explicit_safe_activation_control():
    source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "investigations.js"
    ).read_text(encoding="utf-8")

    assert "Unavailable in current server session" in source
    assert "Load Source Analysis" in source
    assert "/source-analysis/load" in source
    assert "localStorage" not in source
    assert "source_analysis_id: payload.source_analysis_id" in source


@pytest.mark.parametrize("recovered", [False, True])
def test_pivot_evidence_identifiers_resolve_without_mutation(tmp_path, recovered):
    analysis, investigation, out_dir, workspace_root = _prepare(tmp_path)
    repository_file = next((workspace_root / "investigations").glob("*.json"))
    repository_before = repository_file.read_bytes()
    artifacts_before = _hashes(analysis.artifacts)
    server, thread, info = _start(out_dir, workspace_root)
    try:
        if recovered:
            status, _, _ = _request(
                info,
                "POST",
                "/api/investigations/INV-QUERY/source-analysis/load",
                {},
            )
            assert status == 200
        else:
            server.active_analysis_result = analysis

        status, _, entities = _request(
            info, "GET", "/api/investigations/INV-QUERY/entities?type=host"
        )
        assert status == 200
        host = next(
            item for item in entities["entities"]
            if item["display_value"] == "WS-LAB-01"
        )
        root = (
            "/api/investigations/INV-QUERY/entities/"
            + host["entity_id"]
        )
        for category in ("events", "alerts", "evidence"):
            status, _, pivot = _request(info, "GET", root + "/" + category)
            assert status == 200
            evidence_ids = [
                item["evidence_id"]
                for item in pivot["matches"]
                if item.get("evidence_id")
            ]
            assert evidence_ids, category
            for evidence_id in evidence_ids:
                status, _, detail = _request(
                    info,
                    "GET",
                    "/api/investigations/INV-QUERY/evidence/candidates/"
                    + evidence_id,
                )
                assert status == 200
                assert detail["candidate"]["evidence_id"] == evidence_id
                assert all(
                    field["value_hidden"]
                    for field in detail["details"]["fields"]
                    if field["sensitive"]
                )

        status, _, cases = _request(info, "GET", root + "/cases")
        assert status == 200
        assert cases["matches"]
        assert all(item.get("evidence_id") is None for item in cases["matches"])

        assert server.investigation_app.get_investigation(
            "INV-QUERY"
        )["revision"] == 1
    finally:
        _stop(server, thread)

    assert repository_file.read_bytes() == repository_before
    assert _hashes(analysis.artifacts) == artifacts_before


def test_pivot_view_evidence_renders_and_reports_errors_in_workbench():
    query_source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "query_workbench.js"
    ).read_text(encoding="utf-8")
    evidence_source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "investigations.js"
    ).read_text(encoding="utf-8")

    assert "inspectQueryEvidence(item.evidence_id)" in query_source
    assert "inspectEvidence(evidenceId, false, '#workbenchContent')" in query_source
    assert "showQueryError(error)" in query_source
    assert "function renderEvidenceDetails(payload, targetSelector" in evidence_source
    assert "targetSelector = '#evidenceWorkspace'" in evidence_source
    assert "targetSelector === '#workbenchContent' ? showQueryError" in evidence_source
