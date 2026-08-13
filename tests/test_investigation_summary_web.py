import json
import threading
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore
from soc_forge.web.app import make_server


def _start(out_dir, workspace_root):
    server = make_server("127.0.0.1", 0, out_dir, workspace_root=workspace_root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, {"host": host, "port": port}


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
        return response.status, dict(response.getheaders()), json.loads(data)
    finally:
        connection.close()


def _fixture(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    analysis = build_query_analysis(out_dir)
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(workspace_root)
    assert repository.save(investigation) == 1
    CompletedAnalysisSnapshotStore(out_dir).publish(analysis)
    return analysis, investigation, out_dir, workspace_root, repository


def _artifact_hashes(analysis):
    return {
        name: sha256(Path(path).read_bytes()).hexdigest()
        for name, path in analysis.artifacts.items()
    }


def test_summary_route_returns_full_contract_without_mutation(tmp_path):
    analysis, investigation, out_dir, workspace_root, repository = _fixture(tmp_path)
    repo_file = next(repository.investigations_root.glob("*.json"))
    before_repo = repo_file.read_bytes()
    before_artifacts = _artifact_hashes(analysis)
    before_analysis = deepcopy(analysis)
    server, thread, info = _start(out_dir, workspace_root)
    server.active_analysis_result = analysis

    try:
        status, headers, summary = _request(
            info, "GET", "/api/investigations/INV-QUERY/summary"
        )
    finally:
        _stop(server, thread)

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert summary["schema_version"] == "1.0"
    assert summary["mode"] == "full"
    assert summary["investigation_id"] == investigation.investigation_id
    assert summary["revision"] == 1
    assert summary["findings"][0]["attribution"] == "machine"
    assert all(item["attribution"] == "analyst" for item in summary["evidence"])
    assert all(item["attribution"] == "analyst" for item in summary["hypotheses"])
    assert "Analyst assessment:" in summary["narrative"]
    assert summary["timeline"]["timed_entry_count"] > 0
    assert repo_file.read_bytes() == before_repo
    assert _artifact_hashes(analysis) == before_artifacts
    assert analysis == before_analysis


def test_summary_route_is_offline_for_missing_or_wrong_active_analysis(tmp_path):
    analysis, investigation, out_dir, workspace_root, _repository = _fixture(tmp_path)
    server, thread, info = _start(out_dir, workspace_root)
    try:
        status, headers, offline = _request(
            info, "GET", "/api/investigations/INV-QUERY/summary"
        )
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert offline["mode"] == "offline"
        assert offline["findings"] == []
        assert offline["timeline"] is None
        assert offline["evidence"]
        assert offline["hypotheses"]
        assert offline["decisions"]

        wrong = build_query_analysis(tmp_path / "different-analysis")
        wrong.events[0]["host"] = "DIFFERENT-HOST"
        server.active_analysis_result = wrong
        status, _, mismatched = _request(
            info, "GET", "/api/investigations/INV-QUERY/summary"
        )
        assert status == 200
        assert mismatched["mode"] == "offline"
        assert mismatched["source_analysis_id"] == investigation.analysis_id
    finally:
        _stop(server, thread)


def test_snapshot_activation_refreshes_summary_from_offline_to_full(tmp_path):
    analysis, _investigation, out_dir, workspace_root, repository = _fixture(tmp_path)
    repo_file = next(repository.investigations_root.glob("*.json"))
    before_repo = repo_file.read_bytes()
    before_artifacts = _artifact_hashes(analysis)
    server, thread, info = _start(out_dir, workspace_root)
    try:
        status, _, offline = _request(
            info, "GET", "/api/investigations/INV-QUERY/summary"
        )
        assert status == 200
        assert offline["mode"] == "offline"

        status, _, loaded = _request(
            info,
            "POST",
            "/api/investigations/INV-QUERY/source-analysis/load",
            {},
        )
        assert status == 200
        assert loaded["loaded"] is True

        status, _, full = _request(
            info, "GET", "/api/investigations/INV-QUERY/summary"
        )
        assert status == 200
        assert full["mode"] == "full"
        assert full["revision"] == offline["revision"] == 1
        assert full["findings"]
        assert full["timeline"] is not None
    finally:
        _stop(server, thread)

    assert repo_file.read_bytes() == before_repo
    assert _artifact_hashes(analysis) == before_artifacts


def test_summary_browser_contract_uses_safe_dom_and_existing_navigation():
    root = Path(__file__).parents[1]
    source = (root / "soc_forge/web/static/investigation_summary.js").read_text()
    investigations = (root / "soc_forge/web/static/investigations.js").read_text()
    index = (root / "soc_forge/web/static/index.html").read_text()

    assert "textContent" in source
    assert "replaceChildren" in source
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "inspectEvidence(evidenceId, false)" in source
    assert "showWebHypothesis(item.hypothesis_id)" in source
    assert "showQueryDecision(item.decision_id)" in source
    assert "openQueryTimeline" in source
    assert "openFinding(item.finding_id)" in source
    assert "innerHTML" not in source
    assert "/summary" in source
    assert "loadInvestigationSummary().catch" in investigations
    assert investigations.count("await loadInvestigationSummary()") == 0
    assert "/static/investigation_summary.js" in index


def test_summary_route_keeps_analyst_finding_visible_offline_and_full(tmp_path):
    analysis = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis)
    evidence_id = next(
        item.reference_id for item in investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    finding = InvestigationFinding(
        finding_id="FIND-WEB-SUMMARY", investigation_id="INV-QUERY",
        title="Analyst web summary finding",
        conclusion="Analyst review supports control tampering.",
        status="substantiated", confidence="high", author="alice",
        created_at="2026-08-12T10:00:00Z", updated_at="2026-08-12T10:05:00Z",
        evidence_ids=(evidence_id,), limitations=("Visibility is limited.",),
    )
    investigation = replace(investigation, findings=(finding,))
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    repository = InvestigationRepository(workspace_root)
    repository.save(investigation)
    CompletedAnalysisSnapshotStore(out_dir).publish(analysis)
    before = next(repository.investigations_root.glob("*.json")).read_bytes()
    server, thread, info = _start(out_dir, workspace_root)
    try:
        status, _, offline = _request(info, "GET", "/api/investigations/INV-QUERY/summary")
        loaded_status, _, loaded = _request(
            info, "POST",
            "/api/investigations/INV-QUERY/source-analysis/load", {},
        )
        status_full, _, full = _request(info, "GET", "/api/investigations/INV-QUERY/summary")
    finally:
        _stop(server, thread)
    assert status == loaded_status == status_full == 200
    assert loaded["loaded"] is True
    assert offline["mode"] == "offline"
    assert full["mode"] == "full"
    assert offline["analyst_findings"] == full["analyst_findings"]
    assert offline["finding_counts"]["substantiated"] == 1
    assert offline["analyst_findings"][0]["attribution"] == "analyst"
    assert "powershell.exe -enc sensitive" not in json.dumps(offline)
    assert next(repository.investigations_root.glob("*.json")).read_bytes() == before
