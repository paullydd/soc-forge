import json
import threading
from copy import deepcopy
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore
from soc_forge.web.app import make_server


def _start(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    analysis = build_query_analysis(out_dir)
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(workspace_root)
    assert repository.save(investigation) == 1
    CompletedAnalysisSnapshotStore(out_dir).publish(analysis)
    server = make_server("127.0.0.1", 0, out_dir, workspace_root=workspace_root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return analysis, repository, server, thread, (host, port)


def _request(address, method, path, payload=None, raw=None):
    body = raw if raw is not None else (
        None if payload is None else json.dumps(payload).encode()
    )
    headers = {"Content-Type": "application/json"} if body is not None else {}
    connection = HTTPConnection(*address, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        parsed = json.loads(data) if data and response.getheader("Content-Type", "").startswith("application/json") else data
        return response.status, dict(response.getheaders()), parsed
    finally:
        connection.close()


def _stop(server, thread):
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    assert not thread.is_alive()


def _payload(revision=1):
    return {
        "finding_id": "FIND-WEB-001",
        "title": "Web finding",
        "conclusion": "Analyst-authored bounded conclusion.",
        "status": "draft",
        "confidence": "medium",
        "author": "alice",
        "evidence_ids": ["evidence-alert-ALERT-001"],
        "hypothesis_ids": [],
        "decision_ids": [],
        "attack_tactics": ["Defense Evasion"],
        "attack_techniques": ["T1562.001"],
        "limitations": ["Visibility is limited."],
        "expected_revision": revision,
    }


def test_findings_http_crud_offline_revision_and_read_immutability(tmp_path):
    analysis, repository, server, thread, address = _start(tmp_path)
    record = next(repository.investigations_root.glob("*.json"))
    analysis_before = deepcopy(analysis)
    artifact_before = {k: sha256(Path(v).read_bytes()).hexdigest() for k, v in analysis.artifacts.items()}
    try:
        status, headers, empty = _request(address, "GET", "/api/investigations/INV-QUERY/findings")
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert empty["findings"] == []
        before_get = record.read_bytes()

        selected_id = next(
            item.reference_id for item in build_query_investigation(analysis).evidence_references
            if item.origin == "analyst_selection"
        )
        payload = _payload()
        payload["evidence_ids"] = [selected_id]
        status, headers, created = _request(address, "POST", "/api/investigations/INV-QUERY/findings", payload)
        assert status == 201, created
        assert headers["Cache-Control"] == "no-store"
        assert created["revision"] == 2

        status, _, detail = _request(address, "GET", "/api/investigations/INV-QUERY/findings/FIND-WEB-001")
        assert status == 200
        assert detail["finding"]["title"] == "Web finding"
        bytes_after_detail = record.read_bytes()

        update = {"title": "Updated web finding", "expected_revision": 2}
        status, _, updated = _request(address, "PUT", "/api/investigations/INV-QUERY/findings/FIND-WEB-001", update)
        assert status == 200
        assert updated["revision"] == 3

        status, _, noop = _request(address, "PUT", "/api/investigations/INV-QUERY/findings/FIND-WEB-001", {"title": "Updated web finding", "expected_revision": 3})
        assert status == 200
        assert noop["revision"] == 3
        finding_bytes = record.read_bytes()
        status, _, loaded = _request(address, "POST", "/api/investigations/INV-QUERY/source-analysis/load", {})
        assert status == 200
        assert loaded["loaded"] is True
        assert record.read_bytes() == finding_bytes
        status, _, after_load = _request(address, "GET", "/api/investigations/INV-QUERY/findings/FIND-WEB-001")
        assert status == 200
        assert after_load["revision"] == 3
        assert after_load["finding"] == noop["finding"]
        assert record.read_bytes() != before_get
        assert bytes_after_detail == json.dumps(json.loads(bytes_after_detail), indent=2, sort_keys=True).encode() + b"\n"
    finally:
        _stop(server, thread)
    assert analysis == analysis_before
    assert {k: sha256(Path(v).read_bytes()).hexdigest() for k, v in analysis.artifacts.items()} == artifact_before


def test_findings_http_validation_and_bounded_errors(tmp_path):
    analysis, repository, server, thread, address = _start(tmp_path)
    selected_id = next(
        item.reference_id for item in build_query_investigation(analysis).evidence_references
        if item.origin == "analyst_selection"
    )
    try:
        for field, value in (("status", "confirmed"), ("confidence", "certain")):
            payload = _payload()
            payload["evidence_ids"] = [selected_id]
            payload[field] = value
            status, _, response = _request(address, "POST", "/api/investigations/INV-QUERY/findings", payload)
            assert status == 400
            assert "traceback" not in json.dumps(response).lower()
        payload = _payload()
        payload["evidence_ids"] = ["FOREIGN-SECRET-VALUE"]
        status, _, response = _request(address, "POST", "/api/investigations/INV-QUERY/findings", payload)
        assert status == 400
        assert response["error"]["message"] == "A finding relationship is invalid for this investigation."
        assert "FOREIGN-SECRET-VALUE" not in json.dumps(response)
        status, _, malformed = _request(address, "POST", "/api/investigations/INV-QUERY/findings", raw=b"{")
        assert status == 400
    finally:
        _stop(server, thread)


def test_findings_browser_contract_is_safe_and_uses_existing_inspection():
    root = Path(__file__).parents[1]
    source = (root / "soc_forge/web/static/investigation_findings.js").read_text()
    workspace = (root / "soc_forge/web/static/investigations.js").read_text()
    index = (root / "soc_forge/web/static/index.html").read_text()
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "Supersede Finding" in source
    assert "View Active" in source
    assert "View History" in source
    assert "/supersede" in source
    assert "textContent" in source
    assert "inspectEvidence(id, false)" in source
    assert "showWebHypothesis(id)" in source
    assert "showQueryDecision(id)" in source
    assert "affected_entity" not in source
    assert "Investigation Findings" in workspace
    assert "bindFindingActions()" in workspace
    assert "/static/investigation_findings.js" in index


def test_offline_web_supersession_lifecycle_and_historical_read_only(tmp_path):
    analysis, repository, server, thread, address = _start(tmp_path)
    try:
        first = _payload(1)
        selected_id = next(
            item.reference_id
            for item in repository.load_record("INV-QUERY").investigation.evidence_references
            if item.origin == "analyst_selection"
        )
        first["evidence_ids"] = [selected_id]
        status, _, created = _request(address, "POST", "/api/investigations/INV-QUERY/findings", payload=first)
        assert status == 201, created
        second = _payload(created["revision"])
        second["evidence_ids"] = [selected_id]
        second.update({"finding_id": "FIND-WEB-002", "title": "Replacement", "conclusion": "Later analyst conclusion."})
        status, _, replacement = _request(address, "POST", "/api/investigations/INV-QUERY/findings", payload=second)
        assert status == 201, created
        server.active_analysis_result = None
        status, headers, result = _request(
            address, "POST", "/api/investigations/INV-QUERY/findings/FIND-WEB-001/supersede",
            payload={"replacement_finding_id": "FIND-WEB-002", "reason": "Later review", "author": "alice", "expected_revision": replacement["revision"]},
        )
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert result["revision"] == replacement["revision"] + 1
        assert result["finding"]["lifecycle_state"] == "superseded"
        assert result["replacement"]["lifecycle_state"] == "active"
        status, _, listing = _request(address, "GET", "/api/investigations/INV-QUERY/findings")
        assert listing["counts"]["active"] == 1
        assert listing["counts"]["superseded"] == 1
        update = _payload(result["revision"])
        status, _, error = _request(address, "PUT", "/api/investigations/INV-QUERY/findings/FIND-WEB-001", payload=update)
        assert status == 409
        assert error["error"]["code"] in {"finding_historical_read_only", "finding_lifecycle_conflict"}
    finally:
        _stop(server, thread)
