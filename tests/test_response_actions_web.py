import json
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from soc_forge.investigations.response_action_service import InvestigationResponseActionService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from test_investigation_findings_web import _payload, _request, _start, _stop


def finding(address, repository, revision=1, finding_id="FIND-WEB-001"):
    evidence_id = next(x.reference_id for x in repository.load_record("INV-QUERY").investigation.evidence_references if x.origin == "analyst_selection")
    body = _payload(revision)
    body.update({"finding_id": finding_id, "evidence_ids": [evidence_id]})
    status, _, result = _request(address, "POST", "/api/investigations/INV-QUERY/findings", body)
    assert status == 201
    return result


def action(revision, finding_ids=("FIND-WEB-001",), action_id="ACT-WEB-001"):
    return {"action_id": action_id, "finding_ids": list(finding_ids),
            "title": "Reset credentials", "description": "Coordinate reset work.",
            "action_type": "credential_action", "priority": "high",
            "rationale": "Reduce access risk.", "owner": "identity",
            "created_by": "alice", "expected_revision": revision}


def hashes(analysis):
    return {k: sha256(Path(v).read_bytes()).hexdigest() for k, v in analysis.artifacts.items()}


def test_http_offline_create_read_transition_and_immutability(tmp_path):
    analysis, repository, server, thread, address = _start(tmp_path)
    analysis_before, artifacts_before = deepcopy(analysis), hashes(analysis)
    record = next(repository.investigations_root.glob("*.json"))
    try:
        made_finding = finding(address, repository)
        server.active_analysis_result = None
        before = record.read_bytes()
        status, headers, listing = _request(address, "GET", "/api/investigations/INV-QUERY/response-actions")
        assert (status, listing["actions"]) == (200, [])
        assert headers["Cache-Control"] == "no-store"
        assert listing["active_findings"][0]["finding_id"] == "FIND-WEB-001"
        assert record.read_bytes() == before

        status, headers, created = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions", action(made_finding["revision"]))
        assert status == 201
        assert headers["Cache-Control"] == "no-store"
        assert created["revision"] == made_finding["revision"] + 1
        before = record.read_bytes()

        status, headers, detail = _request(address, "GET", "/api/investigations/INV-QUERY/response-actions/ACT-WEB-001")
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert detail["action"]["transition_history"] == []
        assert detail["related_findings"][0]["finding_id"] == "FIND-WEB-001"
        assert record.read_bytes() == before

        status, _, moved = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions/ACT-WEB-001/transition",
            {"target_status": "approved", "author": "alice", "rationale": "Approved.", "expected_revision": created["revision"]})
        assert status == 200
        assert moved["revision"] == created["revision"] + 1
        assert moved["transition"]["from_status"] == "proposed"
        assert moved["transition"]["to_status"] == "approved"
    finally:
        _stop(server, thread)
    assert analysis == analysis_before
    assert hashes(analysis) == artifacts_before


def test_http_invalid_stale_relationship_errors_are_bounded_and_atomic(tmp_path):
    _, repository, server, thread, address = _start(tmp_path)
    try:
        made_finding = finding(address, repository)
        status, _, created = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions", action(made_finding["revision"]))
        assert status == 201
        record = next(repository.investigations_root.glob("*.json"))
        before = record.read_bytes()
        for body in (
            {"target_status": "completed", "author": "alice", "rationale": "Skip.", "expected_revision": created["revision"]},
            {"target_status": "approved", "author": "alice", "rationale": "Stale.", "expected_revision": 1},
        ):
            status, _, error = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions/ACT-WEB-001/transition", body)
            assert status == 409
            assert "traceback" not in json.dumps(error).lower()
            assert record.read_bytes() == before
        status, _, error = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions",
            action(created["revision"], ("FIND-SECRET-MISSING",), "ACT-BAD"))
        assert status == 400
        assert "FIND-SECRET-MISSING" not in json.dumps(error)
        status, _, error = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions",
            action(created["revision"], ("FIND-WEB-001", "FIND-WEB-001"), "ACT-DUP"))
        assert status == 400
        assert "traceback" not in json.dumps(error).lower()
    finally:
        _stop(server, thread)


def test_http_finding_supersession_keeps_original_link_and_allows_transition(tmp_path):
    _, repository, server, thread, address = _start(tmp_path)
    try:
        first = finding(address, repository)
        status, _, made = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions", action(first["revision"]))
        assert status == 201
        second = finding(address, repository, made["revision"], "FIND-WEB-002")
        status, _, superseded = _request(address, "POST", "/api/investigations/INV-QUERY/findings/FIND-WEB-001/supersede",
            {"replacement_finding_id": "FIND-WEB-002", "reason": "Refined.", "author": "alice", "expected_revision": second["revision"]})
        assert status == 200
        status, _, moved = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions/ACT-WEB-001/transition",
            {"target_status": "approved", "author": "alice", "rationale": "Continue.", "expected_revision": superseded["revision"]})
        assert status == 200
        assert moved["action"]["finding_ids"] == ["FIND-WEB-001"]
        status, _, _ = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions",
            action(moved["revision"], action_id="ACT-OLD"))
        assert status == 400
        status, _, new = _request(address, "POST", "/api/investigations/INV-QUERY/response-actions",
            action(moved["revision"], ("FIND-WEB-002",), "ACT-NEW"))
        assert status == 201
        assert new["action"]["finding_ids"] == ["FIND-WEB-002"]
    finally:
        _stop(server, thread)


def test_console_and_web_share_one_durable_action_state(tmp_path):
    _, repository, server, thread, address = _start(tmp_path)
    try:
        made_finding = finding(address, repository)
        console_service = InvestigationResponseActionService(
            InvestigationWorkspaceService(repository),
            id_factory=lambda: "ACT-CONSOLE-001",
            transition_id_factory=lambda: "TRANS-WEB-001",
        )
        console_created = console_service.create_action(
            "INV-QUERY", finding_ids=("FIND-WEB-001",), title="Console action",
            description="Created through the console service boundary.",
            action_type="validation", priority="medium", rationale="Validate state.",
            owner="soc", created_by="alice", expected_revision=made_finding["revision"],
        )
        status, _, listing = _request(
            address, "GET", "/api/investigations/INV-QUERY/response-actions"
        )
        assert status == 200
        assert listing["actions"][0]["action_id"] == "ACT-CONSOLE-001"
        status, _, moved = _request(
            address, "POST",
            "/api/investigations/INV-QUERY/response-actions/ACT-CONSOLE-001/transition",
            {"target_status": "approved", "author": "bob", "rationale": "Web approval.",
             "expected_revision": console_created.revision},
        )
        assert status == 200
        console_loaded = console_service.get_action("INV-QUERY", "ACT-CONSOLE-001")
        assert console_loaded.status == "approved"
        assert console_loaded.transition_history[-1].author == "bob"
        restarted = InvestigationResponseActionService(
            InvestigationWorkspaceService(type(repository)(repository.storage_root))
        )
        assert restarted.get_action("INV-QUERY", "ACT-CONSOLE-001") == console_loaded
    finally:
        _stop(server, thread)


def test_browser_contract_uses_safe_dom_and_workflow_language():
    root = Path(__file__).parents[1]
    source = (root / "soc_forge/web/static/investigation_response_actions.js").read_text()
    workspace = (root / "soc_forge/web/static/investigations.js").read_text()
    index = (root / "soc_forge/web/static/index.html").read_text()
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "textContent" in source
    assert "SOC-FORGE DOES NOT EXECUTE THIS ACTION" in source
    for label in ("Approve", "Start Work", "Complete", "Dismiss"):
        assert label in source
    assert "active_findings" in source
    assert "openFinding(finding.finding_id)" in source
    assert "responseActionCounts" in workspace
    assert "bindResponseActionActions()" in workspace
    assert "/static/investigation_response_actions.js" in index
