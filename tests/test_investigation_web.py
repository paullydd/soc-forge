import json
import threading
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path

import pytest

from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.web.app import make_server


FIXED_TIMES = [
    f"2026-08-04T12:{minute:02d}:00Z" for minute in range(60)
]


@pytest.fixture
def investigation_server(tmp_path):
    times = iter(FIXED_TIMES)
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "shared-workspace"
    server = make_server(
        "127.0.0.1",
        0,
        out_dir,
        workspace_root=workspace_root,
        workspace_clock=lambda: next(times),
        bootstrap_clock=lambda: "2026-08-04T11:59:00Z",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    info = {
        "host": host,
        "port": port,
        "out_dir": out_dir,
        "workspace_root": workspace_root,
        "server": server,
    }
    try:
        yield info
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def request(server_info, method, path, payload=None, raw_body=None, headers=None):
    if raw_body is not None:
        body = raw_body
    elif payload is not None:
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    request_headers = headers if headers is not None else {}
    connection = HTTPConnection(server_info["host"], server_info["port"], timeout=10)
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        data = response.read()
        content_type = response.getheader("Content-Type") or ""
        parsed = (
            json.loads(data.decode("utf-8"))
            if data and content_type.startswith("application/json")
            else data
        )
        return response.status, parsed
    finally:
        connection.close()


def json_request(server_info, method, path, payload=None, raw_body=None):
    return request(
        server_info,
        method,
        path,
        payload=payload,
        raw_body=raw_body,
        headers={"Content-Type": "application/json"},
    )


def run_scenario(server_info):
    status, payload = json_request(
        server_info,
        "POST",
        "/api/scenario",
        {"scenario": "detection_lab"},
    )
    assert status == 200
    return payload["workspace"]


def create_investigation(
    server_info,
    *,
    investigation_id="INV-WEB-001",
    case_id=None,
    title=None,
    owner=None,
):
    workspace = run_scenario(server_info)
    selected_case_id = case_id or workspace["cases"][0]["case_id"]
    payload = {
        "investigation_id": investigation_id,
        "case_ids": [selected_case_id],
    }
    if title is not None:
        payload["title"] = title
    if owner is not None:
        payload["owner"] = owner
    status, result = json_request(
        server_info, "POST", "/api/investigations", payload
    )
    assert status == 201
    return result, workspace


def test_list_empty_and_create_generated_title(investigation_server):
    status, summaries = json_request(
        investigation_server, "GET", "/api/investigations"
    )
    assert status == 200
    assert summaries == []

    created, analysis_workspace = create_investigation(investigation_server)
    selected = analysis_workspace["cases"][0]
    assert created["revision"] == 1
    assert created["investigation"]["investigation_id"] == "INV-WEB-001"
    assert created["investigation"]["metadata"]["title"] == selected["title"]
    assert created["investigation"]["metadata"]["owner"] is None
    assert created["investigation"]["evidence_references"][0]["source_id"] == selected["case_id"]
    assert "events" not in created["investigation"]
    assert "alerts" not in created["investigation"]


def test_create_custom_title_owner_get_and_durable_list(investigation_server):
    created, _ = create_investigation(
        investigation_server,
        investigation_id="INV-WEB-002",
        title="Priority endpoint review",
        owner="Analyst A",
    )
    assert created["investigation"]["metadata"]["title"] == "Priority endpoint review"
    assert created["investigation"]["metadata"]["owner"] == "Analyst A"

    status, retrieved = json_request(
        investigation_server, "GET", "/api/investigations/INV-WEB-002"
    )
    assert status == 200
    assert retrieved == created

    status, summaries = json_request(
        investigation_server, "GET", "/api/investigations"
    )
    assert status == 200
    assert summaries == [
        {
            "investigation_id": "INV-WEB-002",
            "title": "Priority endpoint review",
            "owner": "Analyst A",
            "status": "open",
            "created_at": "2026-08-04T11:59:00Z",
            "updated_at": "2026-08-04T11:59:00Z",
            "revision": 1,
        }
    ]


def test_creation_validation_and_duplicate_errors(investigation_server):
    status, payload = json_request(
        investigation_server,
        "POST",
        "/api/investigations",
        {"investigation_id": "INV-NO-ANALYSIS", "case_ids": ["CASE-X"]},
    )
    assert status == 409
    assert payload["error"]["code"] == "no_active_analysis"

    workspace = run_scenario(investigation_server)
    status, payload = json_request(
        investigation_server,
        "POST",
        "/api/investigations",
        {"investigation_id": "INV-BAD-CASE", "case_ids": ["CASE-UNKNOWN"]},
    )
    assert status == 400
    assert payload["error"]["code"] == "invalid_request"
    assert "CASE-UNKNOWN" in payload["error"]["message"]

    case_id = workspace["cases"][0]["case_id"]
    create_payload = {"investigation_id": "INV-DUP", "case_ids": [case_id]}
    assert json_request(
        investigation_server, "POST", "/api/investigations", create_payload
    )[0] == 201
    status, payload = json_request(
        investigation_server, "POST", "/api/investigations", create_payload
    )
    assert status == 409
    assert payload["error"]["code"] == "investigation_exists"


def test_missing_workspace_and_request_format_errors(investigation_server):
    status, payload = json_request(
        investigation_server, "GET", "/api/investigations/INV-MISSING"
    )
    assert status == 404
    assert payload["error"]["code"] == "investigation_not_found"
    assert "/tmp/" not in json.dumps(payload)

    status, payload = request(
        investigation_server,
        "POST",
        "/api/investigations",
        payload={"investigation_id": "INV-1", "case_ids": ["CASE-1"]},
        headers={"Content-Type": "text/plain"},
    )
    assert status == 415
    assert payload["error"]["code"] == "unsupported_media_type"

    status, payload = json_request(
        investigation_server,
        "POST",
        "/api/investigations",
        raw_body=b"{invalid-json",
    )
    assert status == 400
    assert payload["error"] == {
        "code": "invalid_json",
        "message": "Invalid JSON request body.",
    }


def test_owner_status_close_and_explicit_reopen(investigation_server):
    current, _ = create_investigation(investigation_server)

    status, current = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/owner",
        {"owner": "Analyst B", "expected_revision": current["revision"]},
    )
    assert status == 200
    assert current["revision"] == 2
    assert current["investigation"]["metadata"]["owner"] == "Analyst B"

    status, current = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/owner",
        {"owner": None, "expected_revision": current["revision"]},
    )
    assert status == 200
    assert current["investigation"]["metadata"]["owner"] is None

    for expected_status in ("in_progress", "closed"):
        status, current = json_request(
            investigation_server,
            "POST",
            "/api/investigations/INV-WEB-001/status",
            {
                "status": expected_status,
                "expected_revision": current["revision"],
            },
        )
        assert status == 200
        assert current["investigation"]["metadata"]["status"] == expected_status

    status, error = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/status",
        {"status": "in_progress", "expected_revision": current["revision"]},
    )
    assert status == 409
    assert error["error"]["code"] == "invalid_status_transition"

    status, current = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/reopen",
        {"expected_revision": current["revision"]},
    )
    assert status == 200
    assert current["investigation"]["metadata"]["status"] == "in_progress"


def test_annotation_lifecycle_and_duplicate_id(investigation_server):
    current, _ = create_investigation(investigation_server)
    create_payload = {
        "annotation_id": "NOTE-1",
        "author": "Analyst <A>",
        "text": "<script>alert('x')</script>",
        "expected_revision": current["revision"],
    }
    status, current = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/annotations",
        create_payload,
    )
    assert status == 200
    annotation = current["investigation"]["annotations"][0]
    assert annotation["body"] == "<script>alert('x')</script>"
    assert annotation["created_by"] == "Analyst <A>"

    duplicate_payload = dict(create_payload, expected_revision=current["revision"])
    status, error = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/annotations",
        duplicate_payload,
    )
    assert status == 400
    assert error["error"]["code"] == "invalid_request"

    created_at = annotation["created_at"]
    status, current = json_request(
        investigation_server,
        "PUT",
        "/api/investigations/INV-WEB-001/annotations/NOTE-1",
        {"text": "Updated text", "expected_revision": current["revision"]},
    )
    assert status == 200
    assert current["investigation"]["annotations"][0]["body"] == "Updated text"
    assert current["investigation"]["annotations"][0]["created_at"] == created_at

    status, current = json_request(
        investigation_server,
        "DELETE",
        "/api/investigations/INV-WEB-001/annotations/NOTE-1",
        {"expected_revision": current["revision"]},
    )
    assert status == 200
    assert current["investigation"]["annotations"] == []


def test_append_only_decisions_and_duplicate_id(investigation_server):
    current, _ = create_investigation(investigation_server)
    decision = {
        "decision_id": "DEC-1",
        "author": "Analyst A",
        "decision_type": "disposition",
        "outcome": "escalate",
        "rationale": "Review <credential> activity",
        "evidence_reference_ids": [
            current["investigation"]["evidence_references"][0]["reference_id"]
        ],
        "hypothesis_ids": [],
        "expected_revision": current["revision"],
    }
    status, current = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/decisions",
        decision,
    )
    assert status == 200
    assert current["investigation"]["decisions"][0]["decision_id"] == "DEC-1"
    assert current["investigation"]["decisions"][0]["rationale"] == "Review <credential> activity"

    decision["expected_revision"] = current["revision"]
    status, error = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/decisions",
        decision,
    )
    assert status == 400
    assert error["error"]["code"] == "invalid_request"
    assert request(
        investigation_server,
        "PUT",
        "/api/investigations/INV-WEB-001/decisions/DEC-1",
        payload={"expected_revision": current["revision"]},
        headers={"Content-Type": "application/json"},
    )[0] == 405


def test_revision_conflict_returns_latest_without_overwrite(investigation_server):
    current, _ = create_investigation(investigation_server)
    status, updated = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/owner",
        {"owner": "First writer", "expected_revision": 1},
    )
    assert status == 200
    assert updated["revision"] == 2

    status, conflict = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/owner",
        {"owner": "Stale writer", "expected_revision": current["revision"]},
    )
    assert status == 409
    assert conflict["error"]["code"] == "revision_conflict"
    assert conflict["latest"] == updated
    assert conflict["latest"]["investigation"]["metadata"]["owner"] == "First writer"


def test_delete_preserves_analysis_artifacts(investigation_server):
    current, _ = create_investigation(investigation_server)
    artifact_paths = [
        path
        for path in investigation_server["out_dir"].iterdir()
        if path.is_file()
    ]
    before = {path.name: sha256(path.read_bytes()).hexdigest() for path in artifact_paths}
    status, deleted = json_request(
        investigation_server,
        "DELETE",
        "/api/investigations/INV-WEB-001",
        {"expected_revision": current["revision"]},
    )
    assert status == 200
    assert deleted == {
        "investigation_id": "INV-WEB-001",
        "deleted_revision": 1,
    }
    assert {
        path.name: sha256(path.read_bytes()).hexdigest() for path in artifact_paths
    } == before
    assert json_request(
        investigation_server, "GET", "/api/investigations/INV-WEB-001"
    )[0] == 404


def test_missing_revision_unsupported_method_and_unknown_route(investigation_server):
    create_investigation(investigation_server)
    status, payload = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-WEB-001/owner",
        {"owner": "Analyst A"},
    )
    assert status == 400
    assert payload["error"]["message"] == "expected_revision must be a positive integer"
    assert request(
        investigation_server,
        "PUT",
        "/api/investigations",
        payload={},
        headers={"Content-Type": "application/json"},
    )[0] == 405
    assert json_request(
        investigation_server, "GET", "/api/investigations/INV-WEB-001/unknown"
    )[0] == 404
    assert json_request(
        investigation_server, "GET", "/api/not-an-investigation-route"
    )[0] == 404


def test_web_and_service_share_repository_state(investigation_server):
    external_service = InvestigationWorkspaceService(
        InvestigationRepository(investigation_server["workspace_root"]),
        clock=lambda: "2026-08-04T13:00:00Z",
    )
    created = external_service.create_investigation(
        investigation_id="INV-SHARED",
        title="Shared state",
        analysis_id="analysis-shared",
        case_ids=["CASE-SHARED"],
        artifact_keys=["cases"],
        owner="Console Analyst",
        created_at="2026-08-04T10:00:00Z",
    )
    status, web_state = json_request(
        investigation_server, "GET", "/api/investigations/INV-SHARED"
    )
    assert status == 200
    assert web_state["revision"] == created.revision

    status, web_state = json_request(
        investigation_server,
        "POST",
        "/api/investigations/INV-SHARED/owner",
        {"owner": "Web Analyst", "expected_revision": web_state["revision"]},
    )
    assert status == 200
    service_state = external_service.get_investigation("INV-SHARED")
    assert service_state.revision == web_state["revision"]
    assert service_state.investigation.to_dict() == web_state["investigation"]


def test_workspace_root_has_one_investigations_directory(investigation_server):
    create_investigation(investigation_server)
    expected = (
        investigation_server["workspace_root"]
        / "investigations"
        / "INV-WEB-001.json"
    )
    assert expected.is_file()
    assert not (
        investigation_server["workspace_root"]
        / "investigations"
        / "investigations"
    ).exists()


def test_static_ui_escapes_investigation_owned_strings():
    source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "investigations.js"
    ).read_text(encoding="utf-8")
    assert "escapeHtml" in source
    for field in (
        "metadata.title",
        "metadata.owner",
        "annotation.body",
        "annotation.created_by",
        "decision.rationale",
        "decision.decided_by",
    ):
        assert f"escapeHtml({field}" in source

def test_corrupt_integrity_record_returns_generic_error_without_path_or_traceback(
    investigation_server,
):
    create_investigation(investigation_server)
    path = (
        investigation_server["workspace_root"]
        / "investigations"
        / "INV-WEB-001.json"
    )
    envelope = json.loads(path.read_text(encoding="utf-8"))
    evidence = envelope["investigation"]["evidence_references"][0]
    envelope["investigation"]["evidence_references"].append(dict(evidence))
    path.write_text(json.dumps(envelope), encoding="utf-8")

    status, payload = json_request(
        investigation_server,
        "GET",
        "/api/investigations/INV-WEB-001",
    )

    assert status == 500
    assert payload["error"]["code"] == "workspace_unavailable"
    assert payload["error"]["message"] == "The investigation workspace could not be loaded."
    encoded = json.dumps(payload).lower()
    assert "traceback" not in encoded
    assert str(path).lower() not in encoded
    assert "duplicate" not in encoded
