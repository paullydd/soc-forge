import json
import threading
from copy import deepcopy
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path
from typing import get_type_hints

import pytest

from soc_forge.investigations.handoff import (
    HandoffFile,
    HandoffResult,
    InvestigationHandoffService,
    validate_handoff_bundle,
)
from soc_forge.web.app import make_server


def _hash(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def _tree_hashes(root):
    return {
        path.relative_to(root).as_posix(): _hash(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _request(server, method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    connection = HTTPConnection(server["host"], server["port"], timeout=10)
    try:
        connection.request(
            method,
            path,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        data = response.read()
        return (
            response.status,
            dict(response.getheaders()),
            json.loads(data.decode("utf-8")) if data else None,
        )
    finally:
        connection.close()


@pytest.fixture
def handoff_server(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    server = make_server(
        "127.0.0.1",
        0,
        out_dir,
        workspace_root=workspace_root,
        workspace_clock=lambda: "2026-08-10T12:00:00Z",
        bootstrap_clock=lambda: "2026-08-10T12:00:00Z",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    info = {
        "host": host,
        "port": port,
        "server": server,
        "thread": thread,
        "out_dir": out_dir,
        "workspace_root": workspace_root,
    }
    try:
        yield info
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _create(server, investigation_id="INV-HANDOFF-WEB"):
    status, _, scenario = _request(
        server, "POST", "/api/scenario", {"scenario": "detection_lab"}
    )
    assert status == 200
    case_id = scenario["workspace"]["cases"][0]["case_id"]
    status, _, current = _request(
        server,
        "POST",
        "/api/investigations",
        {"investigation_id": investigation_id, "case_ids": [case_id]},
    )
    assert status == 201
    return current


def _export(server, current, overwrite=False, **overrides):
    payload = {
        "expected_revision": current["revision"],
        "output_root": "handoffs",
        "overwrite": overwrite,
        "sensitive_data_acknowledged": True,
    }
    payload.update(overrides)
    return _request(
        server,
        "POST",
        f"/api/investigations/{current['investigation']['investigation_id']}/handoff/export",
        payload,
    )


def test_handoff_preview_is_bounded_no_store_and_read_only(handoff_server):
    current = _create(handoff_server)
    repository_before = _tree_hashes(handoff_server["workspace_root"])
    artifacts_before = _tree_hashes(handoff_server["out_dir"])
    analysis_before = deepcopy(handoff_server["server"].active_analysis_result)

    status, headers, preview = _request(
        handoff_server,
        "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/preview",
    )

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert preview["investigation_id"] == "INV-HANDOFF-WEB"
    assert preview["revision"] == current["revision"]
    assert preview["selected_case_count"] == 1
    assert preview["required_artifacts_available"] is True
    assert "sensitive" in preview["sensitive_data_warning"].lower()
    assert "events" not in preview
    assert "/tmp/" not in json.dumps(preview)
    assert _tree_hashes(handoff_server["workspace_root"]) == repository_before
    assert _tree_hashes(handoff_server["out_dir"]) == artifacts_before
    assert handoff_server["server"].active_analysis_result == analysis_before


def test_preview_is_available_offline_without_active_analysis(handoff_server):
    _create(handoff_server)
    handoff_server["server"].active_analysis_result = None
    before = _tree_hashes(handoff_server["workspace_root"])
    status, headers, preview = _request(
        handoff_server,
        "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/preview",
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert preview["mode"] == "offline"
    assert preview["source_analysis_available"] is False
    assert preview["available_artifact_keys"] == []
    assert _tree_hashes(handoff_server["workspace_root"]) == before

    _request(handoff_server, "POST", "/api/scenario", {"scenario": "attack_chain"})
    status, _, error = _request(
        handoff_server,
        "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/preview",
    )
    assert status == 409
    assert error["error"]["code"] == "analysis_provenance_mismatch"


def test_offline_export_contains_durable_state_and_missing_analysis_context(handoff_server):
    current = _create(handoff_server)
    handoff_server["server"].active_analysis_result = None
    before = _tree_hashes(handoff_server["workspace_root"])

    status, headers, result = _export(handoff_server, current)

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    bundle = handoff_server["out_dir"] / result["bundle_location"]
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    timeline = json.loads((bundle / "timeline.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "1.3"
    assert manifest["mode"] == "offline"
    assert manifest["source_analysis_available"] is False
    assert timeline["timed_entries"] == timeline["untimed_entries"] == []
    assert not (bundle / "source_artifacts").exists()
    assert validate_handoff_bundle(bundle)
    assert _tree_hashes(handoff_server["workspace_root"]) == before


@pytest.mark.parametrize(
    "payload,code,status",
    [
        ({"output_root": "handoffs", "overwrite": False, "sensitive_data_acknowledged": True}, "invalid_request", 400),
        ({"expected_revision": 1, "output_root": "../../", "overwrite": False, "sensitive_data_acknowledged": True}, "invalid_handoff_request", 400),
        ({"expected_revision": 1, "output_root": "/etc", "overwrite": False, "sensitive_data_acknowledged": True}, "invalid_handoff_request", 400),
        ({"expected_revision": 1, "output_root": "handoffs", "overwrite": False, "sensitive_data_acknowledged": False}, "invalid_handoff_request", 400),
    ],
)
def test_export_rejects_missing_or_unsafe_controlled_inputs(
    handoff_server, payload, code, status
):
    _create(handoff_server)
    actual, headers, error = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/export",
        payload,
    )
    assert actual == status
    assert headers["Cache-Control"] == "no-store"
    assert error["error"]["code"] == code


def test_export_bounded_manifest_and_explicit_overwrite(handoff_server):
    current = _create(handoff_server)
    repository_before = _tree_hashes(handoff_server["workspace_root"])
    source_before = _tree_hashes(handoff_server["out_dir"])

    status, headers, result = _export(handoff_server, current)
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert set(result) == {
        "handoff_id",
        "investigation_id",
        "revision",
        "bundle_location",
        "manifest_location",
        "file_count",
        "validation_status",
        "warnings",
    }
    assert result["bundle_location"] == "handoffs/INV-HANDOFF-WEB"
    assert not Path(result["bundle_location"]).is_absolute()
    assert "/tmp/" not in json.dumps(result)

    status, _, error = _export(handoff_server, current)
    assert status == 409
    assert error["error"]["code"] == "handoff_target_conflict"

    status, _, replacement = _export(handoff_server, current, overwrite=True)
    assert status == 200
    assert replacement["handoff_id"] == result["handoff_id"]
    assert _tree_hashes(handoff_server["workspace_root"]) == repository_before
    after = _tree_hashes(handoff_server["out_dir"])
    for name, digest in source_before.items():
        assert after[name] == digest

    status, headers, manifest = _request(
        handoff_server,
        "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/manifest",
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert manifest["handoff_id"] == result["handoff_id"]
    assert manifest["selected_case_ids"]
    assert manifest["files"]
    assert all(not Path(item["filename"]).is_absolute() for item in manifest["files"])
    assert str(handoff_server["out_dir"]) not in json.dumps(manifest)


def test_stale_revision_is_bounded_and_does_not_export(handoff_server):
    current = _create(handoff_server)
    status, _, updated = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/owner",
        {"owner": "Analyst", "expected_revision": current["revision"]},
    )
    assert status == 200
    status, headers, error = _export(
        handoff_server, current, expected_revision=current["revision"]
    )
    assert status == 409
    assert headers["Cache-Control"] == "no-store"
    assert error == {
        "error": {
            "code": "revision_conflict",
            "message": "The investigation changed in another session.",
            "investigation_id": "INV-HANDOFF-WEB",
        },
        "latest": {"revision": updated["revision"]},
    }
    assert not (handoff_server["out_dir"] / "handoffs").exists()


def test_missing_required_artifact_is_controlled(handoff_server):
    current = _create(handoff_server)
    Path(handoff_server["server"].active_analysis_result.artifacts["cases"]).unlink()
    status, _, error = _export(handoff_server, current)
    assert status == 409
    assert error["error"]["code"] == "required_artifact_missing"
    assert not (handoff_server["out_dir"] / "handoffs" / "INV-HANDOFF-WEB").exists()


def test_validation_detects_tamper_missing_schema_and_reference_failures(
    handoff_server,
):
    current = _create(handoff_server)
    assert _export(handoff_server, current)[0] == 200
    bundle = handoff_server["out_dir"] / "handoffs" / "INV-HANDOFF-WEB"
    original = _tree_hashes(bundle)

    status, headers, valid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert valid["valid"] is True

    alerts = bundle / "source_artifacts" / "alerts.json"
    alerts.write_text("tampered", encoding="utf-8")
    tampered_before = alerts.read_bytes()
    status, _, invalid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )
    assert status == 200
    assert invalid["valid"] is False
    assert invalid["failure_reason"] == "digest_mismatch"
    assert alerts.read_bytes() == tampered_before

    assert _export(handoff_server, current, overwrite=True)[0] == 200
    assert _tree_hashes(bundle) == original

    (bundle / "timeline.json").unlink()
    status, _, invalid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )
    assert status == 200
    assert invalid["failure_reason"] == "missing_file"

    assert _export(handoff_server, current, overwrite=True)[0] == 200
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "99.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    status, _, invalid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )
    assert status == 200
    assert invalid["failure_reason"] == "unsupported_schema"


def test_reference_integrity_failure_is_bounded(handoff_server):
    current = _create(handoff_server)
    assert _export(handoff_server, current)[0] == 200
    bundle = handoff_server["out_dir"] / "handoffs" / "INV-HANDOFF-WEB"
    component = bundle / "investigation.json"
    payload = json.loads(component.read_text(encoding="utf-8"))
    payload["investigation_id"] = "DIFFERENT"
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    component.write_bytes(data)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    item = next(entry for entry in manifest["files"] if entry["filename"] == "investigation.json")
    item["size"] = len(data)
    item["sha256"] = sha256(data).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    status, _, invalid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )

    assert status == 200
    assert invalid["valid"] is False
    assert invalid["failure_reason"] == "reference_integrity_failure"
    assert "DIFFERENT" not in json.dumps(invalid)


def test_offline_validation_survives_server_restart(handoff_server):
    current = _create(handoff_server)
    assert _export(handoff_server, current)[0] == 200
    handoff_server["server"].active_analysis_result = None
    status, _, valid = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {},
    )
    assert status == 200
    assert valid["valid"] is True


def test_web_and_direct_service_exports_are_semantically_identical(handoff_server, tmp_path):
    current = _create(handoff_server)
    status, _, web_result = _export(handoff_server, current)
    assert status == 200
    analysis = handoff_server["server"].active_analysis_result
    direct = InvestigationHandoffService(
        handoff_server["server"].investigation_app.workspace_service.repository
    ).export("INV-HANDOFF-WEB", analysis, tmp_path / "direct")

    web_bundle = handoff_server["out_dir"] / "handoffs" / "INV-HANDOFF-WEB"
    assert direct.handoff_id == web_result["handoff_id"]
    assert _tree_hashes(direct.output_path) == _tree_hashes(web_bundle)
    assert validate_handoff_bundle(direct.output_path)
    assert validate_handoff_bundle(web_bundle)
    assert direct.revision == current["revision"]


def test_handoff_ui_contract_uses_safe_browser_primitives():
    source = Path("soc_forge/web/static/investigations.js").read_text(encoding="utf-8")
    assert "Investigation Handoff" in source
    assert "Preview Handoff" in source
    assert "Export Handoff" in source
    assert "sensitive-data warning" in source
    assert "handoffOverwrite" in source
    assert "Inspect Manifest" in source
    assert "Validate Bundle" in source
    assert "renderHandoffPreview" in source
    assert "[OFFLINE] Source analysis unavailable" in source
    assert "Findings are analyst-authored conclusions" in source
    assert "replaceChildren" in source
    assert "textContent" in source
    assert "localStorage" not in source
    assert "type=\"text\"" not in source[source.index("Investigation Handoff"):source.index("reasoning-section")]
    assert "innerHTML" not in source[source.index("function renderHandoffPayload"):source.index("function evidenceElement")]


def test_public_handoff_result_annotations_resolve():
    assert get_type_hints(HandoffFile)["filename"] is str
    assert get_type_hints(HandoffResult)["handoff_id"] is str
    assert get_type_hints(HandoffResult)["validation_status"] is str


def test_offline_validation_after_real_server_restart(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"

    def start():
        server = make_server(
            "127.0.0.1",
            0,
            out_dir,
            workspace_root=workspace_root,
            workspace_clock=lambda: "2026-08-10T12:00:00Z",
            bootstrap_clock=lambda: "2026-08-10T12:00:00Z",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        return server, thread, {"host": host, "port": port}

    first, first_thread, first_info = start()
    try:
        current = _create(first_info, investigation_id="INV-RESTART")
        assert _export(first_info, current)[0] == 200
    finally:
        first.shutdown()
        first_thread.join(timeout=5)
        first.server_close()

    second, second_thread, second_info = start()
    try:
        assert second.active_analysis_result is None
        status, headers, result = _request(
            second_info,
            "POST",
            "/api/investigations/INV-RESTART/handoff/validate",
            {},
        )
        assert status == 200
        assert headers["Cache-Control"] == "no-store"
        assert result["valid"] is True
    finally:
        second.shutdown()
        second_thread.join(timeout=5)
        second.server_close()



def test_validation_rejects_client_paths_or_bundle_identifiers(handoff_server):
    current = _create(handoff_server)
    assert _export(handoff_server, current)[0] == 200
    status, headers, error = _request(
        handoff_server,
        "POST",
        "/api/investigations/INV-HANDOFF-WEB/handoff/validate",
        {"path": "/etc", "bundle": "../../other"},
    )
    assert status == 400
    assert headers["Cache-Control"] == "no-store"
    assert error["error"]["code"] == "invalid_handoff_request"


def _add_web_finding(server, current):
    status, _, candidates = _request(
        server, "GET", "/api/investigations/INV-HANDOFF-WEB/evidence/candidates"
    )
    assert status == 200
    evidence_id = candidates["candidates"][0]["evidence_id"]
    status, _, selected = _request(
        server, "POST", "/api/investigations/INV-HANDOFF-WEB/evidence/selections",
        {"evidence_id": evidence_id, "classification": "supporting",
         "rationale": "Supports the analyst finding", "author": "alice",
         "expected_revision": current["revision"]},
    )
    assert status == 201
    status, _, updated = _request(
        server, "POST", "/api/investigations/INV-HANDOFF-WEB/findings",
        {"finding_id": "FIND-WEB-HANDOFF", "title": "Analyst finding",
         "conclusion": "Analyst review supports suspicious activity.",
         "status": "draft", "confidence": "medium", "author": "alice",
         "evidence_ids": [evidence_id], "hypothesis_ids": [], "decision_ids": [],
         "attack_tactics": [], "attack_techniques": [],
         "limitations": ["Visibility is limited."],
         "expected_revision": selected["revision"]},
    )
    assert status == 201
    return updated


def test_web_handoff_preview_and_manifest_include_analyst_findings(handoff_server):
    current = _create(handoff_server)
    current = _add_web_finding(handoff_server, current)
    status, headers, preview = _request(
        handoff_server, "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/preview",
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert preview["finding_count"] == 1
    assert preview["findings"][0]["attribution"] == "analyst"
    assert preview["findings"][0]["status"] == "draft"
    assert _export(handoff_server, current)[0] == 200
    status, _, manifest = _request(
        handoff_server, "GET",
        "/api/investigations/INV-HANDOFF-WEB/handoff/manifest",
    )
    assert status == 200
    finding_file = next(item for item in manifest["files"] if item["filename"] == "findings.json")
    assert finding_file["logical_type"] == "component:findings"
