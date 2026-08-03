import json
import threading
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path

import pytest

from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.evidence_service import InvestigationEvidenceService
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.web.app import make_server


@pytest.fixture
def evidence_server(tmp_path):
    times = iter(f"2026-08-07T12:{minute:02d}:00Z" for minute in range(60))
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    server = make_server(
        "127.0.0.1",
        0,
        out_dir,
        workspace_root=workspace_root,
        workspace_clock=lambda: next(times),
        bootstrap_clock=lambda: "2026-08-07T11:59:00Z",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    info = {
        "host": host,
        "port": port,
        "server": server,
        "out_dir": out_dir,
        "workspace_root": workspace_root,
    }
    try:
        yield info
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def request(
    info,
    method,
    path,
    payload=None,
    *,
    content_type="application/json",
    raw=None,
    include_headers=False,
):
    body = raw if raw is not None else (
        json.dumps(payload).encode("utf-8") if payload is not None else None
    )
    headers = {"Content-Type": content_type} if content_type is not None else {}
    connection = HTTPConnection(info["host"], info["port"], timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        kind = response.getheader("Content-Type") or ""
        parsed = (
            json.loads(data.decode("utf-8"))
            if data and kind.startswith("application/json")
            else data
        )
        if include_headers:
            return response.status, dict(response.getheaders()), parsed
        return response.status, parsed
    finally:
        connection.close()


def scenario(info, name="detection_lab"):
    status, payload = request(
        info, "POST", "/api/scenario", {"scenario": name}
    )
    assert status == 200
    return payload["workspace"]


def create(info, investigation_id="INV-EVIDENCE"):
    workspace = scenario(info)
    case_ids = [case["case_id"] for case in workspace["cases"]]
    status, payload = request(
        info,
        "POST",
        "/api/investigations",
        {"investigation_id": investigation_id, "case_ids": case_ids},
    )
    assert status == 201
    return payload, workspace


def candidates(info, evidence_type=None):
    suffix = f"?type={evidence_type}" if evidence_type else ""
    return request(
        info,
        "GET",
        f"/api/investigations/INV-EVIDENCE/evidence/candidates{suffix}",
    )


def select_payload(candidate_id, revision, classification="supporting", rationale="Useful"):
    return {
        "evidence_id": candidate_id,
        "classification": classification,
        "rationale": rationale,
        "author": "Web Analyst",
        "expected_revision": revision,
    }


def test_candidate_listing_filters_order_and_safe_contract(evidence_server):
    create(evidence_server)
    status, payload = candidates(evidence_server)
    assert status == 200
    assert payload["revision"] == 1
    items = payload["candidates"]
    assert items
    assert [(
        item["timestamp"] is None,
        item["timestamp"] or "",
        item["evidence_type"],
        item["evidence_id"],
    ) for item in items] == sorted((
        item["timestamp"] is None,
        item["timestamp"] or "",
        item["evidence_type"],
        item["evidence_id"],
    ) for item in items)
    allowed = {
        "evidence_id", "evidence_type", "title", "summary", "timestamp",
        "source_id", "case_ids", "rule_id", "tactic", "technique", "entities",
        "sensitive_fields", "relationship", "limitation_reason", "selectable",
        "source_analysis_id",
    }
    assert set(items[0]) == allowed
    encoded = json.dumps(items)
    assert "raw_message" not in encoded
    assert "powershell.exe -" not in encoded

    for evidence_type in ("event", "alert", "case", "reconstruction_step"):
        status, filtered = candidates(evidence_server, evidence_type)
        assert status == 200
        assert {item["evidence_type"] for item in filtered["candidates"]} <= {
            evidence_type
        }
    assert candidates(evidence_server, "event")[1]["candidates"] == []


def test_candidate_filter_and_analysis_availability_errors(evidence_server):
    create(evidence_server)
    status, payload = candidates(evidence_server, "unknown")
    assert (status, payload["error"]["code"]) == (400, "invalid_evidence_type")

    evidence_server["server"].active_analysis_result = None
    status, payload = candidates(evidence_server)
    assert (status, payload["error"]["code"]) == (409, "analysis_unavailable")

    scenario(evidence_server, "attack_chain")
    status, payload = candidates(evidence_server)
    assert (status, payload["error"]["code"]) == (
        409,
        "analysis_provenance_mismatch",
    )


def test_candidate_detail_hides_and_explicitly_reveals_sensitive_values(
    evidence_server,
):
    create(evidence_server)
    _, listing = candidates(evidence_server, "alert")
    item = next(
        candidate for candidate in listing["candidates"]
        if candidate["sensitive_fields"]
    )
    path = (
        "/api/investigations/INV-EVIDENCE/evidence/candidates/"
        + item["evidence_id"]
    )
    status, hidden_headers, hidden = request(
        evidence_server, "GET", path, include_headers=True)
    assert status == 200
    assert hidden_headers["Cache-Control"] == "no-store"
    sensitive = [
        field for field in hidden["details"]["fields"] if field["sensitive"]
    ]
    assert sensitive
    assert all(field["value"] is None and field["value_hidden"] for field in sensitive)
    assert hidden["sensitive_values_included"] is False
    assert hidden["source_resolvable"] is True

    status, response_headers, revealed = request(
        evidence_server, "GET", path + "?include_sensitive=true", include_headers=True
    )
    assert status == 200
    sensitive = [
        field for field in revealed["details"]["fields"] if field["sensitive"]
    ]
    assert response_headers["Cache-Control"] == "no-store"
    assert any(field["value"] for field in sensitive)
    assert all(not field["value_hidden"] for field in sensitive)
    assert revealed["sensitive_values_included"] is True

    status, payload = request(
        evidence_server, "GET", path + "?include_sensitive=yes"
    )
    assert (status, payload["error"]["code"]) == (400, "invalid_request")
    status, payload = request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/candidates/evidence-missing",
    )
    assert (status, payload["error"]["code"]) == (
        404,
        "evidence_candidate_not_found",
    )


@pytest.mark.parametrize("classification", ["supporting", "contradicting", "context"])
def test_select_each_classification_and_selection_counts(
    evidence_server, classification
):
    current, _ = create(evidence_server)
    _, listing = candidates(evidence_server, "alert")
    item = listing["candidates"][0]
    status, updated = request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        select_payload(item["evidence_id"], current["revision"], classification),
    )
    assert status == 201
    assert updated["revision"] == 2
    status, selected = request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
    )
    assert status == 200
    assert selected["counts"]["scope"] == len(current["investigation"]["evidence_references"])
    assert selected["counts"]["selected"] == 1
    assert selected["counts"][classification] == 1
    assert selected["scope_references"][0]["origin"] == "scope"
    assert selected["analyst_selections"][0]["origin"] == "analyst_selection"


def test_selection_validation_duplicate_and_revision_conflict(evidence_server):
    current, _ = create(evidence_server)
    _, listing = candidates(evidence_server, "alert")
    evidence_id = listing["candidates"][0]["evidence_id"]

    bad = select_payload(evidence_id, current["revision"], rationale="")
    status, payload = request(
        evidence_server, "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections", bad
    )
    assert (status, payload["error"]["code"]) == (400, "invalid_rationale")

    bad = select_payload(evidence_id, current["revision"], "certain")
    status, payload = request(
        evidence_server, "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections", bad
    )
    assert (status, payload["error"]["code"]) == (400, "invalid_classification")

    valid = select_payload(evidence_id, current["revision"])
    status, updated = request(
        evidence_server, "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections", valid
    )
    assert status == 201

    valid["expected_revision"] = updated["revision"]
    status, payload = request(
        evidence_server, "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections", valid
    )
    assert (status, payload["error"]["code"]) == (
        409,
        "duplicate_evidence_selection",
    )

    status, payload = request(
        evidence_server,
        "PUT",
        f"/api/investigations/INV-EVIDENCE/evidence/selections/{evidence_id}",
        {"rationale": "Stale draft", "expected_revision": 1},
    )
    assert (status, payload["error"]["code"]) == (409, "revision_conflict")
    assert payload["latest"]["revision"] == updated["revision"]


def test_update_remove_and_cross_interface_parity_preserve_artifacts(evidence_server):
    current, _ = create(evidence_server)
    artifact_paths = [
        path for path in evidence_server["out_dir"].iterdir() if path.is_file()
    ]
    before = {
        path.name: sha256(path.read_bytes()).hexdigest() for path in artifact_paths
    }
    _, listing = candidates(evidence_server, "alert")
    evidence_id = listing["candidates"][0]["evidence_id"]
    status, selected = request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        select_payload(evidence_id, current["revision"]),
    )
    assert status == 201

    service = InvestigationWorkspaceService(
        InvestigationRepository(evidence_server["workspace_root"]),
        clock=lambda: "2026-08-07T13:00:00Z",
    )
    service_state = service.get_investigation("INV-EVIDENCE")
    reference = next(
        item for item in service_state.investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    assert reference.reference_id == evidence_id
    assert reference.classification == "supporting"

    status, updated = request(
        evidence_server,
        "PUT",
        f"/api/investigations/INV-EVIDENCE/evidence/selections/{evidence_id}",
        {
            "classification": "context",
            "rationale": "Updated through web",
            "author": "Second Analyst",
            "expected_revision": selected["revision"],
        },
    )
    assert status == 200
    service_state = service.get_investigation("INV-EVIDENCE")
    reference = next(
        item for item in service_state.investigation.evidence_references
        if item.origin == "analyst_selection"
    )
    assert (reference.classification, reference.rationale, reference.selected_by) == (
        "context", "Updated through web", "Second Analyst"
    )
    assert service_state.revision == updated["revision"]

    status, removed = request(
        evidence_server,
        "DELETE",
        f"/api/investigations/INV-EVIDENCE/evidence/selections/{evidence_id}",
        {"expected_revision": updated["revision"]},
    )
    assert status == 200
    assert all(
        item["origin"] == "scope"
        for item in removed["investigation"]["evidence_references"]
    )
    assert {
        path.name: sha256(path.read_bytes()).hexdigest() for path in artifact_paths
    } == before


def test_service_selection_is_visible_and_updatable_through_web(evidence_server):
    current, _ = create(evidence_server)
    analysis = evidence_server["server"].active_analysis_result
    catalog = AnalysisEvidenceCatalog()
    candidate = catalog.list_candidates(
        analysis,
        case_ids=(
            current["investigation"]["evidence_references"][0]["source_id"],
        ),
        evidence_types=("case",),
    )[0]
    workspace = InvestigationWorkspaceService(
        InvestigationRepository(evidence_server["workspace_root"]),
        clock=lambda: "2026-08-07T13:01:00Z",
    )
    service = InvestigationEvidenceService(
        workspace, clock=lambda: "2026-08-07T13:00:00Z"
    )
    selected = service.select_evidence(
        "INV-EVIDENCE",
        candidate,
        classification="context",
        rationale="Selected outside web",
        author="Console Analyst",
        expected_revision=1,
    )
    status, payload = request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
    )
    assert status == 200
    reference = payload["analyst_selections"][0]
    assert reference["reference_id"] == candidate.evidence_id
    assert reference["classification"] == "context"
    assert reference["rationale"] == "Selected outside web"
    assert reference["selected_by"] == "Console Analyst"
    assert payload["revision"] == selected.revision


def test_referenced_remove_missing_selection_and_request_boundaries(evidence_server):
    current, _ = create(evidence_server)
    _, listing = candidates(evidence_server, "alert")
    evidence_id = listing["candidates"][0]["evidence_id"]
    _, selected = request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        select_payload(evidence_id, current["revision"]),
    )
    status, decision_state = request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/reasoning/decisions",
        {
            "decision_id": "DEC-1",
            "author": "Analyst",
            "decision_type": "escalation",
            "outcome": "escalate",
            "rationale": "Uses evidence",
            "evidence_reference_ids": [evidence_id],
            "hypothesis_ids": [],
            "expected_revision": selected["revision"],
        },
    )
    assert status == 201
    status, payload = request(
        evidence_server,
        "DELETE",
        f"/api/investigations/INV-EVIDENCE/evidence/selections/{evidence_id}",
        {"expected_revision": decision_state["revision"]},
    )
    assert (status, payload["error"]["code"]) == (
        409,
        "evidence_reference_conflict",
    )

    status, payload = request(
        evidence_server,
        "DELETE",
        "/api/investigations/INV-EVIDENCE/evidence/selections/evidence-missing",
        {"expected_revision": decision_state["revision"]},
    )
    assert (status, payload["error"]["code"]) == (
        404,
        "evidence_selection_not_found",
    )
    assert request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        select_payload(evidence_id, decision_state["revision"]),
        content_type="text/plain",
    )[0] == 415
    assert request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        raw=b"{bad-json",
    )[0] == 400
    assert request(
        evidence_server,
        "PATCH",
        f"/api/investigations/INV-EVIDENCE/evidence/selections/{evidence_id}",
        {},
    )[0] in {405, 501}
    assert request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/unknown",
    )[0] == 404


def test_error_responses_do_not_leak_paths_payloads_or_stacktraces(evidence_server):
    create(evidence_server)
    status, payload = request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/candidates/evidence-missing",
    )
    assert status == 404
    encoded = json.dumps(payload).lower()
    assert "traceback" not in encoded
    assert "/tmp/" not in encoded
    assert "powershell" not in encoded
    assert "sha256" not in encoded


def test_selected_metadata_remains_available_without_active_analysis(evidence_server):
    current, _ = create(evidence_server)
    _, listing = candidates(evidence_server, "alert")
    evidence_id = listing["candidates"][0]["evidence_id"]
    status, _ = request(
        evidence_server,
        "POST",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
        select_payload(evidence_id, current["revision"]),
    )
    assert status == 201
    evidence_server["server"].active_analysis_result = None

    status, payload = request(
        evidence_server,
        "GET",
        "/api/investigations/INV-EVIDENCE/evidence/selections",
    )
    assert status == 200
    assert payload["analyst_selections"][0]["reference_id"] == evidence_id
    assert candidates(evidence_server)[0] == 409


def test_evidence_ui_uses_safe_dom_and_explicit_sensitive_reveal():
    source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "investigations.js"
    ).read_text(encoding="utf-8")
    evidence_source = source.split("function evidenceElement", 1)[1]

    assert "Browse Evidence" in source
    assert "View Selected Evidence" in source
    for evidence_type in (
        "event", "alert", "case", "reconstruction_step",
    ):
        assert f'value="{evidence_type}"' in source
    assert ".textContent" in evidence_source
    assert ".replaceChildren()" in evidence_source
    assert ".innerHTML" not in evidence_source
    assert "window.confirm('Reveal bounded sensitive evidence values?')" in source
    assert "include_sensitive=true" in source
    assert "Hide Sensitive Values" in source
    assert "encodeURIComponent(evidenceId)" in source
    assert "localStorage" not in evidence_source


def test_evidence_ui_preserves_conflict_draft_and_separates_reference_origins():
    source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "investigations.js"
    ).read_text(encoding="utf-8")
    app_source = (
        Path(__file__).parents[1]
        / "soc_forge"
        / "web"
        / "static"
        / "app.js"
    ).read_text(encoding="utf-8")

    assert "state.evidenceDraft = { classification, rationale, author }" in source
    assert "state.evidenceDraft = null" in source
    assert "Investigation Scope References" in source
    assert "Analyst-Selected Evidence" in source
    assert "scope-evidence" in source
    assert "selected-evidence" in source
    assert "Source evidence details require the matching completed analysis" in source
    assert "evidenceDraft: null" in app_source
