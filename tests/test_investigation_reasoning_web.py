import json
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from soc_forge.investigations.models import EvidenceReference
from soc_forge.investigations.reasoning_service import InvestigationReasoningService
from soc_forge.web.app import make_server


class Clock:
    def __init__(self):
        self.minute = 0

    def __call__(self):
        value = f"2026-08-12T12:{self.minute:02d}:00Z"
        self.minute += 1
        return value


def selected(reference_id, classification):
    return EvidenceReference(
        reference_id=reference_id,
        source_type="alert",
        source_id=reference_id.replace("EVIDENCE", "ALERT"),
        origin="analyst_selection",
        classification=classification,
        rationale=f"{classification} evidence",
        selected_by="Web Analyst",
        selected_at="2026-08-12T11:00:00Z",
        selection_updated_at="2026-08-12T11:00:00Z",
        source_analysis_id="ANALYSIS-WEB",
        evidence_type="alert",
        scope_case_ids=("CASE-001",),
    )


@pytest.fixture
def reasoning_server(tmp_path):
    clock = Clock()
    server = make_server(
        "127.0.0.1",
        0,
        tmp_path / "analysis",
        workspace_root=tmp_path / "workspace",
        workspace_clock=clock,
    )
    workspace = server.investigation_app.workspace_service
    created = workspace.create_investigation(
        investigation_id="INV-REASONING",
        title="Reasoning HTTP workspace",
        analysis_id="ANALYSIS-WEB",
        case_ids=("CASE-001",),
        artifact_keys=("alerts", "cases"),
    )
    prepared = workspace.replace_evidence_references(
        "INV-REASONING",
        created.investigation.evidence_references
        + (
            selected("EVIDENCE-SUPPORT", "supporting"),
            selected("EVIDENCE-CONTRADICT", "contradicting"),
            selected("EVIDENCE-CONTEXT", "context"),
        ),
        expected_revision=created.revision,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    info = {
        "host": host,
        "port": port,
        "server": server,
        "workspace": workspace,
        "current": prepared,
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
    body = raw
    if raw is None and payload is not None:
        body = json.dumps(payload).encode("utf-8")
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


def create_payload(revision, **overrides):
    payload = {
        "hypothesis_id": "HYP-001",
        "statement": "PowerShell activity may have impaired endpoint defenses",
        "author": "Web Analyst",
        "supporting_evidence_ids": [],
        "contradicting_evidence_ids": [],
        "expected_revision": revision,
    }
    payload.update(overrides)
    return payload


def create_hypothesis(info, **overrides):
    status, payload = request(
        info,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses",
        create_payload(info["current"].revision, **overrides),
    )
    assert status == 201
    info["current"] = info["workspace"].get_investigation("INV-REASONING")
    return payload


def test_empty_summary_and_no_store(reasoning_server):
    status, headers, payload = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/reasoning",
        include_headers=True,
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["total_hypotheses"] == 0
    assert payload["open"] == 0
    assert payload["supported"] == 0
    assert payload["rejected"] == 0
    assert payload["inconclusive"] == 0
    assert payload["total_decisions"] == 0
    assert payload["revision"] == reasoning_server["current"].revision


@pytest.mark.parametrize(
    ("supporting", "contradicting"),
    [
        ([], []),
        (["EVIDENCE-SUPPORT"], []),
        ([], ["EVIDENCE-CONTRADICT"]),
        (["EVIDENCE-SUPPORT"], ["EVIDENCE-CONTRADICT"]),
    ],
)
def test_create_list_and_detail_with_compatible_evidence(
    reasoning_server, supporting, contradicting
):
    created = create_hypothesis(
        reasoning_server,
        supporting_evidence_ids=supporting,
        contradicting_evidence_ids=contradicting,
    )
    assert created["hypothesis"]["state"] == "open"
    assert created["hypothesis"]["supporting_evidence_reference_ids"] == supporting
    assert created["hypothesis"]["contradicting_evidence_reference_ids"] == contradicting

    status, listing = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/hypotheses",
    )
    assert status == 200
    assert listing["hypotheses"][0]["hypothesis_id"] == "HYP-001"
    assert listing["hypotheses"][0]["supporting_evidence_count"] == len(supporting)

    status, headers, detail = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001",
        include_headers=True,
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert [item["reference_id"] for item in detail["supporting_evidence"]] == supporting
    assert detail["source_details_available"] is False
    assert "command_line" not in json.dumps(detail)


def test_create_validation_duplicate_and_missing_detail(reasoning_server):
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses",
        create_payload(reasoning_server["current"].revision, statement=" "),
    )
    assert (status, payload["error"]["code"]) == (
        400,
        "invalid_hypothesis_statement",
    )

    create_hypothesis(reasoning_server)
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses",
        create_payload(reasoning_server["current"].revision),
    )
    assert (status, payload["error"]["code"]) == (409, "duplicate_hypothesis")

    status, payload = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/hypotheses/HYP-MISSING",
    )
    assert (status, payload["error"]["code"]) == (404, "hypothesis_not_found")


@pytest.mark.parametrize(
    ("supporting", "contradicting", "code"),
    [
        (["EVIDENCE-CONTEXT"], [], "hypothesis_evidence_conflict"),
        (["EVIDENCE-CONTRADICT"], [], "hypothesis_evidence_conflict"),
        (["CASE-001"], [], "evidence_selection_not_found"),
        (["EVIDENCE-SUPPORT"], ["EVIDENCE-SUPPORT"], "hypothesis_evidence_conflict"),
    ],
)
def test_create_rejects_invalid_evidence_relationships(
    reasoning_server, supporting, contradicting, code
):
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses",
        create_payload(
            reasoning_server["current"].revision,
            supporting_evidence_ids=supporting,
            contradicting_evidence_ids=contradicting,
        ),
    )
    assert status in {404, 409}
    assert payload["error"]["code"] == code


def test_edit_add_and_remove_relationships(reasoning_server):
    created = create_hypothesis(reasoning_server)
    revision = created["revision"]

    status, edited = request(
        reasoning_server,
        "PUT",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001",
        {"statement": "Updated analyst statement", "expected_revision": revision},
    )
    assert status == 200
    before = created["hypothesis"]
    after = edited["hypothesis"]
    assert after["statement"] == "Updated analyst statement"
    assert after["created_at"] == before["created_at"]
    assert after["state"] == before["state"]

    for relationship, evidence_id in (
        ("supporting-evidence", "EVIDENCE-SUPPORT"),
        ("contradicting-evidence", "EVIDENCE-CONTRADICT"),
    ):
        status, edited = request(
            reasoning_server,
            "POST",
            f"/api/investigations/INV-REASONING/hypotheses/HYP-001/{relationship}",
            {"evidence_id": evidence_id, "expected_revision": edited["revision"]},
        )
        assert status == 200
        assert edited["hypothesis"]["state"] == "open"

    for relationship, evidence_id in (
        ("supporting-evidence", "EVIDENCE-SUPPORT"),
        ("contradicting-evidence", "EVIDENCE-CONTRADICT"),
    ):
        status, edited = request(
            reasoning_server,
            "DELETE",
            f"/api/investigations/INV-REASONING/hypotheses/HYP-001/{relationship}/{evidence_id}",
            {"expected_revision": edited["revision"]},
        )
        assert status == 200

    persisted = reasoning_server["workspace"].get_investigation("INV-REASONING")
    assert len(persisted.investigation.evidence_references) == 4
    assert persisted.investigation.hypotheses[0].state == "open"


@pytest.mark.parametrize("state", ["supported", "rejected", "inconclusive"])
def test_assess_and_reopen_preserve_status_and_history(reasoning_server, state):
    created = create_hypothesis(
        reasoning_server,
        supporting_evidence_ids=["EVIDENCE-SUPPORT"],
        contradicting_evidence_ids=["EVIDENCE-CONTRADICT"],
    )
    original_status = created["investigation"]["metadata"]["status"]
    status, assessed = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001/assess",
        {
            "state": state,
            "rationale": "Current reviewed evidence supports this assessment",
            "author": "Web Analyst",
            "decision_id": "DEC-ASSESS",
            "expected_revision": created["revision"],
        },
    )
    assert status == 200
    assert assessed["hypothesis"]["state"] == state
    assert assessed["decision"]["decision_type"] == "hypothesis_assessment"
    assert assessed["investigation"]["metadata"]["status"] == original_status

    status, invalid = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001/assess",
        {
            "state": "rejected",
            "rationale": "Direct reassessment is not allowed",
            "author": "Web Analyst",
            "decision_id": "DEC-INVALID",
            "expected_revision": assessed["revision"],
        },
    )
    assert (status, invalid["error"]["code"]) == (
        409,
        "invalid_hypothesis_transition",
    )

    status, reopened = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001/reopen",
        {
            "rationale": "New evidence requires further investigation",
            "author": "Web Analyst",
            "decision_id": "DEC-REOPEN",
            "expected_revision": assessed["revision"],
        },
    )
    assert status == 200
    assert reopened["hypothesis"]["state"] == "open"
    assert [item["outcome"] for item in reopened["investigation"]["decisions"]] == [
        state,
        "reopened",
    ]
    assert reopened["investigation"]["metadata"]["status"] == original_status


def test_open_hypothesis_cannot_reopen_and_blank_assessment_fails(reasoning_server):
    created = create_hypothesis(reasoning_server)
    path = "/api/investigations/INV-REASONING/hypotheses/HYP-001/reopen"
    status, payload = request(
        reasoning_server,
        "POST",
        path,
        {
            "rationale": "Not applicable",
            "author": "Web Analyst",
            "decision_id": "DEC-1",
            "expected_revision": created["revision"],
        },
    )
    assert (status, payload["error"]["code"]) == (
        409,
        "invalid_hypothesis_transition",
    )

    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001/assess",
        {
            "state": "supported",
            "rationale": "",
            "author": "Web Analyst",
            "decision_id": "DEC-2",
            "expected_revision": created["revision"],
        },
    )
    assert (status, payload["error"]["code"]) == (
        400,
        "invalid_assessment_rationale",
    )


@pytest.mark.parametrize(
    "decision_type",
    [
        "escalation",
        "containment_recommendation",
        "closure_rationale",
        "investigative_conclusion",
    ],
)
def test_general_decisions_and_detail(reasoning_server, decision_type):
    created = create_hypothesis(reasoning_server)
    status, recorded = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/reasoning/decisions",
        {
            "decision_id": "DEC-GENERAL",
            "decision_type": decision_type,
            "rationale": "Documented analyst reasoning",
            "author": "Web Analyst",
            "hypothesis_ids": ["HYP-001"],
            "evidence_reference_ids": ["EVIDENCE-CONTEXT"],
            "expected_revision": created["revision"],
        },
    )
    assert status == 201
    assert recorded["decision"]["decision_type"] == decision_type
    assert recorded["investigation"]["metadata"]["status"] == "open"

    status, listing = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/reasoning/decisions",
    )
    assert status == 200
    assert listing["decisions"][0]["decision_id"] == "DEC-GENERAL"

    status, headers, detail = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/reasoning/decisions/DEC-GENERAL",
        include_headers=True,
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert detail["decision"]["hypothesis_ids"] == ["HYP-001"]


def test_legacy_mutation_rejected_and_decision_list_is_bounded(reasoning_server):
    current = reasoning_server["current"]
    status, payload = request(
        reasoning_server, "POST",
        "/api/investigations/INV-REASONING/decisions",
        {
            "decision_id": "DEC-LEGACY",
            "decision_type": "unrestricted_type",
            "outcome": "anything",
            "rationale": "legacy",
            "author": "Analyst",
            "expected_revision": current.revision,
        },
    )
    assert (status, payload["error"]["code"]) == (410, "legacy_decision_mutation_disabled")
    assert payload["latest"]["revision"] == current.revision

    long_rationale = "sensitive reasoning " * 40
    status, recorded = request(
        reasoning_server, "POST",
        "/api/investigations/INV-REASONING/reasoning/decisions",
        {
            "decision_id": "DEC-LONG",
            "decision_type": "escalation",
            "rationale": long_rationale,
            "author": "Web Analyst",
            "expected_revision": current.revision,
        },
    )
    assert status == 201
    status, listing = request(
        reasoning_server, "GET",
        "/api/investigations/INV-REASONING/reasoning/decisions",
    )
    assert status == 200
    summary = listing["decisions"][0]
    assert len(summary["rationale_summary"]) == 160
    assert summary["rationale_summary"].endswith("...")
    assert "rationale" not in summary
    assert long_rationale not in json.dumps(listing)

    status, detail = request(
        reasoning_server, "GET",
        "/api/investigations/INV-REASONING/reasoning/decisions/DEC-LONG",
    )
    assert status == 200
    assert detail["decision"]["rationale"] == long_rationale.strip()
    assert recorded["investigation"]["metadata"]["status"] == "open"


def test_assessed_hypothesis_edit_is_rejected_until_reopened(reasoning_server):
    created = create_hypothesis(reasoning_server)
    status, assessed = request(
        reasoning_server, "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001/assess",
        {
            "state": "supported",
            "rationale": "Current evidence supports this",
            "author": "Web Analyst",
            "decision_id": "DEC-ASSESS",
            "expected_revision": created["revision"],
        },
    )
    assert status == 200
    status, rejected = request(
        reasoning_server, "PUT",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001",
        {
            "statement": "Changed assessed statement",
            "expected_revision": assessed["revision"],
        },
    )
    assert (status, rejected["error"]["code"]) == (409, "assessed_hypothesis_not_editable")
    assert rejected["latest"]["revision"] == assessed["revision"]


def test_general_decision_validation(reasoning_server):
    created = create_hypothesis(reasoning_server)
    base = {
        "decision_id": "DEC-1",
        "decision_type": "hypothesis_assessment",
        "rationale": "Not allowed through general route",
        "author": "Web Analyst",
        "hypothesis_ids": ["HYP-001"],
        "evidence_reference_ids": [],
        "expected_revision": created["revision"],
    }
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/reasoning/decisions",
        base,
    )
    assert (status, payload["error"]["code"]) == (400, "invalid_decision_type")

    base.update(
        decision_type="escalation",
        rationale="",
    )
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/reasoning/decisions",
        base,
    )
    assert (status, payload["error"]["code"]) == (
        400,
        "invalid_decision_rationale",
    )

    base.update(rationale="Reason", hypothesis_ids=["HYP-MISSING"])
    status, payload = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/reasoning/decisions",
        base,
    )
    assert (status, payload["error"]["code"]) == (
        404,
        "reasoning_reference_not_found",
    )


def test_revision_conflict_returns_latest_without_retry(reasoning_server):
    created = create_hypothesis(reasoning_server)
    reasoning_server["workspace"].assign_owner(
        "INV-REASONING",
        "Other session",
        expected_revision=created["revision"],
    )
    status, payload = request(
        reasoning_server,
        "PUT",
        "/api/investigations/INV-REASONING/hypotheses/HYP-001",
        {
            "statement": "Draft statement retained by browser",
            "expected_revision": created["revision"],
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "revision_conflict"
    assert payload["latest"]["revision"] == created["revision"] + 1
    assert payload["latest"]["investigation"]["hypotheses"][0]["statement"] != (
        "Draft statement retained by browser"
    )


def test_service_web_parity_and_offline_persistence(reasoning_server):
    service = InvestigationReasoningService(reasoning_server["workspace"])
    created = service.create_hypothesis(
        "INV-REASONING",
        hypothesis_id="HYP-SERVICE",
        statement="Created through shared reasoning service",
        author="Console Analyst",
        supporting_evidence_ids=("EVIDENCE-SUPPORT",),
        expected_revision=reasoning_server["current"].revision,
    )

    status, web = request(
        reasoning_server,
        "POST",
        "/api/investigations/INV-REASONING/hypotheses/HYP-SERVICE/assess",
        {
            "state": "supported",
            "rationale": "Web assessment of shared durable state",
            "author": "Web Analyst",
            "decision_id": "DEC-PARITY",
            "expected_revision": created.revision,
        },
    )
    assert status == 200
    persisted = service.workspace_service.get_investigation("INV-REASONING")
    assert persisted.revision == web["revision"]
    assert persisted.investigation.hypotheses[0].state == "supported"
    assert persisted.investigation.hypotheses[0].supporting_evidence_reference_ids == (
        "EVIDENCE-SUPPORT",
    )
    assert persisted.investigation.decisions[0].decision_id == "DEC-PARITY"

    reasoning_server["server"].active_analysis_result = None
    status, detail = request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/hypotheses/HYP-SERVICE",
    )
    assert status == 200
    assert detail["source_details_available"] is False
    assert detail["supporting_evidence"][0]["reference_id"] == "EVIDENCE-SUPPORT"


def test_content_type_json_method_and_error_safety(reasoning_server):
    path = "/api/investigations/INV-REASONING/hypotheses"
    status, payload = request(
        reasoning_server,
        "POST",
        path,
        payload=create_payload(reasoning_server["current"].revision),
        content_type="text/plain",
    )
    assert (status, payload["error"]["code"]) == (
        415,
        "unsupported_media_type",
    )

    status, payload = request(
        reasoning_server,
        "POST",
        path,
        raw=b"{bad-json",
    )
    assert (status, payload["error"]["code"]) == (400, "invalid_json")

    assert request(reasoning_server, "PATCH", path, {})[0] in {404, 501}
    assert request(
        reasoning_server,
        "GET",
        "/api/investigations/INV-REASONING/reasoning/unknown",
    )[0] == 404

    encoded = json.dumps(payload)
    assert "/tmp/" not in encoded
    assert "Traceback" not in encoded
    assert "command_line" not in encoded

def test_reasoning_ui_source_contract_uses_safe_dom_and_controlled_vocabulary():
    source = (
        Path("soc_forge/web/static/investigations.js")
        .read_text(encoding="utf-8")
    )
    assert source.count('class="brief-section reasoning-section"') == 1
    assert "Hypotheses and Decisions" in source
    assert "States reflect analyst assessment of current evidence, not machine certainty." in source
    assert "It does not verify the hypothesis as objective fact." in source
    assert "It does not perform response actions." in source
    assert "element.textContent = String(text)" in source
    assert "${hypothesis.statement}" not in source
    assert "${decision.rationale}" not in source
    assert "encodeURIComponent(hypothesis.hypothesis_id)" in source
    assert "origin === 'analyst_selection'" in source
    assert "item.classification === classification" in source
    assert "state.reasoningDraft" in source
    assert "localStorage" not in source
    general_form = source.split("async function recordWebDecision()", 1)[1]
    general_form = general_form.split("function bindReasoningActions()", 1)[0]
    assert "hypothesis_assessment" not in general_form


def test_public_interfaces_have_one_reasoning_decision_workflow():
    console_source = Path("soc_forge/investigations/console.py").read_text(encoding="utf-8")
    web_api_source = Path("soc_forge/web/investigation_api.py").read_text(encoding="utf-8")
    web_ui_source = Path("soc_forge/web/static/investigations.js").read_text(encoding="utf-8")

    assert "[9] Record decision" not in console_source
    assert "workspace_service.record_decision" not in console_source
    assert "workspace_service.record_decision" not in web_api_source
    assert "recordDecisionButton" not in web_ui_source
    assert "/reasoning/decisions" in web_ui_source


def test_reasoning_web_boundary_does_not_construct_domain_models_or_write_json():
    source = Path("soc_forge/web/investigation_api.py").read_text(encoding="utf-8")
    assert "Hypothesis(" not in source
    assert "Decision(" not in source
    assert "EvidenceReference(" not in source
    assert ".write_text(" not in source
    assert "json.dump" not in source
    assert "InvestigationReasoningService" in source
