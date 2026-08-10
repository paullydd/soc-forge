import json
import threading
from copy import deepcopy
from hashlib import sha256
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import quote, urlencode

import pytest

import soc_forge.web.investigation_api as investigation_api

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import (
    InvestigationQueryContext,
    normalize_entity,
    opaque_entity_id,
)
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.web.app import make_server


@pytest.fixture
def query_web_server(tmp_path):
    out_dir = tmp_path / "analysis"
    workspace_root = tmp_path / "workspace"
    analysis = build_query_analysis(out_dir)
    investigation = build_query_investigation(analysis)
    repository = InvestigationRepository(workspace_root)
    assert repository.save(investigation) == 1
    server = make_server("127.0.0.1", 0, out_dir, workspace_root=workspace_root)
    server.active_analysis_result = analysis
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    info = {
        "host": host,
        "port": port,
        "server": server,
        "analysis": analysis,
        "investigation": investigation,
        "workspace_root": workspace_root,
    }
    try:
        yield info
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def request(info, path, *, include_headers=False):
    connection = HTTPConnection(info["host"], info["port"], timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        kind = response.getheader("Content-Type") or ""
        payload = (
            json.loads(body.decode("utf-8"))
            if body and kind.startswith("application/json")
            else body
        )
        if include_headers:
            return response.status, dict(response.getheaders()), payload
        return response.status, payload
    finally:
        connection.close()


def base(path="timeline"):
    return f"/api/investigations/INV-QUERY/{path}"


def repository_bytes(info):
    return next(
        (info["workspace_root"] / "investigations").glob("*.json")
    ).read_bytes()


def artifact_hashes(info):
    return {
        key: sha256(path.read_bytes()).hexdigest()
        for key, path in info["analysis"].artifacts.items()
    }


def listed_entity(info, entity_type, display_value=None):
    status, payload = request(info, base("entities"))
    assert status == 200
    return next(
        item
        for item in payload["entities"]
        if item["entity_type"] == entity_type
        and (display_value is None or item["display_value"] == display_value)
    )


def entity_route(info, entity_type, category=None, display_value=None):
    entity = listed_entity(info, entity_type, display_value)
    path = f"entities/{quote(entity['entity_id'], safe='')}"
    if category:
        path += f"/{category}"
    return base(path)


def test_full_timeline_contract_order_untimed_overlays_and_no_store(query_web_server):
    status, headers, payload = request(
        query_web_server, base(), include_headers=True
    )
    context = InvestigationQueryContext(
        query_web_server["analysis"], query_web_server["investigation"]
    )
    expected = InvestigationTimelineService().timeline(context)

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["investigation_id"] == "INV-QUERY"
    assert payload["revision"] == 1
    assert [item["entry_id"] for item in payload["timed_entries"]] == [
        item.entry_id for item in expected.entries
    ]
    assert [item["entry_id"] for item in payload["untimed_entries"]] == [
        item.entry_id for item in expected.untimed_entries
    ]
    assert payload["untimed_entries"]
    alert = next(item for item in payload["timed_entries"] if item["source_id"] == "ALERT-001")
    assert alert["evidence_classification"] == "supporting"
    assert alert["hypothesis_overlays"][0]["hypothesis_id"] == "HYP-001"
    assert alert["decision_overlays"][0]["decision_id"] == "DEC-ASSESS"
    encoded = json.dumps(payload)
    assert "Supports defense-evasion hypothesis" not in encoded
    assert "Evidence supported the working hypothesis" not in encoded
    assert "powershell.exe -enc sensitive" not in encoded


@pytest.mark.parametrize(
    ("name", "value", "field"),
    [
        ("start_time", "2026-08-10T14:00:00Z", "start_time"),
        ("end_time", "2026-08-10T14:10:00Z", "end_time"),
        ("entry_type", "alert", "entry_types"),
        ("host", "WS-LAB-01", "host"),
        ("user", "DOMAIN\\alice", "user"),
        ("ip", "10.0.0.5", "ip"),
        ("process", "powershell.exe", "process"),
        ("rule_id", "SOCF-021", "rule_id"),
        ("attack_tactic", "Defense Evasion", "attack_tactic"),
        ("attack_technique", "T1562.001", "attack_technique"),
        ("severity", "high", "severity"),
        ("evidence_classification", "supporting", "evidence_classification"),
        ("hypothesis_id", "HYP-001", "hypothesis_id"),
        ("case_id", "CASE-001", "case_id"),
    ],
)
def test_typed_timeline_filters(query_web_server, name, value, field):
    status, payload = request(query_web_server, base() + "?" + urlencode({name: value}))
    assert status == 200
    expected = [value] if field == "entry_types" else value
    assert payload["applied_filters"][field] == expected


def test_multiple_filters_use_shared_and_semantics(query_web_server):
    query = urlencode({"host": "WS-LAB-01", "rule_id": "SOCF-021"})
    status, payload = request(query_web_server, base() + "?" + query)
    assert status == 200
    assert payload["timed_entries"]
    assert all(item["host"] == "WS-LAB-01" for item in payload["timed_entries"])
    assert all(item["rule_id"] == "SOCF-021" for item in payload["timed_entries"])


@pytest.mark.parametrize(
    ("query", "code"),
    [
        ("free_text=anything", "invalid_filter"),
        ("entry_type=unsupported", "invalid_filter"),
        ("severity=urgent", "invalid_filter"),
        ("evidence_classification=unknown", "invalid_filter"),
        (
            urlencode(
                {
                    "start_time": "2026-08-11T00:00:00Z",
                    "end_time": "2026-08-10T00:00:00Z",
                }
            ),
            "invalid_time_range",
        ),
    ],
)
def test_invalid_timeline_filters_are_generic(query_web_server, query, code):
    status, payload = request(query_web_server, base() + "?" + query)
    assert status == 400
    assert payload["error"]["code"] == code
    assert str(query_web_server["workspace_root"]) not in json.dumps(payload)


def test_timeline_entry_detail_uses_projection_and_navigation_ids(query_web_server):
    _, timeline = request(query_web_server, base())
    entry = next(item for item in timeline["timed_entries"] if item["source_id"] == "ALERT-001")
    status, headers, payload = request(
        query_web_server,
        base("timeline/" + quote(entry["entry_id"], safe="")),
        include_headers=True,
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["entry"] == entry
    assert payload["entry"]["relationship_reason"]
    assert payload["navigation"]["evidence_id"] == entry["evidence_id"]
    assert payload["navigation"]["hypothesis_ids"] == ["HYP-001"]
    assert "rationale" not in json.dumps(payload).casefold()


def test_missing_timeline_entry_returns_404(query_web_server):
    status, payload = request(query_web_server, base("timeline/missing-entry"))
    assert status == 404
    assert payload["error"]["code"] == "timeline_entry_not_found"


def test_entity_list_is_deterministic_bounded_projection(query_web_server):
    status, headers, payload = request(
        query_web_server, base("entities"), include_headers=True
    )
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    keys = [
        (item["entity_type"], item["normalized_value"], item["secondary_key"] or "")
        for item in payload["entities"]
    ]
    assert keys == sorted(keys)
    assert {
        "host", "user", "ip", "process", "service", "rule",
        "attack_technique", "case", "evidence", "hypothesis",
    } <= {item["entity_type"] for item in payload["entities"]}
    host = next(item for item in payload["entities"] if item["entity_type"] == "host")
    assert set(host["observed_counts"]) == {
        "events", "alerts", "cases", "evidence", "evidence_selections"
    }
    assert host["first_seen"] <= host["last_seen"]


def test_opaque_entity_ids_are_deterministic_bounded_and_source_private():
    sensitive = (
        ("host", "VERY-SENSITIVE-HOST"),
        ("user", r"DOMAIN\SensitiveUser"),
        ("ip", "203.0.113.77"),
        ("ip", "2001:db8::77"),
        ("process", r"C:\Sensitive\Path\powershell.exe"),
        ("service", "SensitiveServiceName"),
    )
    for entity_type, value in sensitive:
        entity = normalize_entity(entity_type, value)
        entity_id = opaque_entity_id("analysis-sensitive", entity)
        assert entity_id == opaque_entity_id("analysis-sensitive", entity)
        assert entity_id.startswith(f"entity-{entity_type}-")
        assert len(entity_id) <= 64
        assert value.casefold() not in entity_id.casefold()
        assert entity_id != opaque_entity_id("analysis-other", entity)


def test_entity_list_ids_drive_private_http_routes(query_web_server):
    _, listing = request(query_web_server, base("entities"))
    for entity_type in ("host", "user", "ip", "process", "service"):
        entity = next(
            item for item in listing["entities"] if item["entity_type"] == entity_type
        )
        assert entity["display_value"]
        assert entity["entity_id"].startswith(f"entity-{entity_type}-")
        path = base(f"entities/{quote(entity['entity_id'], safe='')}/events")
        assert entity["display_value"] not in path
        assert "?" not in path
        status, _, _ = request(query_web_server, path, include_headers=True)
        assert status == 200


def test_foreign_and_wrong_type_entity_ids_do_not_resolve(query_web_server):
    foreign = opaque_entity_id(
        "different-analysis",
        normalize_entity("host", "WS-LAB-01"),
    )
    status, payload = request(query_web_server, base(f"entities/{foreign}/events"))
    assert status == 404
    assert payload["error"]["code"] == "entity_not_found"

    host = listed_entity(query_web_server, "host", "WS-LAB-01")
    wrong_type = host["entity_id"].replace("entity-host-", "entity-user-", 1)
    status, payload = request(query_web_server, base(f"entities/{wrong_type}/events"))
    assert status == 404
    assert payload["error"]["code"] == "entity_not_found"

def test_opaque_entity_collision_fails_explicitly(query_web_server, monkeypatch):
    monkeypatch.setattr(
        investigation_api,
        "opaque_entity_id",
        lambda source_analysis_id, entity: "entity-collision",
    )
    status, payload = request(
        query_web_server,
        base("entities/entity-collision/events"),
    )
    assert status == 409
    assert payload["error"]["code"] == "entity_identity_collision"

def test_entity_type_filter_detail_and_invalid_type(query_web_server):
    status, payload = request(query_web_server, base("entities?type=host"))
    assert status == 200
    assert {item["entity_type"] for item in payload["entities"]} == {"host"}
    host = payload["entities"][0]
    path = "entities/" + quote(host["entity_id"], safe="")
    status, detail = request(query_web_server, base(path))
    assert status == 200
    assert detail["entity"]["normalized_value"] == host["normalized_value"]

    status, invalid = request(query_web_server, base("entities?type=unknown"))
    assert status == 400
    assert invalid["error"]["code"] == "unsupported_entity_type"


@pytest.mark.parametrize(
    ("entity_type", "category"),
    [
        ("host", "events"),
        ("user", "alerts"),
        ("ip", "evidence"),
        ("process", "cases"),
        ("rule", "alerts"),
        ("attack_technique", "alerts"),
        ("case", "evidence"),
        ("evidence", "hypotheses"),
        ("hypothesis", "hypotheses"),
    ],
)
def test_entity_pivot_categories(query_web_server, entity_type, category):
    _, listing = request(query_web_server, base("entities"))
    entity = next(item for item in listing["entities"] if item["entity_type"] == entity_type)
    path = "/".join(
        [
            "entities",
            quote(entity["entity_id"], safe=""),
            category,
        ]
    )
    status, payload = request(query_web_server, base(path))
    assert status == 200
    assert payload["entity"]["entity_type"] == entity_type
    assert all(item["relationship_reason"] for item in payload["matches"])


def test_related_entities_and_entity_timeline_are_explainable(query_web_server):
    entity_id = quote(listed_entity(query_web_server, "host", "WS-LAB-01")["entity_id"], safe="")
    status, related = request(
        query_web_server, base(f"entities/{entity_id}/related")
    )
    assert status == 200
    assert related["relationships"]
    assert all(item["relationship_reason"] for item in related["relationships"])
    assert "caused by" not in json.dumps(related).casefold()

    status, timeline = request(
        query_web_server, base(f"entities/{entity_id}/timeline")
    )
    assert status == 200
    assert all(item["host"] == "WS-LAB-01" for item in timeline["timed_entries"])


def test_entity_not_found_and_invalid_ip_are_controlled(query_web_server):
    status, missing = request(
        query_web_server, base("entities/entity-host-000000000000000000000000/events")
    )
    assert status == 404
    assert missing["error"]["code"] == "entity_not_found"
    status, deprecated = request(
        query_web_server, base("entities/ip/not-an-ip/events")
    )
    assert status == 410
    assert deprecated["error"]["code"] == "deprecated_entity_route"


def test_missing_active_analysis_and_provenance_mismatch_are_409(query_web_server, tmp_path):
    server = query_web_server["server"]
    active = server.active_analysis_result
    server.active_analysis_result = None
    status, missing = request(query_web_server, base())
    assert status == 409
    assert missing["error"]["code"] == "analysis_unavailable"

    other = build_query_analysis(tmp_path / "other-analysis")
    other.input_name = "other.jsonl"
    server.active_analysis_result = other
    status, mismatch = request(query_web_server, base())
    assert status == 409
    assert mismatch["error"]["code"] == "analysis_provenance_mismatch"
    server.active_analysis_result = active


def test_current_revision_refreshes_without_mutating_workbench(query_web_server):
    service = query_web_server["server"].investigation_app.workspace_service
    latest = service.assign_owner("INV-QUERY", "other-session", expected_revision=1)
    status, payload = request(query_web_server, base())
    assert status == 200
    assert payload["revision"] == latest.revision == 2


def test_http_workbench_is_byte_and_hash_read_only(query_web_server):
    repository_before = repository_bytes(query_web_server)
    artifacts_before = artifact_hashes(query_web_server)
    analysis_before = deepcopy(query_web_server["analysis"])
    _, timeline = request(query_web_server, base())
    entry = next(item for item in timeline["timed_entries"] if item["source_id"] == "ALERT-001")
    host_detail = entity_route(query_web_server, "host", display_value="WS-LAB-01")
    paths = [
        base(),
        base() + "?host=WS-LAB-01&rule_id=SOCF-021",
        base("timeline/" + quote(entry["entry_id"], safe="")),
        base("entities"),
        host_detail,
        entity_route(query_web_server, "host", "events", "WS-LAB-01"),
        entity_route(query_web_server, "host", "evidence", "WS-LAB-01"),
        entity_route(query_web_server, "host", "hypotheses", "WS-LAB-01"),
        entity_route(query_web_server, "host", "related", "WS-LAB-01"),
        entity_route(query_web_server, "host", "timeline", "WS-LAB-01"),
        base("evidence/candidates/" + quote(entry["evidence_id"], safe="")),
        base("hypotheses/HYP-001"),
        base("reasoning/decisions/DEC-ASSESS"),
    ]
    for path in paths:
        assert request(query_web_server, path)[0] == 200
    assert repository_bytes(query_web_server) == repository_before
    assert artifact_hashes(query_web_server) == artifacts_before
    assert query_web_server["analysis"] == analysis_before
    current = query_web_server["server"].investigation_app.workspace_service.get_investigation(
        "INV-QUERY"
    )
    assert current.revision == 1


def test_web_and_console_query_services_have_semantic_parity(query_web_server):
    analysis = query_web_server["analysis"]
    investigation = query_web_server["investigation"]
    context = InvestigationQueryContext(analysis, investigation)
    timeline = InvestigationTimelineService().timeline(
        context, filters={"host": "WS-LAB-01"}
    )
    status, web = request(query_web_server, base() + "?host=WS-LAB-01")
    assert status == 200
    assert [item["entry_id"] for item in web["timed_entries"]] == [
        item.entry_id for item in timeline.entries
    ]
    assert web["applied_filters"]["host"] == timeline.applied_filters.host

    service = InvestigationPivotService()
    entities = service.entities(context)
    _, web_entities = request(query_web_server, base("entities"))
    assert [
        (item["entity_type"], item["normalized_value"], item["secondary_key"])
        for item in web_entities["entities"]
    ] == [
        (item.entity_type, item.normalized_value, item.secondary_key)
        for item in entities
    ]
    pivot = service.alerts_for_entity(context, "host", "WS-LAB-01")
    _, web_pivot = request(
        query_web_server, entity_route(query_web_server, "host", "alerts", "WS-LAB-01")
    )
    assert [
        (item["source_id"], item["relationship_type"], item["relationship_reason"])
        for item in web_pivot["matches"]
    ] == [
        (item.source_id, item.relationship_type, item.relationship_reason)
        for item in pivot.matches
    ]


def test_query_api_source_has_no_write_service_calls():
    source = Path("soc_forge/web/investigation_api.py").read_text(encoding="utf-8")
    query_section = source[source.index("    def get_timeline("):source.index("    def _matching_analysis_available(")]
    for call in (
        "assign_owner(",
        "change_status(",
        "save(",
        "delete_investigation(",
        "replace_evidence_references(",
        "record_investigation_decision(",
    ):
        assert call not in query_section


def test_web_workbench_ui_contract_is_safe_read_only_and_complete():
    source = Path("soc_forge/web/static/query_workbench.js").read_text(
        encoding="utf-8"
    )
    investigation_source = Path(
        "soc_forge/web/static/investigations.js"
    ).read_text(encoding="utf-8")
    html = Path("soc_forge/web/static/index.html").read_text(encoding="utf-8")

    assert "query_workbench.js" in html
    assert "Timeline and Pivot Workbench" in investigation_source
    assert "Read Only" in investigation_source
    assert "bindInvestigationWorkbench()" in investigation_source
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "encodeURIComponent" in source
    assert "entity.entity_id" in source
    assert "encodeURIComponent(entity.display_value)" not in source
    assert "encodeURIComponent(entity.entity_type)" not in source
    assert "queryControlledFilters" in source
    assert "const input = queryNode(options ? 'select' : 'input')" in source
    assert "entry_type:" in source
    assert "severity:" in source
    assert "evidence_classification:" in source
    assert "Active Filters" in source
    assert "Clear Filters" in source
    assert "Untimed Investigation Context" in source
    assert "Normalized Entities" in source
    assert "Reason:" in source
    assert "View Evidence" in source
    assert "View Hypothesis" in source
    assert "View Decision" in source
    assert "Workbench data may be stale" in source
    assert "refreshQueryWorkbench" in source
    assert "analysis_provenance_mismatch" in source
    assert "method: 'POST'" not in source
    assert "method: 'PUT'" not in source
    assert "method: 'DELETE'" not in source


def test_workbench_routes_are_get_only_in_static_source():
    source = Path("soc_forge/web/static/query_workbench.js").read_text(
        encoding="utf-8"
    )
    assert "fetch(path, { cache: 'no-store' })" in source
    for mutation in (
        "/owner",
        "/status",
        "/annotations",
        "/assess",
        "/reopen",
        "/selections",
    ):
        assert mutation not in source
