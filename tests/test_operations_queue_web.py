import json
import threading
from http.client import HTTPConnection
from pathlib import Path
from urllib.parse import quote

import pytest

from soc_forge.investigations.finding_service import InvestigationFindingService
from dataclasses import asdict

from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.operations_prioritization import OperationsPrioritizationService
from soc_forge.investigations.operations_queue import OperationsQueueService
from soc_forge.investigations.operations_queue_console import render_queue_items
from soc_forge.investigations.response_action_service import (
    InvestigationResponseActionService,
)
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService
from soc_forge.web.app import make_server
from test_operations_queue import _action, _finding, _save


def _request(address, path):
    connection = HTTPConnection(*address, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        payload = json.loads(response.read())
        return response.status, dict(response.getheaders()), payload
    finally:
        connection.close()


def _start(tmp_path, repository):
    out_dir = tmp_path / "out"
    server = make_server(
        "127.0.0.1",
        0,
        out_dir,
        workspace_root=repository.storage_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address


def _stop(server, thread):
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def test_get_empty_queue_is_no_store_and_offline(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    server, thread, address = _start(tmp_path, repository)
    try:
        server.active_analysis_result = None
        status, headers, payload = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["summary"] == {
        "total_items": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "response_actions": 0,
        "uncovered_findings": 0,
        "proposed": 0,
        "approved": 0,
        "in_progress": 0,
    }
    assert payload["items"] == []

    operational = payload["operational_summary"]
    assert operational["total_attention_items"] == 0
    assert operational["investigations_represented"] == 0
    assert operational["response_action_count"] == 0
    assert operational["uncovered_finding_count"] == 0
    assert operational["top_item"] is None
    assert operational["top_items"] == []

@pytest.mark.parametrize("status", ["proposed", "approved", "in_progress"])
def test_get_queue_includes_each_open_action_state(tmp_path, status):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status=status),))
    server, thread, address = _start(tmp_path, repository)
    try:
        response_status, headers, payload = _request(
            address, "/api/operations-queue"
        )
    finally:
        _stop(server, thread)
    assert response_status == 200
    assert headers["Cache-Control"] == "no-store"
    assert [item["source_status"] for item in payload["items"]] == [status]
    assert payload["summary"][status] == 1


@pytest.mark.parametrize("status", ["completed", "dismissed"])
def test_terminal_action_is_excluded_and_finding_is_uncovered(tmp_path, status):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(status=status),))
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, payload = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert [(item["item_type"], item["source_id"]) for item in payload["items"]] == [
        ("uncovered_finding", "FIND-001")
    ]


def test_mixed_queue_summary_order_ids_detail_and_read_immutability(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(
        repository,
        "INV-B",
        actions=(_action("INV-B", status="approved", priority="critical"),),
    )
    _save(repository, "INV-A", findings=(_finding("INV-A", "FIND-001"),))
    before = {
        path.name: path.read_bytes()
        for path in repository.investigations_root.glob("*.json")
    }
    revisions = {
        item.investigation_id: item.revision
        for item in repository.list_investigations()
    }
    server, thread, address = _start(tmp_path, repository)
    try:
        status, headers, payload = _request(address, "/api/operations-queue")
        queue_id = payload["items"][0]["queue_item_id"]
        detail_status, detail_headers, detail = _request(
            address, "/api/operations-queue/" + queue_id
        )
    finally:
        _stop(server, thread)
    assert status == detail_status == 200
    assert headers["Cache-Control"] == detail_headers["Cache-Control"] == "no-store"
    assert [item["investigation_id"] for item in payload["items"]] == [
        "INV-B",
        "INV-A",
    ]
    assert payload["summary"]["total_items"] == 2
    assert payload["summary"]["critical"] == 1
    assert payload["summary"]["medium"] == 1
    assert payload["summary"]["response_actions"] == 1
    assert payload["summary"]["uncovered_findings"] == 1
    assert detail == payload["items"][0]
    assert detail["queue_item_id"] == "OPQ:INV-B:response_action:ACT-001"
    assert {
        path.name: path.read_bytes()
        for path in repository.investigations_root.glob("*.json")
    } == before
    assert {
        item.investigation_id: item.revision
        for item in repository.list_investigations()
    } == revisions



def test_web_and_terminal_service_projection_are_identical(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, "INV-A", actions=(_action("INV-A", status="in_progress"),))
    _save(repository, "INV-B", findings=(_finding("INV-B", "FIND-001"),))
    queue_service = OperationsQueueService(repository)
    service = OperationsPrioritizationService(queue_service)
    expected_items = service.prioritize()
    expected_summary = queue_service.summarize(item.queue_item for item in expected_items)
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, payload = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    expected_payload = []
    for item in expected_items:
        projected = asdict(item.queue_item)
        projected.update(
            priority_tier=item.priority_tier,
            priority_basis=list(item.priority_basis),
            operational_state=item.operational_state,
        )
        expected_payload.append(projected)
    assert payload["items"] == expected_payload
    assert payload["top_item"] == expected_payload[0]
    assert payload["summary"] == asdict(expected_summary)

def test_multi_finding_action_is_one_item_and_superseded_is_excluded(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    findings = (
        _finding(finding_id="FIND-001", supersedes_finding_id="FIND-OLD"),
        _finding(finding_id="FIND-002"),
        _finding(
            finding_id="FIND-OLD",
            lifecycle_state="superseded",
            superseded_by_finding_id="FIND-001",
            supersession_reason="Replaced.",
            supersession_author="alice",
            superseded_at="2026-08-14T13:00:00Z",
        ),
    )
    _save(
        repository,
        findings=findings,
        actions=(_action(finding_ids=("FIND-001", "FIND-002")),),
    )
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, payload = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert len(payload["items"]) == 1
    assert payload["items"][0]["source_id"] == "ACT-001"


def test_cross_investigation_same_source_id_is_scoped_and_distinct(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, "INV-A", actions=(_action("INV-A"),))
    _save(repository, "INV-B", actions=(_action("INV-B"),))
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, payload = _request(address, "/api/operations-queue")
        details = [
            _request(address, "/api/operations-queue/" + item["queue_item_id"])[2]
            for item in payload["items"]
        ]
    finally:
        _stop(server, thread)
    assert {item["investigation_id"] for item in details} == {"INV-A", "INV-B"}
    assert len({item["queue_item_id"] for item in details}) == 2


def test_missing_and_corrupt_queue_errors_are_bounded(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository)
    server, thread, address = _start(tmp_path, repository)
    try:
        status, headers, payload = _request(
            address, "/api/operations-queue/OPQ:missing"
        )
        record = next(repository.investigations_root.glob("*.json"))
        record.write_text("{broken")
        broken_status, _, broken = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert status == 404
    assert headers["Cache-Control"] == "no-store"
    assert payload == {"error": "Operations queue item not found"}
    assert broken_status == 500
    assert broken == {"error": "Unable to load analyst operations queue"}
    assert "broken" not in json.dumps(broken)


def test_authoritative_mutations_refresh_action_finding_membership(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(repository, actions=(_action(),))
    workspace = InvestigationWorkspaceService(repository)
    actions = InvestigationResponseActionService(workspace)
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, initial = _request(address, "/api/operations-queue")
        revision = 1
        for target in ("approved", "in_progress", "completed"):
            result = actions.transition_action(
                "INV-A",
                "ACT-001",
                target_status=target,
                author="alice",
                rationale="Authoritative transition.",
                expected_revision=revision,
            )
            revision = result.revision
        _, _, refreshed = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert initial["items"][0]["source_id"] == "ACT-001"
    assert [(item["item_type"], item["source_id"]) for item in refreshed["items"]] == [
        ("uncovered_finding", "FIND-001")
    ]


def test_new_action_removes_uncovered_and_supersession_removes_original(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(
        repository,
        findings=(
            _finding(finding_id="FIND-001"),
            _finding(finding_id="FIND-002"),
        ),
    )
    workspace = InvestigationWorkspaceService(repository)
    actions = InvestigationResponseActionService(workspace)
    findings = InvestigationFindingService(workspace)
    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, initial = _request(address, "/api/operations-queue")
        created = actions.create_action(
            "INV-A",
            action_id="ACT-NEW",
            finding_ids=("FIND-001",),
            title="Review",
            description="Review durable state.",
            action_type="validation",
            priority="high",
            rationale="Finding requires work.",
            owner="soc",
            created_by="alice",
            expected_revision=1,
        )
        _, _, covered = _request(address, "/api/operations-queue")
        findings.supersede_finding(
            "INV-A",
            "FIND-002",
            "FIND-001",
            reason="Consolidated.",
            author="alice",
            expected_revision=created.revision,
        )
        _, _, superseded = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    assert {item["source_id"] for item in initial["items"]} == {
        "FIND-001",
        "FIND-002",
    }
    assert {item["source_id"] for item in covered["items"]} == {
        "ACT-NEW",
        "FIND-002",
    }
    assert [item["source_id"] for item in superseded["items"]] == ["ACT-NEW"]


def test_queue_uncovered_finding_navigation_preserves_ids_offline_without_mutation(
    tmp_path,
):
    repository = InvestigationRepository(tmp_path / "workspace")
    _save(
        repository,
        "INV-MANUAL-001",
        findings=(_finding("INV-MANUAL-001", "FIND-MANUAL-001"),),
    )
    before = {
        path.name: path.read_bytes()
        for path in repository.investigations_root.glob("*.json")
    }
    server, thread, address = _start(tmp_path, repository)
    try:
        server.active_analysis_result = None
        queue_status, _, queue = _request(address, "/api/operations-queue")
        item = queue["items"][0]
        investigation_id = item["investigation_id"]
        finding_id = item["source_id"]
        detail_status, _, detail = _request(
            address,
            (
                f"/api/investigations/{quote(investigation_id, safe='')}"
                f"/findings/{quote(finding_id, safe='')}"
            ),
        )
    finally:
        _stop(server, thread)

    assert queue_status == detail_status == 200
    assert item["queue_item_id"] == (
        "OPQ:INV-MANUAL-001:uncovered_finding:FIND-MANUAL-001"
    )
    assert investigation_id == detail["investigation_id"] == "INV-MANUAL-001"
    assert finding_id == detail["finding"]["finding_id"] == "FIND-MANUAL-001"
    assert detail["finding"]["lifecycle_state"] == "active"
    assert {
        path.name: path.read_bytes()
        for path in repository.investigations_root.glob("*.json")
    } == before


def test_web_operations_contract_uses_safe_dom_and_existing_source_workflows():
    root = Path(__file__).parents[1]
    source = (root / "soc_forge/web/static/operations_queue.js").read_text()
    findings_source = (
        root / "soc_forge/web/static/investigation_findings.js"
    ).read_text()
    app = (root / "soc_forge/web/static/app.js").read_text()
    index = (root / "soc_forge/web/static/index.html").read_text()
    assert "Operations Queue" in index
    assert "Operations Workspace" in index
    assert "What needs attention" in index
    assert "Read-only prioritization surface." in index
    assert index.index("id=\"operationsTopItems\"") < index.index(
        "class=\"operations-browser\""
    )
    assert "Prioritize current attention items derived from durable Findings and Response Actions." in index
    for label in (
        "All",
        "Response Actions",
        "Uncovered Findings",
        "High/Critical",
        "Open Response Action",
        "Open Finding",
        "No analyst attention items.",
    ):
        assert label in source or label in index
    for label in (
        "Attention Items",
        "High / Critical",
        "Investigations Represented",
        "Why it needs attention",
        "Authoritative destination",
    ):
        assert label in source
    assert "createElement" in source
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "Why this is prioritized:" in source
    assert "priority_basis" in source
    assert "state.activeOperationsItemId" in source
    assert "renderOperationsDetail" in source
    assert "innerHTML" not in source
    assert "score" not in source.lower()
    assert "gauge" not in source.lower()
    assert "localStorage" not in source
    for forbidden in ("Acknowledge", "Dismiss Queue Item", "Snooze", "Escalate"):
        assert forbidden not in source
    assert "openInvestigation(item.investigation_id)" in source
    assert "await openResponseAction(item.source_id)" in source
    assert "openFinding(item.source_id, item.investigation_id)" in source
    assert "async function openFinding(findingId, investigationId = null)" in findings_source
    assert "findingBase(investigationId)" in findings_source
    assert "items.forEach((item, index)" in source
    assert "items.sort" not in source
    assert "innerHTML" not in findings_source
    assert "loadOperationsQueue()" in app
    assert "/static/operations_queue.js" in index


def test_mixed_state_service_terminal_web_prioritization_parity(tmp_path):
    repository = InvestigationRepository(tmp_path / "workspace")
    for investigation_id, status, priority in (
        ("INV-CRIT", "proposed", "critical"),
        ("INV-PROG", "in_progress", "high"),
        ("INV-APP", "approved", "high"),
        ("INV-PROP", "proposed", "high"),
    ):
        _save(
            repository,
            investigation_id,
            actions=(_action(investigation_id, status=status, priority=priority),),
        )
    _save(
        repository,
        "INV-MED",
        findings=(
            _finding("INV-MED", "FIND-MED", supersedes_finding_id="FIND-OLD"),
            _finding(
                "INV-MED", "FIND-OLD", lifecycle_state="superseded",
                superseded_by_finding_id="FIND-MED",
                supersession_reason="Replaced.", supersession_author="alice",
                superseded_at="2026-08-14T13:00:00Z",
            ),
        ),
        actions=(
            _action(
                "INV-MED", action_id="ACT-DONE", finding_ids=("FIND-OLD",), status="completed"
            ),
        ),
    )
    service = OperationsPrioritizationService(OperationsQueueService(repository))
    expected = service.prioritize()

    server, thread, address = _start(tmp_path, repository)
    try:
        _, _, payload = _request(address, "/api/operations-queue")
    finally:
        _stop(server, thread)
    rendered = render_queue_items(expected, width=100, ansi=False)

    assert [item["investigation_id"] for item in payload["items"]] == [
        "INV-CRIT", "INV-PROG", "INV-APP", "INV-PROP", "INV-MED",
    ]
    assert [item["priority_basis"] for item in payload["items"]] == [
        list(item.priority_basis) for item in expected
    ]
    assert payload["top_item"]["investigation_id"] == "INV-CRIT"
    operational = payload["operational_summary"]
    assert operational["total_attention_items"] == 5
    assert operational["investigations_represented"] == 5
    assert (
        operational["critical_count"], operational["high_count"],
        operational["medium_count"], operational["low_count"],
    ) == (1, 3, 1, 0)
    assert operational["response_action_count"] == 4
    assert operational["uncovered_finding_count"] == 1
    assert operational["top_item"] == payload["top_item"]
    assert [item["investigation_id"] for item in operational["top_items"]] == [
        "INV-CRIT", "INV-PROG", "INV-APP",
    ]
    assert "ACT-DONE" not in json.dumps(payload)
    assert "FIND-OLD" not in json.dumps(payload)
    for earlier, later in zip(
        ("INV-CRIT", "INV-PROG", "INV-APP", "INV-PROP"),
        ("INV-PROG", "INV-APP", "INV-PROP", "INV-MED"),
    ):
        assert rendered.index(earlier) < rendered.index(later)
