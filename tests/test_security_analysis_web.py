import json
import threading
from http.client import HTTPConnection
from pathlib import Path

from soc_forge.web.app import make_server


ROOT = Path(__file__).parents[1]
STATIC = ROOT / "soc_forge" / "web" / "static"


def _request(address, path):
    connection = HTTPConnection(*address, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), json.loads(response.read())
    finally:
        connection.close()


def test_security_analysis_workspace_has_only_supported_subviews():
    index = (STATIC / "index.html").read_text()
    app = (STATIC / "app.js").read_text()

    assert 'data-view="analysis">Security Analysis' in index
    assert 'id="analysisView"' in index
    for tab in ("overview", "entities", "attack", "relationships", "timeline", "hunts"):
        assert f'data-analysis-tab="{tab}"' in index
        assert f'data-analysis-panel="{tab}"' in index
    assert 'data-view="hunts"' not in index
    assert 'data-view="graph">Investigation Graph' not in index
    assert "analysis: ['Security Analysis'" in app


def test_security_analysis_renderer_preserves_semantic_boundaries():
    source = (STATIC / "security_analysis.js").read_text()

    for text in (
        "FULL combines current machine analysis with durable analyst state",
        "OFFLINE is a valid durable-state view",
        "Observed activity, not Detection Coverage",
        "Shared observations do not establish identity or cause",
        "Chronology is not causality",
        "Existing pipeline Hunts",
        "exploration results remain ephemeral",
    ):
        assert text in source
    for prohibited in (
        "risk score", "threat score", "campaign score", "completeness",
        "saved hunts", "scheduled hunts", "localStorage", "sessionStorage",
    ):
        assert prohibited not in source.lower()


def test_entity_explorer_is_exact_safe_dom_and_has_clean_pivots():
    source = (STATIC / "security_analysis.js").read_text()

    assert "exact normalized match" in source
    assert "document.createElement" in source
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "innerHTML" not in source
    assert "URLSearchParams" in source
    assert "openInvestigation(investigationId)" in source
    assert "setInvestigationTab('summary')" in source
    assert "setAnalysisTab('hunts')" in source
    assert "Observed entities" in source
    assert "selectDiscoveredEntity(entity)" in source
    assert "searchAnalysisEntity(entity.entity_type, entity.display_value)" in source
    assert "Machine " in source and "Analyst " in source
    assert "Persisted Investigation state does not contain standalone entity values" in source


def test_offline_api_is_read_only_and_marks_machine_fields_unavailable(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path / "out")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, payload = _request(server.server_address, "/api/security-analysis")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["overview"]["mode"] == "offline"
    assert payload["overview"]["alert_count"] is None
    assert payload["attack"]["mode"] == "offline"
    assert payload["relationships"]["mode"] == "offline"
    assert payload["timeline"]["mode"] == "offline"
    assert payload["hunts"]["mode"] == "offline"
    assert payload["hunts"]["hunt_count"] is None


def test_entity_api_rejects_unsupported_or_empty_queries(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path / "out")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        unsupported, _, _ = _request(
            server.server_address, "/api/security-analysis/entity?type=email&value=a%40b"
        )
        empty, _, _ = _request(
            server.server_address, "/api/security-analysis/entity?type=host&value="
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert unsupported == 400
    assert empty == 400


def test_entity_discovery_api_is_offline_honest_and_no_store(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path / "out")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, payload = _request(
            server.server_address, "/api/security-analysis/entities"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload == {
        "mode": "offline",
        "machine_context_available": False,
        "entities": [],
    }


def test_security_analysis_asset_is_packaged_and_responsive():
    index = (STATIC / "index.html").read_text()
    styles = (STATIC / "styles.css").read_text()

    assert '<script src="/static/security_analysis.js"></script>' in index
    for selector in (
        ".analysis-workspace", ".analysis-tabs", ".analysis-browser",
        ".analysis-timeline-list", ".analysis-context-strip",
        ".analysis-entity-discovery", ".analysis-entity-groups",
    ):
        assert selector in styles
    assert "overflow-x: auto" in styles
    assert "@media (max-width: 1100px)" in styles
    assert "@media (max-width: 820px)" in styles
