import json
import threading
from http.client import HTTPConnection
from pathlib import Path

from soc_forge.system_workspace import PlatformComponentStatus, PlatformStatus
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


def _start(tmp_path):
    server = make_server("127.0.0.1", 0, tmp_path / "out")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server, thread):
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def test_reporting_and_system_workspaces_are_reachable_without_sidebar_duplicates():
    index = (STATIC / "index.html").read_text()
    app = (STATIC / "app.js").read_text()

    assert 'data-view="reporting">Reporting' in index
    assert 'data-view="system">System' in index
    assert 'id="reportingView"' in index
    assert 'id="systemView"' in index
    assert '<div class="sidebar-label">Output</div>' not in index
    assert '>Open HTML report</a>' not in index
    assert '>Cases JSON</a>' not in index
    assert '>Alerts JSON</a>' not in index
    assert "reporting: ['Reporting'" in app
    assert "system: ['System'" in app


def test_reporting_has_only_supported_destinations_and_boundaries():
    index = (STATIC / "index.html").read_text()
    source = (STATIC / "reporting_system.js").read_text()

    for tab in ("overview", "reports", "investigation", "executive", "exports"):
        assert f'data-reporting-tab="{tab}"' in index
        assert f'data-reporting-panel="{tab}"' in index
    for text in (
        "Investigation Report ≠ Investigation Handoff",
        "Structured operational transfer remains in the Investigation Workspace",
        "Existing artifacts only",
        "does not transform, regenerate, or create a second Investigation Handoff",
        "Machine context unavailable",
        "Protected evidence values are not revealed",
    ):
        assert text in source
    for fake in ("PDF", "CSV", "AI-generated", "Schedule report", "Email report"):
        assert fake not in source


def test_system_has_supported_read_only_views_and_unknown_semantics():
    index = (STATIC / "index.html").read_text()
    source = (STATIC / "reporting_system.js").read_text()
    api = (ROOT / "soc_forge" / "web" / "app.py").read_text()

    for tab in ("status", "configuration", "health", "storage", "environment", "about"):
        assert f'data-system-tab="{tab}"' in index
        assert f'data-system-panel="{tab}"' in index
    for text in (
        "Required components", "Optional components",
        "UNKNOWN means the state could not be determined",
        "Read-only effective configuration",
        "Asset loadability, not Detection Coverage",
        "Bounded known-path inspection",
        "Bounded Python-native inspection",
    ):
        assert text in source
    assert "SOC-Forge does not execute remediation" in api
    for mutation in (
        "Save configuration", "Reset configuration", "Restart service",
        "Repair repository", "Install package", "Reveal secret",
    ):
        assert mutation not in source


def test_reporting_system_renderer_is_safe_dom_and_packaged():
    index = (STATIC / "index.html").read_text()
    source = (STATIC / "reporting_system.js").read_text()
    styles = (STATIC / "styles.css").read_text()

    assert '<script src="/static/reporting_system.js"></script>' in index
    assert "document.createElement" in source
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    for selector in (
        ".reporting-workspace", ".system-workspace", ".information-facts",
        ".system-status-groups", ".reporting-handoff-boundary",
    ):
        assert selector in styles


def test_reporting_api_is_offline_read_only_and_exposes_supported_artifacts(tmp_path):
    server, thread = _start(tmp_path)
    try:
        status, headers, payload = _request(server.server_address, "/api/reporting")
    finally:
        _stop(server, thread)

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["executive"]["mode"] == "offline"
    assert payload["executive"]["machine_context_available"] is False
    assert [row["filename"] for row in payload["exports"]] == [
        "report.html", "cases.json", "alerts.json", "hunts.json",
        "reconstructions.json",
    ]
    assert payload["reports"] == payload["investigations"] == []


def test_system_api_preserves_unknown_and_masks_bounded_configuration(tmp_path):
    server, thread = _start(tmp_path)
    server.system_workspace.platform_status = lambda: PlatformStatus(
        "unknown",
        (PlatformComponentStatus("runtime", "Runtime", "unknown", "Not determined."),),
    )
    try:
        status, headers, payload = _request(server.server_address, "/api/system")
    finally:
        _stop(server, thread)

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert payload["status"]["overall_state"] == "unknown"
    assert payload["status"]["components"][0]["state"] == "unknown"
    assert all(
        not any(secret in key.lower() for secret in ("password", "secret", "token", "credential", "api_key"))
        for key, _value in payload["configuration"]["values"]
    )
    assert "PATH" not in payload["environment"]
    assert payload["about"]["remediation_boundary"] == "SOC-Forge does not execute remediation."
