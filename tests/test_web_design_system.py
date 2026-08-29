from pathlib import Path
import re


ROOT = Path(__file__).parents[1]
STATIC = ROOT / "soc_forge" / "web" / "static"


def test_application_shell_has_grouped_implemented_navigation_and_context():
    index = (STATIC / "index.html").read_text()
    app = (STATIC / "app.js").read_text()

    assert 'aria-label="Primary navigation"' in index
    for group in ("Workspace", "Operations", "Engineering", "Analysis", "Information"):
        assert group in index
    destinations = re.findall(r'data-view="([a-z]+)"', index)
    assert destinations == [
        "overview", "operations", "investigations", "cases", "detection",
        "analysis", "reporting", "system",
    ]
    for destination in destinations:
        assert f'id="{destination}View"' in index
    assert "Coming Soon" not in index
    assert 'id="pageTitle"' in index
    assert 'id="pageDescription"' in index
    assert 'id="sidebarToggle"' in index
    assert 'aria-controls="appSidebar"' in index
    assert 'aria-expanded="false"' in index
    assert "viewMetadata" in app
    assert "setAttribute('aria-current', 'page')" in app
    assert "sidebarToggle.addEventListener('click'" in app


def test_design_system_exposes_shared_semantic_and_layout_contracts():
    styles = (STATIC / "styles.css").read_text()
    for token in (
        "--bg-canvas", "--surface-primary", "--surface-secondary",
        "--border-subtle", "--text-primary", "--text-secondary",
        "--semantic-critical", "--semantic-high", "--semantic-medium",
        "--semantic-low", "--semantic-valid", "--semantic-warning",
        "--semantic-error", "--semantic-info", "--sidebar-width",
        "--content-wide", "--content-reading", "--focus-ring",
    ):
        assert token in styles
    for contract in (
        ".nav-group", ".status-indicator", ".technical-id", ".panel",
        ".metrics", ".pill", ".notice", ".empty-state", ".table-wrap",
        ".context-nav", "button:focus-visible", "tbody tr:hover",
    ):
        assert contract in styles
    assert '@media (max-width: 1100px)' in styles
    assert '@media (max-width: 820px)' in styles
    assert '@media (prefers-reduced-motion: reduce)' in styles
    assert 'table { min-width: 680px; }' in styles


def test_safe_dom_modules_and_authoritative_state_contract_remain_intact():
    safe_modules = (
        "operations_queue.js",
        "investigation_findings.js",
        "investigation_response_actions.js",
        "investigation_summary.js",
        "query_workbench.js",
    )
    for filename in safe_modules:
        source = (STATIC / filename).read_text()
        assert "textContent" in source
        assert "localStorage" not in source
        assert "sessionStorage" not in source
    for filename in (
        "operations_queue.js",
        "investigation_findings.js",
        "investigation_response_actions.js",
        "investigation_summary.js",
    ):
        assert "innerHTML" not in (STATIC / filename).read_text()
    assert "localStorage" not in (STATIC / "app.js").read_text()
    assert "localStorage" not in (STATIC / "investigations.js").read_text()


def test_semantic_statuses_keep_text_labels_and_no_external_assets():
    index = (STATIC / "index.html").read_text()
    styles = (STATIC / "styles.css").read_text()
    assert "Local" in index
    assert "v3.6.1" in index
    assert "http://" not in index
    assert "https://" not in index
    for label in ("critical", "high", "medium", "low"):
        assert f".pill.{label}" in styles
    for label in (
        "response-status-proposed", "response-status-approved",
        "response-status-in_progress", "response-status-completed",
        "response-status-dismissed",
    ):
        assert label in styles
