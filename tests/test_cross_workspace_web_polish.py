from pathlib import Path


ROOT = Path(__file__).parents[1]
STATIC = ROOT / "soc_forge" / "web" / "static"


def _source(name):
    return (STATIC / name).read_text()


def test_shared_metric_contract_separates_labels_and_values():
    reporting = _source("reporting_system.js")
    styles = _source("styles.css")

    assert "infoNode('span', label, 'metric-label')" in reporting
    assert "infoNode('strong', value, 'metric-value')" in reporting
    assert ".metric, .information-metric, .analysis-metric, .detection-metric" in styles
    assert ".metric-label, .metric-value { display: block; }" in styles


def test_primary_workspace_tabs_expose_keyboard_and_panel_relationships():
    index = _source("index.html")
    modules = {
        "investigation": _source("investigations.js"),
        "detection": _source("detection_workspace.js"),
        "analysis": _source("security_analysis.js"),
        "reporting": _source("reporting_system.js"),
        "system": _source("reporting_system.js"),
    }

    for workspace in ("detection", "analysis", "reporting", "system"):
        assert f'class="{workspace}-tabs" role="tablist"' in index
        assert f'data-{workspace}-tab=' in index
        assert f'data-{workspace}-panel=' in index
    for source in set(modules.values()):
        assert "aria-selected" in source
        assert "aria-controls" in source
        assert "aria-labelledby" in source
        assert "role', 'tabpanel" in source
        assert "ArrowRight" in source and "ArrowLeft" in source
        assert "Home" in source and "End" in source


def test_human_readable_utc_is_presentation_only_and_preserves_exact_value():
    app = _source("app.js")
    reporting = _source("reporting_system.js")

    assert "function formatUtcTimestamp" in app
    assert "getUTCDate" in app and "getUTCHours" in app
    assert "node.dateTime = String(value)" in app
    assert "node.title = String(value)" in app
    assert "formatUtcTimestamp(report.updated_at" in reporting
    assert "modified_at" in reporting and "infoTime(" in reporting


def test_status_messages_and_responsive_release_contracts_remain_explicit():
    index = _source("index.html")
    styles = _source("styles.css")
    reporting = _source("reporting_system.js")
    analysis = _source("security_analysis.js")
    operations = _source("operations_queue.js")

    assert index.count('role="status"') >= 7
    assert index.count('aria-live="polite"') >= 4
    assert "UNKNOWN means the state could not be determined" in reporting
    assert "OFFLINE is a valid durable-state view" in analysis
    assert "This does not mean there are no alerts or investigations" in operations
    assert '@media (max-width: 560px)' in styles
    assert "overflow-wrap: anywhere" in styles
    assert '[role="tabpanel"][hidden]' in styles


def test_narrow_sidebar_can_be_dismissed_without_a_pointer():
    app = _source("app.js")

    assert "event.key !== 'Escape'" in app
    assert "sidebar.classList.remove('open')" in app
    assert "sidebarToggle?.focus()" in app
