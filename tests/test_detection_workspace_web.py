from pathlib import Path


ROOT = Path(__file__).parents[1]
STATIC = ROOT / "soc_forge" / "web" / "static"


def test_detection_workspace_has_supported_reachable_destinations():
    index = (STATIC / "index.html").read_text()
    app = (STATIC / "app.js").read_text()

    assert 'data-view="detection"' in index
    assert 'id="detectionView"' in index
    for tab in ("overview", "alerts", "rules", "attack", "health"):
        assert f'data-detection-tab="{tab}"' in index
        assert f'data-detection-panel="{tab}"' in index
    assert "Detection Scorecard</button>" not in index
    assert 'data-view="alerts"' not in index
    assert "detection: ['Detection'" in app


def test_detection_renderer_is_safe_dom_and_preserves_textual_semantics():
    source = (STATIC / "detection_workspace.js").read_text()

    assert "document.createElement" in source
    assert "textContent" in source
    assert "replaceChildren" in source
    assert "innerHTML" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    for severity in ("critical", "high", "medium", "low"):
        assert severity in source
    assert "Machine-generated detection alert" in source
    assert "Deterministic loaded-rule metadata" in source


def test_detection_coverage_observation_and_explainability_remain_distinct():
    source = (STATIC / "detection_workspace.js").read_text()

    assert "Detection Coverage" in source
    assert "Observed ATT&CK Activity" in source
    assert "do not prove attacker intent" in source
    assert "they are not observed activity" in source
    assert "Why this rule fires" in source
    assert "Match conditions" in source
    assert "Contributing current alerts" in source
    assert "Open Rule Explainability" in source
    for prohibited in ("Enable Rule", "Disable Rule", "Edit Rule", "Execute remediation"):
        assert prohibited not in source


def test_detection_static_asset_is_packaged_and_responsive():
    index = (STATIC / "index.html").read_text()
    styles = (STATIC / "styles.css").read_text()

    assert '<script src="/static/detection_workspace.js"></script>' in index
    for selector in (
        ".detection-workspace", ".detection-tabs", ".detection-browser",
        ".detection-attack-grid", ".detection-health-grid",
    ):
        assert selector in styles
    assert "overflow-x: auto" in styles
    assert "@media (max-width: 1100px)" in styles
    assert "@media (max-width: 820px)" in styles
