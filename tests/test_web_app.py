from pathlib import Path

from soc_forge.web.app import build_detection_scorecard, build_summary, load_workspace, run_demo_scenario, safe_artifact_path


def test_build_summary_counts_cases_alerts_and_quality():
    cases = [
        {"case_id": "CASE-1", "title": "Low", "risk_score": 10, "case_quality": {"quality_score": 80}},
        {"case_id": "CASE-2", "title": "High", "risk_score": 300, "case_quality": {"quality_score": 100}},
    ]
    alerts = [
        {"rule_id": "SOCF-011", "title": "PowerShell", "severity": "high", "mitre": [{"tactic": "Execution"}]},
        {"rule_id": "SOCF-CORR-005", "title": "Correlation", "severity": "critical", "mitre": [{"tactic": "Defense Evasion"}]},
    ]

    summary = build_summary(cases, alerts, [], [], Path("out"))

    assert summary["case_count"] == 2
    assert summary["alert_count"] == 2
    assert summary["correlated_alert_count"] == 1
    assert summary["top_case_id"] == "CASE-2"
    assert summary["average_case_quality"] == 90
    assert summary["rule_counts"][0]["rule_id"] in {"SOCF-011", "SOCF-CORR-005"}


def test_load_workspace_sorts_cases_by_risk(tmp_path):
    (tmp_path / "cases.json").write_text('[{"case_id":"CASE-LOW","risk_score":10},{"case_id":"CASE-HIGH","risk_score":300}]', encoding="utf-8")
    (tmp_path / "alerts.json").write_text('[]', encoding="utf-8")
    (tmp_path / "hunts.json").write_text('[]', encoding="utf-8")
    (tmp_path / "reconstructions.json").write_text('[]', encoding="utf-8")

    workspace = load_workspace(tmp_path)

    assert [case["case_id"] for case in workspace["cases"]] == ["CASE-HIGH", "CASE-LOW"]


def test_safe_artifact_path_only_allows_known_outputs():
    out_dir = Path("out")

    assert safe_artifact_path(out_dir, "report.html") == out_dir / "report.html"
    assert safe_artifact_path(out_dir, "../README.md") is None



def test_run_demo_scenario_generates_detection_lab_workspace(tmp_path):
    workspace = run_demo_scenario("detection_lab", tmp_path)

    assert workspace["active_scenario"] == "detection_lab"
    assert workspace["generated_event_count"] == 6
    assert workspace["summary"]["alert_count"] == 8
    assert workspace["summary"]["correlated_alert_count"] == 3
    assert (tmp_path / "alerts.json").exists()
    assert (tmp_path / "cases.json").exists()
    assert (tmp_path / "report.html").exists()



def test_load_workspace_attaches_web_graph(tmp_path):
    (tmp_path / "cases.json").write_text(
        '[{"case_id":"CASE-GRAPH","risk_score":100,"iocs":{"ips":["203.0.113.10"],"users":["alice"],"hosts":["WS-01"]},"alerts":[]}]',
        encoding="utf-8",
    )
    (tmp_path / "alerts.json").write_text("[]", encoding="utf-8")
    (tmp_path / "hunts.json").write_text("[]", encoding="utf-8")
    (tmp_path / "reconstructions.json").write_text("[]", encoding="utf-8")

    workspace = load_workspace(tmp_path)
    graph = workspace["cases"][0]["web_graph"]

    assert graph["summary"]["total_nodes"] == 3
    assert graph["summary"]["total_edges"] >= 2
    assert "203.0.113.10" in graph["nodes"]


def test_detection_scorecard_summarizes_rule_program(tmp_path):
    (tmp_path / "report.html").write_text("<html></html>", encoding="utf-8")
    alerts = [
        {"rule_id": "SOCF-011", "severity": "high"},
        {"rule_id": "SOCF-CORR-007", "severity": "critical"},
    ]

    scorecard = build_detection_scorecard(alerts, [{"case_id": "CASE-1"}], [{"hunt_id": "HUNT-1"}], tmp_path)

    assert scorecard["overall_score"] >= 80
    assert scorecard["grade"] in {"A", "B"}
    assert scorecard["quality_gate"] is True
    assert scorecard["enabled_rule_count"] >= 19
    assert scorecard["coverage"]["tactic_count"] >= 5
    assert scorecard["correlation_alert_count"] == 1
