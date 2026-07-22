from pathlib import Path

import pytest

import soc_forge.web.app as web_app
from soc_forge.web.app import build_detection_scorecard, build_summary, load_workspace, run_demo_scenario, safe_artifact_path


SCENARIO_EXPECTATIONS = {
    "attack_chain": {
        "label": "Attack Chain",
        "events": 5,
        "alerts": 10,
        "correlations": 4,
        "cases": 5,
        "hunts": 1,
    },
    "detection_lab": {
        "label": "Detection Lab",
        "events": 6,
        "alerts": 8,
        "correlations": 3,
        "cases": 3,
        "hunts": 1,
    },
}


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



@pytest.mark.parametrize("scenario,expected", sorted(SCENARIO_EXPECTATIONS.items()))
def test_run_demo_scenario_uses_pipeline_for_supported_scenarios(tmp_path, monkeypatch, scenario, expected):
    calls = []
    results = []
    real_run_analysis = web_app.run_analysis_for_events

    def spy_run_analysis(options):
        calls.append(options)
        result = real_run_analysis(options)
        results.append(result)
        return result

    monkeypatch.setattr(web_app, "run_analysis_for_events", spy_run_analysis)

    workspace = web_app.run_demo_scenario(scenario, tmp_path)

    assert len(calls) == 1
    assert len(results) == 1
    assert calls[0].input_name == f"{scenario}_events.jsonl"
    assert calls[0].output_dir == tmp_path
    assert calls[0].events_path == tmp_path / f"{scenario}_events.jsonl"
    assert len(calls[0].events) == expected["events"]
    assert set(results[0].artifacts) == {"events", "alerts", "cases", "hunts", "reconstructions", "report"}
    assert results[0].artifacts["events"] == tmp_path / f"{scenario}_events.jsonl"
    assert results[0].artifacts["alerts"] == tmp_path / "alerts.json"
    assert results[0].artifacts["cases"] == tmp_path / "cases.json"
    assert results[0].artifacts["hunts"] == tmp_path / "hunts.json"
    assert results[0].artifacts["reconstructions"] == tmp_path / "reconstructions.json"
    assert results[0].artifacts["report"] == tmp_path / "report.html"
    assert workspace["active_scenario"] == scenario
    assert workspace["scenario_label"] == expected["label"]
    assert workspace["generated_event_count"] == expected["events"]
    assert workspace["summary"]["alert_count"] == expected["alerts"]
    assert workspace["summary"]["correlated_alert_count"] == expected["correlations"]
    assert workspace["summary"]["case_count"] == expected["cases"]
    assert workspace["summary"]["hunt_count"] == expected["hunts"]
    assert len(workspace["cases"]) == expected["cases"]
    assert len(workspace["alerts"]) == expected["alerts"]
    assert len(workspace["hunts"]) == expected["hunts"]
    assert len(workspace["reconstructions"]) == expected["cases"]
    assert {"summary", "detection_scorecard", "cases", "alerts", "hunts", "reconstructions"}.issubset(workspace)
    assert (tmp_path / f"{scenario}_events.jsonl").exists()
    assert (tmp_path / "alerts.json").exists()
    assert (tmp_path / "cases.json").exists()
    assert (tmp_path / "hunts.json").exists()
    assert (tmp_path / "reconstructions.json").exists()
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
