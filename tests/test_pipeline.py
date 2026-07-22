import json

from soc_forge.pipeline import AnalysisOptions, AnalysisResult, run_analysis, run_analysis_for_events
from soc_forge.simulator import generate_scenario, write_events_jsonl


def test_run_analysis_for_events_detection_lab_matches_current_artifact_shape(tmp_path):
    events = generate_scenario("detection_lab")
    events_path = write_events_jsonl(events, tmp_path / "detection_lab_events.jsonl")

    result = run_analysis_for_events(
        AnalysisOptions(
            events=events,
            input_name=events_path.name,
            output_dir=tmp_path,
            events_path=events_path,
        )
    )

    assert isinstance(result, AnalysisResult)
    assert result.input_name == "detection_lab_events.jsonl"
    assert result.input_path is None
    assert result.output_dir == tmp_path
    assert result.alerts_path == tmp_path / "alerts.json"
    assert result.report_path == tmp_path / "report.html"
    assert result.events_path == events_path
    assert result.event_count == 6
    assert len(result.alerts) == 8
    assert len(result.yaml_alerts) == 5
    assert len(result.legacy_alerts) == 0
    assert result.correlations["total"] == 3
    assert len(result.hunt_findings) == 1
    assert len(result.cases) == 3
    assert len(result.reconstructions) == len(result.cases)
    assert result.risk_summary["level"] == "critical"

    assert result.artifacts["events"] == events_path
    assert result.artifacts["alerts"] == tmp_path / "alerts.json"
    assert result.artifacts["cases"] == tmp_path / "cases.json"
    assert result.artifacts["hunts"] == tmp_path / "hunts.json"
    assert result.artifacts["reconstructions"] == tmp_path / "reconstructions.json"
    assert result.artifacts["report"] == tmp_path / "report.html"

    assert len(json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))) == 8
    assert len(json.loads((tmp_path / "cases.json").read_text(encoding="utf-8"))) == 3
    assert len(json.loads((tmp_path / "hunts.json").read_text(encoding="utf-8"))) == 1
    assert len(json.loads((tmp_path / "reconstructions.json").read_text(encoding="utf-8"))) == 3
    assert (tmp_path / "report.html").exists()


def test_run_analysis_for_events_can_skip_artifact_writes(tmp_path):
    result = run_analysis_for_events(
        AnalysisOptions(
            events=generate_scenario("detection_lab"),
            input_name="detection_lab_events.jsonl",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
        )
    )

    assert len(result.alerts) == 8
    assert len(result.cases) == 3
    assert result.alerts_path is None
    assert result.report_path is None
    assert result.artifacts == {}
    assert not (tmp_path / "alerts.json").exists()
    assert not (tmp_path / "report.html").exists()


def test_run_analysis_file_input_preserves_cli_style_artifact_paths(tmp_path):
    events_path = write_events_jsonl(generate_scenario("brute_force"), tmp_path / "brute_force_events.jsonl")
    alerts_path = tmp_path / "json" / "alerts.json"
    report_path = tmp_path / "html" / "report.html"
    hunts_path = tmp_path / "out" / "hunts.json"
    reconstructions_path = alerts_path.parent / "reconstructions.json"

    result = run_analysis(
        AnalysisOptions(
            input_path=events_path,
            input_name=events_path.name,
            output_dir=report_path.parent,
            alerts_path=alerts_path,
            report_path=report_path,
            cases_output_dir=report_path.parent,
            hunts_path=hunts_path,
            reconstructions_path=reconstructions_path,
            rules_only=True,
        )
    )

    assert result.input_path == events_path
    assert result.input_name == events_path.name
    assert result.alerts_path == alerts_path
    assert result.report_path == report_path
    assert result.cases_output_dir == report_path.parent
    assert result.hunts_path == hunts_path
    assert result.reconstructions_path == reconstructions_path
    assert len(result.alerts) == 10
    assert len(result.legacy_alerts) == 0
    assert result.correlations["total"] == 0
    assert len(result.cases) == 1
    assert result.hunt_findings == []
    assert len(result.reconstructions) == 1
    assert alerts_path.exists()
    assert report_path.exists()
    assert (report_path.parent / "cases.json").exists()
    assert hunts_path.exists()
    assert reconstructions_path.exists()
    assert not (alerts_path.parent / "cases.json").exists()
    assert not (report_path.parent / "reconstructions.json").exists()
