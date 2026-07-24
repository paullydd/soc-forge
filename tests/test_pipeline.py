import json

import pytest

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
    assert result.artifacts == {
        "alerts": alerts_path,
        "cases": report_path.parent / "cases.json",
        "hunts": hunts_path,
        "reconstructions": reconstructions_path,
        "report": report_path,
    }
    assert alerts_path.exists()
    assert report_path.exists()
    assert (report_path.parent / "cases.json").exists()
    assert hunts_path.exists()
    assert reconstructions_path.exists()
    assert not (alerts_path.parent / "cases.json").exists()
    assert not (report_path.parent / "reconstructions.json").exists()


def test_run_analysis_file_input_format_override_loads_windows_security_csv(tmp_path):
    csv_path = tmp_path / "security.events"
    csv_path.write_text(
        "TimeCreated,Id,Computer,User,Message\n"
        "2026-07-17T18:26:03Z,4625,WS-LAB-01,alice,Source Network Address: 198.51.100.88\n",
        encoding="utf-8",
    )

    result = run_analysis(
        AnalysisOptions(
            input_path=csv_path,
            input_format="windows-security-csv",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
        )
    )

    assert result.input_path == csv_path
    assert result.input_name == "security.events"
    assert result.event_count == 1
    assert result.events[0]["event_id"] == 4625
    assert result.events[0]["host"] == "WS-LAB-01"
    assert result.events[0]["username"] == "alice"
    assert result.events[0]["ip"] == "198.51.100.88"


def test_run_analysis_file_input_exposes_csv_ingest_diagnostics(tmp_path):
    csv_path = tmp_path / "security.csv"
    csv_path.write_text(
        "TimeCreated,Id,Message\n"
        ",not-a-number,Missing timestamp and invalid event id\n",
        encoding="utf-8",
    )

    result = run_analysis(
        AnalysisOptions(
            input_path=csv_path,
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
        )
    )

    assert result.event_count == 1
    assert result.ingest_diagnostics
    assert any(item["level"] == "error" for item in result.ingest_diagnostics)
    assert any(item.get("field") == "event_id" for item in result.ingest_diagnostics)
    assert any(item.get("field") == "timestamp" for item in result.ingest_diagnostics)

@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("attack_chain", {"events": 5, "alerts": 10, "correlations": 4, "cases": 5, "hunts": 1}),
        ("detection_lab", {"events": 6, "alerts": 8, "correlations": 3, "cases": 3, "hunts": 1}),
    ],
)
def test_run_analysis_for_events_artifact_map_matches_serialized_outputs(tmp_path, scenario, expected):
    events = generate_scenario(scenario)
    events_path = write_events_jsonl(events, tmp_path / f"{scenario}_events.jsonl")

    result = run_analysis_for_events(
        AnalysisOptions(
            events=events,
            input_name=events_path.name,
            output_dir=tmp_path,
            events_path=events_path,
        )
    )

    assert result.event_count == expected["events"]
    assert len(result.alerts) == expected["alerts"]
    assert result.correlations["total"] == expected["correlations"]
    assert len(result.cases) == expected["cases"]
    assert len(result.hunt_findings) == expected["hunts"]
    assert len(result.reconstructions) == expected["cases"]
    assert set(result.artifacts) == {"events", "alerts", "cases", "hunts", "reconstructions", "report"}

    for path in result.artifacts.values():
        assert path.exists(), path

    assert result.artifacts["events"] == events_path
    serialized_alerts = json.loads(result.artifacts["alerts"].read_text(encoding="utf-8"))
    serialized_cases = json.loads(result.artifacts["cases"].read_text(encoding="utf-8"))
    serialized_hunts = json.loads(result.artifacts["hunts"].read_text(encoding="utf-8"))
    serialized_reconstructions = json.loads(result.artifacts["reconstructions"].read_text(encoding="utf-8"))

    assert serialized_alerts == result.alerts
    assert serialized_hunts == result.hunt_findings
    assert serialized_reconstructions == result.reconstructions
    assert [case["case_id"] for case in serialized_cases] == [case["case_id"] for case in result.cases]
    assert [case["title"] for case in serialized_cases] == [case["title"] for case in result.cases]
    assert [case["risk_score"] for case in serialized_cases] == [case["risk_score"] for case in result.cases]
    assert [len(case.get("evidence", [])) for case in serialized_cases] == [len(case.get("evidence", [])) for case in result.cases]
    assert result.artifacts["report"].read_text(encoding="utf-8").startswith("<!doctype html>")
