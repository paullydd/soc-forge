import json
from unittest.mock import patch

import pytest

from soc_forge.ingest.windows_evtx import WindowsSecurityEvtxResult
from soc_forge.pipeline import AnalysisOptions, AnalysisResult, InputLoadError, load_events_with_diagnostics, run_analysis, run_analysis_for_events
from soc_forge.simulator import generate_scenario, write_events_jsonl


EVTX_FIXTURE = "tests/fixtures/evtx/issue_38.evtx"


def test_load_events_with_diagnostics_auto_detects_evtx_fixture():
    events, diagnostics = load_events_with_diagnostics(EVTX_FIXTURE)

    assert diagnostics == []
    assert len(events) == 1
    assert events[0]["event_id"] == 4672
    assert events[0]["provider"] == "Microsoft-Windows-Security-Auditing"


def test_run_analysis_file_input_explicit_evtx_format_alias_loads_fixture(tmp_path):
    result = run_analysis(
        AnalysisOptions(
            input_path=EVTX_FIXTURE,
            input_format="evtx",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
            rules_only=True,
        )
    )

    assert result.event_count == 1
    assert result.ingest_diagnostics == []
    assert result.events[0]["event_id"] == 4672
    assert result.alerts == []


def test_run_analysis_file_input_explicit_canonical_evtx_format_loads_fixture(tmp_path):
    result = run_analysis(
        AnalysisOptions(
            input_path=EVTX_FIXTURE,
            input_format="windows-security-evtx",
            output_dir=tmp_path,
            write_outputs=False,
            write_report=False,
            rules_only=True,
        )
    )

    assert result.event_count == 1
    assert result.events[0]["channel"] == "Security"


def test_pipeline_calls_evtx_loader_and_runs_standard_rules(tmp_path):
    evtx_event = {
        "timestamp": "2026-07-17T18:26:03Z",
        "event_id": 4688,
        "message": "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe",
        "host": "WS-LAB-01",
        "username": "alice",
        "process_name": "payload.exe",
        "command_line": "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe",
        "raw": {"event_data": {"CommandLine": "C:\\Users\\alice\\AppData\\Local\\Temp\\payload.exe"}},
    }
    loader_result = WindowsSecurityEvtxResult(
        events=[evtx_event],
        diagnostics=[{"level": "info", "message": "diagnostic proof", "field": "provider"}],
        parsed_record_count=1,
        skipped_record_count=0,
    )

    with patch("soc_forge.pipeline.load_windows_security_evtx_with_diagnostics", return_value=loader_result) as loader:
        result = run_analysis(
            AnalysisOptions(
                input_path=tmp_path / "proof.evtx",
                output_dir=tmp_path,
                write_outputs=False,
                write_report=False,
                rules_only=True,
            )
        )

    loader.assert_called_once_with(tmp_path / "proof.evtx")
    assert result.event_count == 1
    assert result.ingest_diagnostics == loader_result.diagnostics
    assert any(alert.get("rule_id") == "SOCF-012" for alert in result.alerts)


def test_evtx_loader_diagnostics_propagate_to_input_load_error(tmp_path):
    malformed = tmp_path / "bad.evtx"
    malformed.write_text("not an evtx", encoding="utf-8")

    with pytest.raises(InputLoadError) as excinfo:
        run_analysis(
            AnalysisOptions(
                input_path=malformed,
                output_dir=tmp_path,
                write_outputs=False,
                write_report=False,
            )
        )

    assert "No normalized EVTX events were loaded" in str(excinfo.value)
    assert excinfo.value.diagnostics == [{"level": "error", "message": "Unable to parse EVTX file", "field": "evtx"}]


def test_missing_evtx_file_uses_loader_diagnostic(tmp_path):
    missing = tmp_path / "missing.evtx"

    with pytest.raises(InputLoadError) as excinfo:
        load_events_with_diagnostics(missing)

    assert excinfo.value.diagnostics == [{"level": "error", "message": "EVTX file not found", "field": "input_path"}]


def test_evtx_zero_normalized_events_is_not_successful_analysis(tmp_path):
    loader_result = WindowsSecurityEvtxResult(
        events=[],
        diagnostics=[{"level": "warning", "message": "EVTX file contains no records", "field": "records"}],
        parsed_record_count=0,
        skipped_record_count=0,
    )

    with patch("soc_forge.pipeline.load_windows_security_evtx_with_diagnostics", return_value=loader_result):
        with pytest.raises(InputLoadError) as excinfo:
            run_analysis(
                AnalysisOptions(
                    input_path=tmp_path / "empty.evtx",
                    output_dir=tmp_path,
                    write_outputs=False,
                    write_report=False,
                )
            )

    assert "No normalized EVTX events were loaded" in str(excinfo.value)
    assert excinfo.value.diagnostics == loader_result.diagnostics

def test_unsupported_extension_remains_unsupported(tmp_path):
    unsupported = tmp_path / "events.txt"
    unsupported.write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported input format"):
        load_events_with_diagnostics(unsupported)


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
