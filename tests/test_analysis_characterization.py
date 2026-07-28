import json
import sys
from pathlib import Path
from unittest.mock import patch

from soc_forge.cli import main
from soc_forge.rules.legacy import detect_bruteforce
from soc_forge.cases.builder import build_cases
from soc_forge.simulator import generate_scenario, write_events_jsonl
from soc_forge.web.app import run_demo_scenario


REPO_ROOT = Path(__file__).resolve().parents[1]


def _link_package_into_workdir(workdir: Path) -> None:
    (workdir / "soc_forge").symlink_to(REPO_ROOT / "soc_forge", target_is_directory=True)


def test_cli_detection_lab_analysis_outputs_current_artifact_shape(tmp_path, monkeypatch):
    _link_package_into_workdir(tmp_path)
    events_path = write_events_jsonl(generate_scenario("detection_lab"), tmp_path / "detection_lab_events.jsonl")
    alerts_path = tmp_path / "alerts.json"
    report_path = tmp_path / "report.html"

    monkeypatch.chdir(tmp_path)
    argv = [
        "soc-forge",
        "--input",
        str(events_path),
        "--out",
        str(alerts_path),
        "--html",
        str(report_path),
    ]

    with patch.object(sys, "argv", argv):
        assert main() is None

    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    cases = json.loads((tmp_path / "cases.json").read_text(encoding="utf-8"))
    hunts = json.loads((tmp_path / "out" / "hunts.json").read_text(encoding="utf-8"))
    reconstructions = json.loads((tmp_path / "reconstructions.json").read_text(encoding="utf-8"))

    assert len(alerts) == 8
    assert sum(1 for alert in alerts if str(alert.get("rule_id", "")).startswith("SOCF-CORR")) == 3
    assert len(cases) == 3
    assert len(hunts) == 1
    assert len(reconstructions) == len(cases)
    assert report_path.exists()


def test_web_detection_lab_demo_outputs_current_workspace_shape(tmp_path):
    workspace = run_demo_scenario("detection_lab", tmp_path)

    assert workspace["active_scenario"] == "detection_lab"
    assert workspace["scenario_label"] == "Detection Lab"
    assert workspace["generated_event_count"] == 6
    assert workspace["summary"]["alert_count"] == 8
    assert workspace["summary"]["correlated_alert_count"] == 3
    assert workspace["summary"]["case_count"] == 3
    assert workspace["summary"]["hunt_count"] == 1
    assert len(workspace["reconstructions"]) == len(workspace["cases"])
    assert (tmp_path / "alerts.json").exists()
    assert (tmp_path / "cases.json").exists()
    assert (tmp_path / "hunts.json").exists()
    assert (tmp_path / "reconstructions.json").exists()
    assert (tmp_path / "report.html").exists()


def test_cli_rules_only_custom_paths_and_write_events_writes_normalized_events(tmp_path, monkeypatch, capsys):
    _link_package_into_workdir(tmp_path)
    events_path = write_events_jsonl(generate_scenario("password_spray"), tmp_path / "password_spray_events.jsonl")
    alerts_path = tmp_path / "json" / "alerts_rules_only.json"
    report_path = tmp_path / "html" / "report_rules_only.html"
    normalized_events_path = tmp_path / "normalized_events.json"

    monkeypatch.chdir(tmp_path)
    argv = [
        "soc-forge",
        "--input",
        str(events_path),
        "--out",
        str(alerts_path),
        "--html",
        str(report_path),
        "--rules-only",
        "--write-events",
        str(normalized_events_path),
    ]

    with patch.object(sys, "argv", argv):
        assert main() is None

    output = capsys.readouterr().out
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    cases = json.loads((report_path.parent / "cases.json").read_text(encoding="utf-8"))
    hunts = json.loads((tmp_path / "out" / "hunts.json").read_text(encoding="utf-8"))
    reconstructions = json.loads((alerts_path.parent / "reconstructions.json").read_text(encoding="utf-8"))

    assert len(alerts) == 1
    assert sum(1 for alert in alerts if alert.get("rule_id") == "SOCF-001") == 0
    assert sum(1 for alert in alerts if str(alert.get("rule_id", "")).startswith("SOCF-CORR")) == 0
    assert len(cases) == 1
    assert hunts == []
    assert len(reconstructions) == len(cases)
    assert report_path.exists()
    normalized_events = json.loads(normalized_events_path.read_text(encoding="utf-8"))
    assert len(normalized_events) == 9
    assert normalized_events[0]["event_id"] == 4625
    assert not (alerts_path.parent / "cases.json").exists()
    assert not (report_path.parent / "reconstructions.json").exists()
    assert "HUNT RESULTS" in output
    assert "No hunt findings." in output
    assert "RISK SUMMARY" in output
    assert "Saved alerts to:" in output
    assert "Saved HTML report to:" in output
    assert "Correlated alerts:" in output




def test_cli_prints_csv_ingest_diagnostics(tmp_path, monkeypatch, capsys):
    _link_package_into_workdir(tmp_path)
    csv_path = tmp_path / "security.csv"
    csv_path.write_text(
        "TimeCreated,Id,Message\n"
        ",not-a-number,Missing timestamp and invalid event id\n",
        encoding="utf-8",
    )
    alerts_path = tmp_path / "alerts.json"
    report_path = tmp_path / "report.html"

    monkeypatch.chdir(tmp_path)
    argv = [
        "soc-forge",
        "--input",
        str(csv_path),
        "--out",
        str(alerts_path),
        "--html",
        str(report_path),
        "--rules-only",
    ]

    with patch.object(sys, "argv", argv):
        assert main() is None

    output = capsys.readouterr().out
    assert "INGEST DIAGNOSTICS" in output
    assert "ERROR:" in output
    assert "field=event_id" in output
    assert "field=timestamp" in output



def test_cli_accepts_evtx_input_and_writes_existing_outputs(tmp_path, monkeypatch, capsys):
    _link_package_into_workdir(tmp_path)
    evtx_path = REPO_ROOT / "tests" / "fixtures" / "evtx" / "issue_38.evtx"
    alerts_path = tmp_path / "alerts.json"
    report_path = tmp_path / "report.html"

    monkeypatch.chdir(tmp_path)
    argv = [
        "soc-forge",
        "--input",
        str(evtx_path),
        "--out",
        str(alerts_path),
        "--html",
        str(report_path),
        "--format",
        "windows-security-evtx",
        "--rules-only",
    ]

    with patch.object(sys, "argv", argv):
        assert main() is None

    output = capsys.readouterr().out
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    cases = json.loads((tmp_path / "cases.json").read_text(encoding="utf-8"))

    assert alerts == []
    assert cases == []
    assert report_path.exists()
    assert "Saved alerts to:" in output
    assert "Saved HTML report to:" in output


def test_cli_prints_bounded_evtx_diagnostics_for_malformed_input(tmp_path, monkeypatch, capsys):
    _link_package_into_workdir(tmp_path)
    malformed = tmp_path / "bad.evtx"
    malformed.write_text("not an evtx", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    argv = [
        "soc-forge",
        "--input",
        str(malformed),
        "--out",
        str(tmp_path / "alerts.json"),
        "--html",
        str(tmp_path / "report.html"),
    ]

    with patch.object(sys, "argv", argv):
        assert main() == 1

    output = capsys.readouterr().out
    assert "INGEST DIAGNOSTICS" in output
    assert "ERROR:" in output
    assert "field=evtx" in output
    assert "Unable to parse EVTX file" in output
    assert "No normalized EVTX events were loaded" in output
    assert "Traceback" not in output
    assert str(malformed) not in output


def test_core_owner_imports_remain_available_for_legacy_detector_and_case_builder():
    alerts = detect_bruteforce(
        [
            {
                "timestamp": f"2026-02-27T21:0{i}:00Z",
                "event_id": 4625,
                "username": "bob",
                "ip": "10.0.0.5",
                "host": "WIN10",
            }
            for i in range(8)
        ],
        threshold=8,
        window_minutes=10,
    )
    cases = build_cases(
        [
            {
                "rule_id": "SOCF-011",
                "severity": "high",
                "score": 70,
                "title": "Suspicious PowerShell execution",
                "timestamp": "2026-07-17T18:26:03Z",
                "details": {"host": "WS-LAB-01", "username": "alice"},
                "mitre": [{"tactic": "Execution", "technique": "PowerShell", "id": "T1059.001"}],
            }
        ],
        "compatibility.jsonl",
    )

    assert alerts[0].rule_id == "SOCF-001"
    assert alerts[0].details["ip"] == "10.0.0.5"
    assert cases[0]["case_id"].startswith("CASE-")
    assert cases[0]["case_quality"]["quality_score"] == 85
