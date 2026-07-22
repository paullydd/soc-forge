import json
import sys
from pathlib import Path
from unittest.mock import patch

from soc_forge.cli import detect_bruteforce, main
from soc_forge.report.html_report import build_cases
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


def test_compatibility_imports_remain_available_for_legacy_entry_points():
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
