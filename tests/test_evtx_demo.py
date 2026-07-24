import json
from collections import Counter
from pathlib import Path

from soc_forge.pipeline import AnalysisOptions, run_analysis

DEMO_EVTX = Path(__file__).parent / "fixtures" / "evtx" / "system_service_demo.evtx"


def test_real_evtx_service_demo_produces_explainable_investigation(tmp_path):
    normalized_events_path = tmp_path / "normalized_events.json"

    result = run_analysis(
        AnalysisOptions(
            input_path=DEMO_EVTX,
            output_dir=tmp_path,
            events_path=normalized_events_path,
        )
    )

    event_ids = Counter(event.get("event_id") for event in result.events)
    rule_ids = Counter(alert.get("rule_id") for alert in result.alerts)
    service_events = [event for event in result.events if event.get("event_id") == 7045]
    psexec_alerts = [alert for alert in result.alerts if alert.get("rule_id") == "SOCF-016"]

    assert result.event_count == 1601
    assert result.ingest_diagnostics == []
    assert event_ids[7045] == 12
    assert event_ids[7036] >= 1000
    assert any(event.get("service_name") == "PsExec" for event in service_events)
    assert any(event.get("image_path") == "%SystemRoot%\\PSEXESVC.EXE" for event in service_events)
    assert any(event.get("service_account") == "LocalSystem" for event in service_events)

    assert len(result.alerts) == 16
    assert rule_ids["SOCF-004"] == 12
    assert rule_ids["SOCF-016"] == 4
    assert psexec_alerts
    assert psexec_alerts[0]["details"]["service_name"] == "PsExec"
    assert psexec_alerts[0]["details"]["image_path"] == "%SystemRoot%\\PSEXESVC.EXE"

    assert len(result.hunt_findings) == 13
    assert len(result.cases) == 1
    assert result.cases[0]["title"] == "PsExec-style service execution"
    assert result.cases[0]["risk_score"] >= 90
    assert len(result.reconstructions) == 1

    assert result.artifacts["alerts"] == tmp_path / "alerts.json"
    assert result.artifacts["cases"] == tmp_path / "cases.json"
    assert result.artifacts["reconstructions"] == tmp_path / "reconstructions.json"
    assert result.artifacts["report"] == tmp_path / "report.html"
    assert result.artifacts["events"] == normalized_events_path

    assert len(json.loads(result.artifacts["alerts"].read_text(encoding="utf-8"))) == 16
    assert len(json.loads(result.artifacts["cases"].read_text(encoding="utf-8"))) == 1
    assert len(json.loads(result.artifacts["events"].read_text(encoding="utf-8"))) == 1601
    assert result.artifacts["report"].read_text(encoding="utf-8").startswith("<!doctype html>")