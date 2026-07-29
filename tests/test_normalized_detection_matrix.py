import csv
import json
from pathlib import Path

from soc_forge.ingest.windows_evtx import EvtxRecordXml, normalize_windows_evtx_records
from soc_forge.pipeline import AnalysisOptions, run_analysis, run_analysis_for_events


def _event_xml(event_id: int, timestamp: str, event_data: dict[str, str]) -> str:
    data_xml = "".join(
        f'<Data Name="{name}">{value}</Data>'
        for name, value in event_data.items()
    )
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon" />
<EventID>{event_id}</EventID>
<TimeCreated SystemTime="{timestamp}" />
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>WS-LAB-01</Computer>
</System>
<EventData>{data_xml}</EventData>
</Event>'''


def test_csv_identity_chain_reaches_correlations_cases_and_artifacts(tmp_path):
    csv_path = tmp_path / "identity-chain.csv"
    fieldnames = ["TimeCreated", "Id", "Computer", "User", "Message"]
    rows = [
        {
            "TimeCreated": "2026-07-17T12:00:00Z",
            "Id": 4720,
            "Computer": "DC1",
            "User": "admin01",
            "Message": "Account Name: admin01\nTarget Account Name: svc-backup",
        },
        {
            "TimeCreated": "2026-07-17T12:05:00Z",
            "Id": 4732,
            "Computer": "DC1",
            "User": "admin01",
            "Message": (
                "Account Name: admin01\n"
                "Target Account Name: svc-backup\n"
                "Group Name: Administrators"
            ),
        },
        {
            "TimeCreated": "2026-07-17T12:07:00Z",
            "Id": 1102,
            "Computer": "DC1",
            "User": "svc-backup",
            "Message": "Account Name: svc-backup\nThe audit log was cleared.",
        },
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    output_dir = tmp_path / "csv-out"
    events_path = output_dir / "normalized_events.json"
    result = run_analysis(
        AnalysisOptions(
            input_path=csv_path,
            input_format="windows-security-csv",
            output_dir=output_dir,
            events_path=events_path,
            rules_only=True,
        )
    )

    rule_ids = {alert["rule_id"] for alert in result.alerts}
    assert {"SOCF-007", "SOCF-008", "SOCF-009"}.issubset(rule_ids)
    assert {"SOCF-CORR-004", "SOCF-CORR-005"}.issubset(rule_ids)
    assert result.correlations["total"] == 2
    assert result.events[1]["target_user"] == "svc-backup"
    assert result.events[1]["group_name"] == "Administrators"
    assert result.cases
    assert len(result.reconstructions) == len(result.cases)

    assert set(result.artifacts) == {
        "alerts",
        "cases",
        "events",
        "hunts",
        "reconstructions",
        "report",
    }
    assert all(path.exists() for path in result.artifacts.values())
    assert len(json.loads(result.artifacts["alerts"].read_text())) == len(result.alerts)
    assert len(json.loads(result.artifacts["cases"].read_text())) == len(result.cases)
    assert len(json.loads(result.artifacts["events"].read_text())) == 3


def test_evtx_process_credential_chain_reaches_pipeline_and_artifacts(tmp_path):
    records = [
        EvtxRecordXml(
            record_number=1,
            xml=_event_xml(
                1,
                "2026-07-17T12:00:00Z",
                {
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -nop -enc SQBFAFgA",
                    "ParentImage": r"C:\Windows\explorer.exe",
                    "User": "LAB\\alice",
                },
            ),
        ),
        EvtxRecordXml(
            record_number=2,
            xml=_event_xml(
                10,
                "2026-07-17T12:03:00Z",
                {
                    "SourceImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "TargetImage": r"C:\Windows\System32\lsass.exe",
                    "User": "LAB\\alice",
                },
            ),
        ),
        EvtxRecordXml(
            record_number=3,
            xml=_event_xml(
                11,
                "2026-07-17T12:05:00Z",
                {
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "TargetFilename": (
                        r"C:\Users\alice\AppData\Local\Google\Chrome\User Data"
                        r"\Default\Login Data"
                    ),
                    "User": "LAB\\alice",
                },
            ),
        ),
    ]

    normalized = normalize_windows_evtx_records(records)

    assert normalized.diagnostics == []
    assert normalized.skipped_record_count == 0
    assert normalized.events[1]["target_process"].endswith("lsass.exe")
    assert normalized.events[2]["file_path"].endswith("Login Data")
    assert normalized.events[2]["target_filename"].endswith("Login Data")
    assert all(event["username"] == "LAB\\alice" for event in normalized.events)

    output_dir = tmp_path / "evtx-out"
    result = run_analysis_for_events(
        AnalysisOptions(
            events=normalized.events,
            input_name="sysmon-process-credential.evtx",
            output_dir=output_dir,
            rules_only=True,
            ingest_diagnostics=normalized.diagnostics,
        )
    )

    rule_ids = {alert["rule_id"] for alert in result.alerts}
    assert {"SOCF-011", "SOCF-014", "SOCF-015"}.issubset(rule_ids)
    assert {"SOCF-CORR-007", "SOCF-CORR-008"}.issubset(rule_ids)
    assert result.correlations["total"] == 2
    assert result.cases
    assert len(result.reconstructions) == len(result.cases)
    assert set(result.artifacts) == {
        "alerts",
        "cases",
        "hunts",
        "reconstructions",
        "report",
    }
    assert all(path.exists() for path in result.artifacts.values())
    assert len(json.loads(result.artifacts["alerts"].read_text())) == len(result.alerts)
