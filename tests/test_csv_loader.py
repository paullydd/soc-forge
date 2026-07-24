from pathlib import Path

from soc_forge.ingest.windows_security_csv import load_windows_security_csv, load_windows_security_csv_with_diagnostics


def test_load_windows_security_csv(tmp_path: Path):
    csv_file = tmp_path / "security.csv"
    csv_file.write_text(
        """TimeCreated,Id,Message
2026-03-11T10:00:00Z,4720,"A user account was created. Target Account Name: socforge_test"
2026-03-11T10:02:00Z,4732,"A member was added to a security-enabled local group. Group Name: Administrators"
""",
        encoding="utf-8",
    )

    events = load_windows_security_csv(csv_file)

    assert len(events) == 2
    assert events[0]["event_id"] == 4720
    assert events[1]["event_id"] == 4732
    assert "message" in events[0]


def test_windows_security_csv_diagnostics_report_dataset_quality(tmp_path: Path):
    csv_file = tmp_path / "security.csv"
    csv_file.write_text(
        "TimeCreated,Id,Message\n"
        ",not-a-number,Missing timestamp and invalid event id\n"
        "2026-03-11T10:02:00Z,,Missing event id\n",
        encoding="utf-8",
    )

    result = load_windows_security_csv_with_diagnostics(csv_file)
    diagnostics = result.diagnostics_as_dicts()

    assert result.row_count == 2
    assert len(result.events) == 2
    assert result.events[0]["event_id"] == 0
    assert {item["level"] for item in diagnostics} >= {"error", "warning"}
    assert any(item.get("field") == "event_id" for item in diagnostics)
    assert any(item.get("field") == "timestamp" for item in diagnostics)