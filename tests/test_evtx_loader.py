from pathlib import Path

from soc_forge.ingest.windows_evtx import MAX_EVTX_RECORD_XML_CHARS, load_windows_evtx_records

FIXTURE = Path(__file__).parent / "fixtures" / "evtx" / "issue_38.evtx"


def test_valid_evtx_fixture_opens_successfully():
    result = load_windows_evtx_records(FIXTURE)

    assert result.diagnostics == []
    assert result.skipped_record_count == 0
    assert result.record_count == 1


def test_valid_evtx_fixture_returns_plausible_record_xml():
    result = load_windows_evtx_records(FIXTURE)

    assert len(result.records) == 1
    record = result.records[0]
    assert record.record_number == 1
    assert record.xml.strip().startswith("<Event")
    assert "<System>" in record.xml
    assert "<EventID" in record.xml
    assert len(record.xml) <= MAX_EVTX_RECORD_XML_CHARS
    assert record.truncated is False
    assert result.xml_entries() == [record.xml]


def test_malformed_evtx_input_fails_with_controlled_diagnostic(tmp_path):
    malformed = tmp_path / "not.evtx"
    malformed.write_text("this is not an evtx file", encoding="utf-8")

    result = load_windows_evtx_records(malformed)

    assert result.records == []
    assert result.record_count == 0
    assert result.skipped_record_count == 0
    assert result.diagnostics == [{"level": "error", "message": "Unable to parse EVTX file", "field": "evtx"}]
    assert "Traceback" not in str(result.diagnostics)
    assert str(malformed) not in str(result.diagnostics)


def test_missing_evtx_file_fails_with_controlled_diagnostic(tmp_path):
    missing = tmp_path / "missing.evtx"

    result = load_windows_evtx_records(missing)

    assert result.records == []
    assert result.record_count == 0
    assert result.skipped_record_count == 0
    assert result.diagnostics == [{"level": "error", "message": "EVTX file not found", "field": "input_path"}]
    assert "Traceback" not in str(result.diagnostics)
    assert str(missing) not in str(result.diagnostics)