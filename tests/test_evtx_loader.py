from pathlib import Path

from soc_forge.ingest.windows_evtx import (
    MAX_EVTX_RECORD_XML_CHARS,
    EvtxRecordXml,
    load_windows_evtx_records,
    load_windows_security_evtx_with_diagnostics,
    normalize_windows_evtx_records,
)

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

def _event_xml(system: str, event_data: str = "", rendering: str = "") -> str:
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>{system}</System>
{event_data}
{rendering}
</Event>'''


def test_valid_evtx_fixture_produces_one_normalized_event():
    result = load_windows_security_evtx_with_diagnostics(FIXTURE)

    assert result.parsed_record_count == 1
    assert result.skipped_record_count == 0
    assert result.record_count == 1
    assert result.diagnostics == []

    event = result.events[0]
    assert event["event_id"] == 4672
    assert isinstance(event["event_id"], int)
    assert event["timestamp"] == "2017-06-23T05:31:19.787264Z"
    assert event["host"] == "foobar-PC"
    assert event["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event["channel"] == "Security"
    assert event["record_id"] == 17845
    assert event["level"] == 0
    assert event["task"] == 12548
    assert event["actor"] == "foobar"
    assert event["username"] == "foobar"
    assert event["raw"]["event_data"]["SubjectUserName"] == "foobar"
    assert "raw_xml" not in event
    assert "xml" not in event["raw"]


def test_evtx_alias_precedence_and_compact_raw_event_data():
    xml = _event_xml(
        '''<Provider Name="Provider-A" />
<EventID>4624</EventID>
<Level>0</Level>
<Task>12544</Task>
<TimeCreated SystemTime="2026-07-17T18:26:03.000000+00:00" />
<EventRecordID>42</EventRecordID>
<Channel>Security</Channel>
<Computer>WS-LAB-01</Computer>''',
        '''<EventData>
<Data Name="SubjectUserName">alice</Data>
<Data Name="TargetUserName">bob</Data>
<Data Name="AccountName">charlie</Data>
<Data Name="IpAddress">198.51.100.88</Data>
<Data Name="DestinationIpAddress">203.0.113.10</Data>
<Data Name="LogonType">10</Data>
<Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentProcessName">explorer.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data>
<Data Name="ImagePath">C:\\Windows\\PSEXESVC.EXE</Data>
<Data Name="ServiceName">TestService</Data>
<Data Name="TaskName">\\Microsoft\\Windows\\Test</Data>
<Data Name="TargetGroupName">Administrators</Data>
<Data Name="UnmappedField">kept</Data>
</EventData>''',
    )

    result = normalize_windows_evtx_records([EvtxRecordXml(record_number=7, xml=xml)])
    event = result.events[0]

    assert result.diagnostics == []
    assert event["actor"] == "alice"
    assert event["target_user"] == "bob"
    assert event["username"] == "charlie"
    assert event["ip"] == "198.51.100.88"
    assert event["dest_ip"] == "203.0.113.10"
    assert event["logon_type"] == "10"
    assert event["process_name"] == "C:\\Windows\\System32\\cmd.exe"
    assert event["parent_process"] == "explorer.exe"
    assert event["command_line"] == "cmd.exe /c whoami"
    assert event["image_path"] == "C:\\Windows\\PSEXESVC.EXE"
    assert event["service_name"] == "TestService"
    assert event["service_account"] == "charlie"
    assert event["task_name"] == "\\Microsoft\\Windows\\Test"
    assert event["group_name"] == "Administrators"
    assert event["raw"]["event_data"]["UnmappedField"] == "kept"


def test_evtx_identity_fallbacks_when_only_one_identity_exists():
    xml = _event_xml(
        '''<Provider Name="Provider-A" />
<EventID>4720</EventID>
<TimeCreated SystemTime="2026-07-17T18:26:03+00:00" />
<Channel>Security</Channel>
<Computer>WS-LAB-01</Computer>''',
        '''<EventData><Data Name="TargetUserName">new-user</Data></EventData>''',
    )

    event = normalize_windows_evtx_records([EvtxRecordXml(record_number=1, xml=xml)]).events[0]

    assert event["actor"] == "new-user"
    assert event["target_user"] == "new-user"
    assert event["username"] == "new-user"


def test_evtx_placeholder_network_values_are_not_promoted():
    xml = _event_xml(
        '''<Provider Name="Provider-A" />
<EventID>4624</EventID>
<TimeCreated SystemTime="2026-07-17T18:26:03+00:00" />
<Channel>Security</Channel>
<Computer>WS-LAB-01</Computer>''',
        '''<EventData>
<Data Name="IpAddress">-</Data>
<Data Name="DestinationIpAddress">127.0.0.1</Data>
</EventData>''',
    )

    event = normalize_windows_evtx_records([EvtxRecordXml(record_number=1, xml=xml)]).events[0]

    assert "ip" not in event
    assert "dest_ip" not in event
    assert event["raw"]["event_data"]["IpAddress"] == "-"


def test_evtx_missing_required_fields_produce_bounded_diagnostics():
    xml = _event_xml("<Level>4</Level>")

    result = normalize_windows_evtx_records([EvtxRecordXml(record_number=3, xml=xml)])

    assert result.skipped_record_count == 0
    fields = {item.get("field") for item in result.diagnostics}
    levels = {item.get("field"): item.get("level") for item in result.diagnostics}
    assert {"event_id", "timestamp", "host", "provider", "channel"}.issubset(fields)
    assert levels["event_id"] == "error"
    assert levels["timestamp"] == "warning"
    assert levels["host"] == "info"
    assert "Traceback" not in str(result.diagnostics)


def test_evtx_malformed_record_xml_is_skipped_without_crashing():
    valid = _event_xml(
        '''<Provider Name="Provider-A" />
<EventID>4624</EventID>
<TimeCreated SystemTime="2026-07-17T18:26:03+00:00" />
<Channel>Security</Channel>
<Computer>WS-LAB-01</Computer>'''
    )

    result = normalize_windows_evtx_records(
        [
            EvtxRecordXml(record_number=1, xml="<Event><System>"),
            EvtxRecordXml(record_number=2, xml=valid),
        ]
    )

    assert result.parsed_record_count == 2
    assert result.skipped_record_count == 1
    assert len(result.events) == 1
    assert any(item.get("message") == "Malformed EVTX record XML" for item in result.diagnostics)
    assert any(item.get("message") == "Skipped EVTX record during normalization" for item in result.diagnostics)


def test_evtx_message_prefers_rendered_message_then_deterministic_fallback():
    rendered_xml = _event_xml(
        '''<Provider Name="Provider-A" />
<EventID>1</EventID>
<TimeCreated SystemTime="2026-07-17T18:26:03+00:00" />
<Channel>Application</Channel>
<Computer>HOST1</Computer>''',
        rendering='''<RenderingInfo><Message>Rendered message text</Message></RenderingInfo>''',
    )
    fallback_xml = _event_xml(
        '''<Provider Name="Provider-B" />
<EventID>2</EventID>
<TimeCreated SystemTime="2026-07-17T18:26:03+00:00" />
<Channel>Application</Channel>
<Computer>HOST1</Computer>''',
        '''<EventData><Data Name="B">two</Data><Data Name="A">one</Data></EventData>''',
    )

    result = normalize_windows_evtx_records(
        [EvtxRecordXml(record_number=1, xml=rendered_xml), EvtxRecordXml(record_number=2, xml=fallback_xml)]
    )

    assert result.events[0]["message"] == "Rendered message text"
    assert result.events[1]["message"] == "Provider-B event 2: A=one, B=two"


def test_evtx_no_useful_content_is_skipped():
    result = normalize_windows_evtx_records([EvtxRecordXml(record_number=1, xml="<Event />")])

    assert result.events == []
    assert result.skipped_record_count == 1
    assert any(item.get("message") == "EVTX record produced no useful normalized content" for item in result.diagnostics)