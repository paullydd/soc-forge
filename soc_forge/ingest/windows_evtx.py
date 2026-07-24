from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from Evtx.Evtx import Evtx

MAX_EVTX_RECORD_XML_CHARS = 16_384
MAX_MESSAGE_FIELD_CHARS = 512
PLACEHOLDER_VALUES = {"", "-", "N/A", "n/a", "unknown", "UNKNOWN", "::1", "127.0.0.1", "0.0.0.0", "::"}


@dataclass(frozen=True)
class EvtxRecordXml:
    record_number: int
    xml: str
    truncated: bool = False


@dataclass
class WindowsEvtxLoadResult:
    records: List[EvtxRecordXml]
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    record_count: int = 0
    skipped_record_count: int = 0

    def xml_entries(self) -> List[str]:
        return [record.xml for record in self.records]


@dataclass
class WindowsSecurityEvtxResult:
    events: List[Dict[str, Any]]
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    parsed_record_count: int = 0
    skipped_record_count: int = 0

    @property
    def record_count(self) -> int:
        return len(self.events)


def _diagnostic(level: str, message: str, field: str | None = None, row: int | None = None) -> Dict[str, Any]:
    diagnostic: Dict[str, Any] = {"level": level, "message": message}
    if field is not None:
        diagnostic["field"] = field
    if row is not None:
        diagnostic["row"] = row
    return diagnostic


def _bounded_xml(xml: str) -> tuple[str, bool]:
    if len(xml) <= MAX_EVTX_RECORD_XML_CHARS:
        return xml, False
    return xml[:MAX_EVTX_RECORD_XML_CHARS], True


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child(parent: ET.Element | None, name: str) -> ET.Element | None:
    if parent is None:
        return None
    for child in list(parent):
        if _strip_namespace(child.tag) == name:
            return child
    return None


def _text(parent: ET.Element | None, name: str) -> str | None:
    child = _child(parent, name)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def _clean_value(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    if cleaned in PLACEHOLDER_VALUES:
        return None
    return cleaned or None


def _int_or_zero(value: Any) -> int:
    try:
        return int(str(value or "").strip())
    except (TypeError, ValueError):
        return 0


def _normalize_timestamp(value: str | None) -> str:
    timestamp = _clean_value(value)
    if not timestamp:
        return ""
    normalized = timestamp.replace(" ", "T", 1)
    if normalized.endswith("Z"):
        return normalized
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return normalized
    if parsed.tzinfo is None:
        return parsed.isoformat()
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _extract_event_data(root: ET.Element) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for container_name in ("EventData", "UserData"):
        container = _child(root, container_name)
        if container is None:
            continue
        for item in container.iter():
            item_name = _strip_namespace(item.tag)
            if item_name == container_name:
                continue
            key = item.attrib.get("Name") or item.attrib.get("name") or item_name
            value = (item.text or "").strip()
            if key and value:
                data[str(key)] = value
    return data


def _first_event_data(event_data: Dict[str, str], names: tuple[str, ...], allow_placeholders: bool = False) -> str | None:
    for name in names:
        value = event_data.get(name)
        if allow_placeholders:
            if value is not None and str(value).strip() != "":
                return str(value).strip()
        else:
            cleaned = _clean_value(value)
            if cleaned:
                return cleaned
    return None


def _message_from_rendering(root: ET.Element) -> str | None:
    rendering = _child(root, "RenderingInfo")
    message = _text(rendering, "Message")
    return _clean_value(message)


def _fallback_message(provider: str | None, event_id: int, event_data: Dict[str, str]) -> str:
    base = f"{provider} event {event_id}" if provider and event_id else f"Windows event {event_id or 'unknown'}"
    selected_parts = []
    for key in sorted(event_data)[:4]:
        value = event_data[key].replace("\n", " ").strip()
        if len(value) > 80:
            value = value[:77] + "..."
        selected_parts.append(f"{key}={value}")
    if selected_parts:
        base = f"{base}: {', '.join(selected_parts)}"
    return base[:MAX_MESSAGE_FIELD_CHARS]


def normalize_evtx_record_xml(record: EvtxRecordXml) -> tuple[Dict[str, Any] | None, List[Dict[str, Any]], bool]:
    diagnostics: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(record.xml)
    except ET.ParseError:
        return None, [_diagnostic("warning", "Malformed EVTX record XML", field="record_xml", row=record.record_number)], True

    system = _child(root, "System")
    event_id_raw = _text(system, "EventID")
    event_id = _int_or_zero(event_id_raw)
    provider_element = _child(system, "Provider")
    provider = _clean_value(provider_element.attrib.get("Name") if provider_element is not None else None)
    time_created = _child(system, "TimeCreated")
    timestamp = _normalize_timestamp(time_created.attrib.get("SystemTime") if time_created is not None else None)
    host = _clean_value(_text(system, "Computer"))
    channel = _clean_value(_text(system, "Channel"))
    record_id = _int_or_zero(_text(system, "EventRecordID"))
    level = _int_or_zero(_text(system, "Level"))
    task = _int_or_zero(_text(system, "Task"))
    event_data = _extract_event_data(root)

    if not event_id:
        diagnostics.append(_diagnostic("error", "EVTX record is missing an event ID", field="event_id", row=record.record_number))
    if not timestamp:
        diagnostics.append(_diagnostic("warning", "EVTX record is missing a timestamp", field="timestamp", row=record.record_number))
    if not host:
        diagnostics.append(_diagnostic("info", "EVTX record is missing host context", field="host", row=record.record_number))
    if not provider:
        diagnostics.append(_diagnostic("info", "EVTX record is missing provider context", field="provider", row=record.record_number))
    if not channel:
        diagnostics.append(_diagnostic("info", "EVTX record is missing channel context", field="channel", row=record.record_number))

    has_system_content = system is not None and any(_clean_value(value) for value in (event_id_raw, timestamp, host, provider, channel, record_id, level, task))
    has_event_data_content = any(_clean_value(value) for value in event_data.values())
    if not has_system_content and not has_event_data_content:
        diagnostics.append(_diagnostic("warning", "EVTX record produced no useful normalized content", field="record", row=record.record_number))
        return None, diagnostics, True

    actor = _first_event_data(event_data, ("SubjectUserName", "AccountName", "TargetUserName"))
    target_user = _first_event_data(event_data, ("TargetUserName",))
    username = _first_event_data(event_data, ("AccountName", "TargetUserName", "SubjectUserName"))
    ip = _first_event_data(event_data, ("IpAddress", "SourceNetworkAddress", "SourceAddress"))
    dest_ip = _first_event_data(event_data, ("DestinationIp", "DestinationIpAddress", "DestAddress", "DestinationAddress"))
    process_name = _first_event_data(event_data, ("ProcessName", "NewProcessName", "Image"))
    parent_process = _first_event_data(event_data, ("ParentProcessName", "ParentImage"))
    command_line = _first_event_data(event_data, ("CommandLine", "ProcessCommandLine"))
    image_path = _first_event_data(event_data, ("ImagePath", "NewProcessName", "Image"))
    group_name = _first_event_data(event_data, ("GroupName", "TargetGroupName"))

    event: Dict[str, Any] = {
        "timestamp": timestamp,
        "event_id": event_id,
        "message": _message_from_rendering(root) or _fallback_message(provider, event_id, event_data),
        "host": host or "",
        "provider": provider or "",
        "channel": channel or "",
        "record_id": record_id,
        "level": level,
        "task": task,
        "raw": {
            "system": {
                "provider": provider,
                "channel": channel,
                "computer": host,
                "event_record_id": record_id,
                "level": level,
                "task": task,
            },
            "event_data": dict(sorted(event_data.items())),
            "record_number": record.record_number,
            "xml_truncated": record.truncated,
        },
    }

    optional_fields = {
        "actor": actor,
        "target_user": target_user,
        "username": username,
        "ip": ip,
        "dest_ip": dest_ip,
        "logon_type": _first_event_data(event_data, ("LogonType",), allow_placeholders=True),
        "process_name": process_name,
        "parent_process": parent_process,
        "command_line": command_line,
        "image_path": image_path,
        "service_name": _first_event_data(event_data, ("ServiceName",)),
        "service_account": _first_event_data(event_data, ("ServiceAccount", "AccountName")),
        "task_name": _first_event_data(event_data, ("TaskName",)),
        "group_name": group_name,
    }
    for key, value in optional_fields.items():
        if value is not None:
            event[key] = value

    return event, diagnostics, False


def normalize_windows_evtx_records(records: List[EvtxRecordXml], diagnostics: List[Dict[str, Any]] | None = None) -> WindowsSecurityEvtxResult:
    normalized_events: List[Dict[str, Any]] = []
    all_diagnostics = list(diagnostics or [])
    skipped_record_count = 0

    for record in records:
        event, record_diagnostics, skipped = normalize_evtx_record_xml(record)
        all_diagnostics.extend(record_diagnostics)
        if skipped:
            skipped_record_count += 1
            all_diagnostics.append(_diagnostic("warning", "Skipped EVTX record during normalization", field="record", row=record.record_number))
            continue
        if event is not None:
            normalized_events.append(event)

    return WindowsSecurityEvtxResult(
        events=normalized_events,
        diagnostics=all_diagnostics,
        parsed_record_count=len(records),
        skipped_record_count=skipped_record_count,
    )


def load_windows_security_evtx_with_diagnostics(path: str | Path) -> WindowsSecurityEvtxResult:
    result = load_windows_evtx_records(path)
    normalized = normalize_windows_evtx_records(result.records, diagnostics=result.diagnostics)
    normalized.skipped_record_count += result.skipped_record_count
    return normalized


def load_windows_evtx_records(path: str | Path) -> WindowsEvtxLoadResult:
    input_path = Path(path)
    records: List[EvtxRecordXml] = []
    diagnostics: List[Dict[str, Any]] = []
    skipped_record_count = 0

    if not input_path.exists():
        return WindowsEvtxLoadResult(
            records=[],
            diagnostics=[_diagnostic("error", "EVTX file not found", field="input_path")],
            record_count=0,
            skipped_record_count=0,
        )

    try:
        with Evtx(str(input_path)) as log:
            for record_number, record in enumerate(log.records(), start=1):
                try:
                    xml, truncated = _bounded_xml(record.xml())
                    records.append(EvtxRecordXml(record_number=record_number, xml=xml, truncated=truncated))
                except Exception:
                    skipped_record_count += 1
                    diagnostics.append(
                        _diagnostic(
                            "warning",
                            "Unable to extract EVTX record XML",
                            field="record_xml",
                            row=record_number,
                        )
                    )
    except Exception:
        return WindowsEvtxLoadResult(
            records=[],
            diagnostics=[_diagnostic("error", "Unable to parse EVTX file", field="evtx")],
            record_count=0,
            skipped_record_count=0,
        )

    if not records and skipped_record_count == 0:
        diagnostics.append(_diagnostic("warning", "EVTX file contains no records", field="records"))

    return WindowsEvtxLoadResult(
        records=records,
        diagnostics=diagnostics,
        record_count=len(records),
        skipped_record_count=skipped_record_count,
    )