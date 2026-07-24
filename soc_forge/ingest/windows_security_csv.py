from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List

TIMESTAMP_FIELDS = ("TimeCreated", "Date and Time")
EVENT_ID_FIELDS = ("Id", "Event ID")
HOST_FIELDS = ("Computer", "Host")
USER_FIELDS = ("User", "Username")
MESSAGE_FIELD = "Message"


@dataclass
class IngestDiagnostic:
    level: str
    message: str
    row: int | None = None
    field: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"level": self.level, "message": self.message}
        if self.row is not None:
            data["row"] = self.row
        if self.field is not None:
            data["field"] = self.field
        return data


@dataclass
class WindowsSecurityCsvResult:
    events: List[Dict[str, Any]]
    diagnostics: List[IngestDiagnostic] = field(default_factory=list)
    row_count: int = 0

    def diagnostics_as_dicts(self) -> List[Dict[str, Any]]:
        return [diagnostic.to_dict() for diagnostic in self.diagnostics]


def _extract_value(message: str, label: str) -> str | None:
    if not message or label not in message:
        return None
    try:
        tail = message.split(label, 1)[1]
        value = tail.splitlines()[0].strip()
        return value or None
    except Exception:
        return None


def _first_value(row: Dict[str, Any], fields: tuple[str, ...]) -> Any:
    for field_name in fields:
        value = row.get(field_name)
        if value not in (None, ""):
            return value
    return None


def _has_any_field(fieldnames: List[str], candidates: tuple[str, ...]) -> bool:
    return any(field_name in fieldnames for field_name in candidates)


def _normalize_row(row: Dict[str, Any], default_host: str = "WINDOWS-PC") -> Dict[str, Any]:
    message = row.get(MESSAGE_FIELD, "") or ""

    timestamp = _first_value(row, TIMESTAMP_FIELDS) or ""
    event_id_raw = _first_value(row, EVENT_ID_FIELDS) or 0
    host = _first_value(row, HOST_FIELDS) or default_host
    username = _first_value(row, USER_FIELDS)

    try:
        event_id = int(event_id_raw)
    except Exception:
        event_id = 0

    event: Dict[str, Any] = {
        "timestamp": timestamp,
        "event_id": event_id,
        "message": message,
        "host": host,
    }

    if username:
        event["username"] = username
        event["actor"] = username

    # Parse common Windows Security fields from message text
    account_name = _extract_value(message, "Account Name:")
    target_user = _extract_value(message, "Target Account Name:")
    group_name = _extract_value(message, "Group Name:")
    ip = _extract_value(message, "Source Network Address:")

    if account_name and account_name not in {"-", "SYSTEM"}:
        event.setdefault("username", account_name)
        event.setdefault("actor", account_name)

    if target_user:
        event["target_user"] = target_user

    if group_name:
        event["group_name"] = group_name

    if ip and ip != "-":
        event["ip"] = ip

    return event


def _validate_headers(fieldnames: List[str]) -> List[IngestDiagnostic]:
    diagnostics: List[IngestDiagnostic] = []
    if not _has_any_field(fieldnames, TIMESTAMP_FIELDS):
        diagnostics.append(IngestDiagnostic("warning", "CSV is missing a recognized timestamp column", field="TimeCreated"))
    if not _has_any_field(fieldnames, EVENT_ID_FIELDS):
        diagnostics.append(IngestDiagnostic("error", "CSV is missing a recognized event ID column", field="Id"))
    if not _has_any_field(fieldnames, HOST_FIELDS):
        diagnostics.append(IngestDiagnostic("info", "CSV is missing a host column; default host will be used", field="Computer"))
    if MESSAGE_FIELD not in fieldnames:
        diagnostics.append(IngestDiagnostic("info", "CSV is missing a Message column; message text will be empty", field=MESSAGE_FIELD))
    return diagnostics


def _validate_row(row: Dict[str, Any], row_number: int) -> List[IngestDiagnostic]:
    diagnostics: List[IngestDiagnostic] = []
    timestamp = _first_value(row, TIMESTAMP_FIELDS)
    event_id_raw = _first_value(row, EVENT_ID_FIELDS)

    if not timestamp:
        diagnostics.append(IngestDiagnostic("warning", "Row is missing a timestamp", row=row_number, field="timestamp"))

    if event_id_raw in (None, ""):
        diagnostics.append(IngestDiagnostic("error", "Row is missing an event ID", row=row_number, field="event_id"))
    else:
        try:
            int(event_id_raw)
        except Exception:
            diagnostics.append(IngestDiagnostic("error", "Row has a non-numeric event ID", row=row_number, field="event_id"))

    return diagnostics


def load_windows_security_csv_with_diagnostics(path: str | Path, default_host: str = "WINDOWS-PC") -> WindowsSecurityCsvResult:
    path = Path(path)
    events: List[Dict[str, Any]] = []
    diagnostics: List[IngestDiagnostic] = []
    row_count = 0

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        if not fieldnames:
            return WindowsSecurityCsvResult(
                events=[],
                diagnostics=[IngestDiagnostic("error", "CSV file has no header row")],
                row_count=0,
            )

        diagnostics.extend(_validate_headers(fieldnames))
        for row_number, row in enumerate(reader, start=2):
            row_count += 1
            diagnostics.extend(_validate_row(row, row_number))
            events.append(_normalize_row(row, default_host=default_host))

    if row_count == 0:
        diagnostics.append(IngestDiagnostic("warning", "CSV file contains no event rows"))

    return WindowsSecurityCsvResult(events=events, diagnostics=diagnostics, row_count=row_count)


def load_windows_security_csv(path: str | Path, default_host: str = "WINDOWS-PC") -> List[Dict[str, Any]]:
    return load_windows_security_csv_with_diagnostics(path, default_host=default_host).events


def iter_windows_security_events(path: str | Path, default_host: str = "WINDOWS-PC") -> Iterator[Dict[str, Any]]:
    for event in load_windows_security_csv(path, default_host=default_host):
        yield event