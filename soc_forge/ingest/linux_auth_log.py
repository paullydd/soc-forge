from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List

# Traditional syslog line, no year: "Sep 16 03:14:07 host sshd[8842]: <msg>"
SYSLOG_LINE_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w.-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# journalctl ISO export: "2026-09-16T03:14:07+0000 host sshd[8842]: <msg>"
ISO_LINE_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w.-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)\s*ssh2$",
    re.IGNORECASE,
)
FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:(?P<invalid>invalid user) )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)\s*ssh2$",
    re.IGNORECASE,
)
INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?$",
    re.IGNORECASE,
)

_MONTH_TO_NUM = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


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
class LinuxAuthLogResult:
    events: List[Dict[str, Any]]
    diagnostics: List[IngestDiagnostic] = field(default_factory=list)
    row_count: int = 0

    def diagnostics_as_dicts(self) -> List[Dict[str, Any]]:
        return [diagnostic.to_dict() for diagnostic in self.diagnostics]


def _normalize_syslog_timestamp(mon: str, day: str, time_str: str, default_year: int | None) -> str:
    month_num = _MONTH_TO_NUM.get(mon[:3].title(), 1)
    year = default_year if default_year is not None else datetime.now(timezone.utc).year
    return f"{year:04d}-{month_num:02d}-{int(day):02d}T{time_str}Z"


def _normalize_iso_timestamp(iso: str) -> str:
    # Leave as-is; already a valid ISO8601 timestamp (with or without an explicit offset).
    return iso


def _parse_outer_line(line: str, default_year: int | None) -> Dict[str, Any] | None:
    m = ISO_LINE_RE.match(line)
    if m:
        return {
            "timestamp": _normalize_iso_timestamp(m.group("iso")),
            "host": m.group("host"),
            "proc": m.group("proc"),
            "pid": m.group("pid"),
            "msg": m.group("msg"),
        }
    m = SYSLOG_LINE_RE.match(line)
    if m:
        return {
            "timestamp": _normalize_syslog_timestamp(m.group("mon"), m.group("day"), m.group("time"), default_year),
            "host": m.group("host"),
            "proc": m.group("proc"),
            "pid": m.group("pid"),
            "msg": m.group("msg"),
        }
    return None


def _parse_inner_message(msg: str) -> Dict[str, Any] | None:
    m = ACCEPTED_RE.match(msg)
    if m:
        return {
            "auth_result": "success",
            "auth_method": m.group("method").lower(),
            "username": m.group("user"),
            "ip": m.group("ip"),
            "invalid_user": False,
        }
    m = FAILED_RE.match(msg)
    if m:
        return {
            "auth_result": "failure",
            "auth_method": m.group("method").lower(),
            "username": m.group("user"),
            "ip": m.group("ip"),
            "invalid_user": m.group("invalid") is not None,
        }
    m = INVALID_USER_RE.match(msg)
    if m:
        return {
            "auth_result": "failure",
            "auth_method": "",
            "username": m.group("user"),
            "ip": m.group("ip"),
            "invalid_user": True,
        }
    return None


def load_linux_auth_log_with_diagnostics(
    path: str | Path,
    default_host: str = "LINUX-HOST-01",
    default_year: int | None = None,
) -> LinuxAuthLogResult:
    input_path = Path(path)
    if not input_path.exists():
        return LinuxAuthLogResult(
            events=[],
            diagnostics=[IngestDiagnostic("error", "Linux auth log file not found", field="input_path")],
            row_count=0,
        )

    events: List[Dict[str, Any]] = []
    diagnostics: List[IngestDiagnostic] = []
    row_count = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            outer = _parse_outer_line(line, default_year)
            if outer is None:
                diagnostics.append(
                    IngestDiagnostic(
                        "warning",
                        "Line did not match a recognized auth log format",
                        row=line_number,
                        field="line",
                    )
                )
                continue

            if not outer["proc"].lower().startswith("sshd"):
                continue

            row_count += 1
            host = outer["host"] or default_host
            pid = int(outer["pid"]) if outer["pid"] else None
            msg = outer["msg"]

            event: Dict[str, Any] = {
                "timestamp": outer["timestamp"],
                "host": host,
                "process_name": "sshd",
                "message": msg,
            }
            if pid is not None:
                event["pid"] = pid

            inner = _parse_inner_message(msg)
            if inner is None:
                diagnostics.append(
                    IngestDiagnostic(
                        "info",
                        "sshd line did not match a known auth event pattern",
                        row=line_number,
                        field="message",
                    )
                )
                events.append(event)
                continue

            event["username"] = inner["username"]
            event["actor"] = inner["username"]
            event["ip"] = inner["ip"]
            event["auth_result"] = inner["auth_result"]
            event["auth_method"] = inner["auth_method"]
            event["invalid_user"] = inner["invalid_user"]
            events.append(event)

    if row_count == 0:
        diagnostics.append(IngestDiagnostic("warning", "Auth log file contains no sshd events"))

    return LinuxAuthLogResult(events=events, diagnostics=diagnostics, row_count=row_count)


def load_linux_auth_log(path: str | Path, default_host: str = "LINUX-HOST-01") -> List[Dict[str, Any]]:
    return load_linux_auth_log_with_diagnostics(path, default_host=default_host).events


def iter_linux_auth_log_events(path: str | Path, default_host: str = "LINUX-HOST-01") -> Iterator[Dict[str, Any]]:
    for event in load_linux_auth_log(path, default_host=default_host):
        yield event
