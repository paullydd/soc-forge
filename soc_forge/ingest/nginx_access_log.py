from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List

# nginx "combined" log format:
# 192.168.128.2 - - [16/Sep/2026:03:10:00 +0000] "GET /.git/HEAD HTTP/1.1" 200 23 "-" "gobuster/3.8.2"
LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<remote_user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)
REQUEST_RE = re.compile(r"^(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>\S+)$")


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
class NginxAccessLogResult:
    events: List[Dict[str, Any]]
    diagnostics: List[IngestDiagnostic] = field(default_factory=list)
    row_count: int = 0

    def diagnostics_as_dicts(self) -> List[Dict[str, Any]]:
        return [diagnostic.to_dict() for diagnostic in self.diagnostics]


def _normalize_timestamp(raw: str) -> str:
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_int(value: str | None) -> int | None:
    if value is None or value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def load_nginx_access_log_with_diagnostics(
    path: str | Path,
    default_host: str = "LINUX-HOST-01",
) -> NginxAccessLogResult:
    input_path = Path(path)
    if not input_path.exists():
        return NginxAccessLogResult(
            events=[],
            diagnostics=[IngestDiagnostic("error", "Nginx access log file not found", field="input_path")],
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

            m = LINE_RE.match(line)
            if not m:
                diagnostics.append(
                    IngestDiagnostic(
                        "warning",
                        "Line did not match the expected nginx combined log format",
                        row=line_number,
                        field="line",
                    )
                )
                continue

            row_count += 1
            timestamp = _normalize_timestamp(m.group("time"))
            status_code = _to_int(m.group("status"))
            bytes_sent = _to_int(m.group("bytes"))
            referrer = m.group("referrer")
            user_agent = m.group("user_agent")
            request = m.group("request")

            event: Dict[str, Any] = {
                "timestamp": timestamp,
                "host": default_host,
                "ip": m.group("ip"),
                "message": request,
            }
            if status_code is not None:
                event["status_code"] = status_code
            if bytes_sent is not None:
                event["bytes_sent"] = bytes_sent
            if referrer and referrer != "-":
                event["referrer"] = referrer
            if user_agent and user_agent != "-":
                event["user_agent"] = user_agent

            req_match = REQUEST_RE.match(request) if request else None
            if req_match is None:
                diagnostics.append(
                    IngestDiagnostic(
                        "info",
                        "Request field did not parse into method/uri/protocol",
                        row=line_number,
                        field="request",
                    )
                )
                events.append(event)
                continue

            event["method"] = req_match.group("method")
            event["uri"] = req_match.group("uri")
            event["protocol"] = req_match.group("protocol")
            events.append(event)

    if row_count == 0:
        diagnostics.append(IngestDiagnostic("warning", "Nginx access log file contains no parsed lines"))

    return NginxAccessLogResult(events=events, diagnostics=diagnostics, row_count=row_count)


def load_nginx_access_log(path: str | Path, default_host: str = "LINUX-HOST-01") -> List[Dict[str, Any]]:
    return load_nginx_access_log_with_diagnostics(path, default_host=default_host).events


def iter_nginx_access_log_events(path: str | Path, default_host: str = "LINUX-HOST-01") -> Iterator[Dict[str, Any]]:
    for event in load_nginx_access_log(path, default_host=default_host):
        yield event
