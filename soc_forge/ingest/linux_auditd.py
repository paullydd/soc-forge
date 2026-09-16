from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

# "node=<host> type=SYSCALL msg=audit(1757990400.123:4821): arch=c000003e ... pid=4820 comm="tar" exe="/usr/bin/tar" ..."
RECORD_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+"
    r"msg=audit\((?P<epoch>\d+)\.(?P<msec>\d+):(?P<serial>\d+)\):\s*(?P<kv>.*)$"
)
KV_RE = re.compile(r'(\w+(?:\[\d+\])?)=("(?:[^"\\]|\\.)*"|\S*)')
UID_NAME_RE = re.compile(r"^(\d+)\((\S+)\)$")


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
class LinuxAuditdResult:
    events: List[Dict[str, Any]]
    diagnostics: List[IngestDiagnostic] = field(default_factory=list)
    parsed_record_count: int = 0

    @property
    def event_count(self) -> int:
        return len(self.events)

    def diagnostics_as_dicts(self) -> List[Dict[str, Any]]:
        return [diagnostic.to_dict() for diagnostic in self.diagnostics]


def _parse_kv(kv_tail: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for key, raw_value in KV_RE.findall(kv_tail):
        if raw_value.startswith('"') and raw_value.endswith('"') and len(raw_value) >= 2:
            value = raw_value[1:-1]
        else:
            value = raw_value
        result[key] = value
    return result


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _reassemble_command_line(execve: Dict[str, str]) -> Tuple[str, bool]:
    argc = _to_int(execve.get("argc")) or 0
    args: List[str] = []
    has_continuation = False
    for i in range(argc):
        direct_key = f"a{i}"
        if direct_key in execve:
            args.append(execve[direct_key])
            continue
        parts: List[str] = []
        j = 0
        while f"a{i}[{j}]" in execve:
            parts.append(execve[f"a{i}[{j}]"])
            j += 1
        if parts:
            has_continuation = True
            args.append("".join(parts))
        else:
            args.append("")
    return " ".join(args), has_continuation


def load_linux_auditd_with_diagnostics(path: str | Path, default_host: str = "LINUX-HOST-01") -> LinuxAuditdResult:
    input_path = Path(path)
    if not input_path.exists():
        return LinuxAuditdResult(
            events=[],
            diagnostics=[IngestDiagnostic("error", "Linux auditd log file not found", field="input_path")],
            parsed_record_count=0,
        )

    diagnostics: List[IngestDiagnostic] = []
    parsed_record_count = 0

    # Group raw records by their shared audit id (epoch, serial) rather than by line
    # adjacency: concurrent syscalls interleave their record lines in a real audit.log,
    # so position-based pairing of SYSCALL/EXECVE lines would be wrong.
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str]] = []

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            m = RECORD_RE.match(line)
            if not m:
                diagnostics.append(
                    IngestDiagnostic(
                        "warning",
                        "Line did not match a recognized audit record format",
                        row=line_number,
                        field="line",
                    )
                )
                continue

            parsed_record_count += 1
            rec_id = (m.group("epoch"), m.group("serial"))
            if rec_id not in groups:
                groups[rec_id] = {"types": {}, "epoch": m.group("epoch"), "msec": m.group("msec"), "node": None}
                order.append(rec_id)
            record = groups[rec_id]
            record["types"][m.group("type")] = _parse_kv(m.group("kv"))
            if m.group("node") and not record["node"]:
                record["node"] = m.group("node")

    events: List[Dict[str, Any]] = []
    for rec_id in order:
        group = groups[rec_id]
        types = group["types"]
        syscall = types.get("SYSCALL")
        execve = types.get("EXECVE")

        if syscall is None:
            # No SYSCALL record for this id (e.g. an EXECVE record with no paired
            # SYSCALL line seen) - not enough information to build a normalized event.
            continue

        if execve is None:
            diagnostics.append(
                IngestDiagnostic(
                    "info",
                    "SYSCALL record has no matching EXECVE record; skipped (not a process-exec event)",
                    field="EXECVE",
                )
            )
            continue

        epoch_i = _to_int(group["epoch"]) or 0
        timestamp = (
            datetime.fromtimestamp(epoch_i, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            + f".{group['msec']}Z"
        )
        host = group.get("node") or default_host

        pid = _to_int(syscall.get("pid"))
        ppid = _to_int(syscall.get("ppid"))
        comm = syscall.get("comm") or ""
        exe = syscall.get("exe")

        username = None
        uid_val = None
        uid_raw = syscall.get("uid")
        if uid_raw:
            name_match = UID_NAME_RE.match(uid_raw)
            if name_match:
                uid_val, username = name_match.group(1), name_match.group(2)
            else:
                uid_val = uid_raw

        command_line, has_continuation = _reassemble_command_line(execve)
        if has_continuation:
            diagnostics.append(
                IngestDiagnostic(
                    "warning",
                    "EXECVE argument may be truncated/split across continuation fields",
                    field="command_line",
                )
            )

        event: Dict[str, Any] = {
            "timestamp": timestamp,
            "host": host,
            "process_name": comm,
            "command_line": command_line,
        }
        if pid is not None:
            event["pid"] = pid
        if ppid is not None:
            event["ppid"] = ppid
        if exe:
            event["exe"] = exe
        if username:
            event["username"] = username
            event["actor"] = username
        elif uid_val is not None:
            event["uid"] = uid_val

        event["message"] = f"execve pid={pid} exe={exe}: {command_line}"
        events.append(event)

    if not events and parsed_record_count > 0:
        diagnostics.append(IngestDiagnostic("warning", "Auditd log file contains no execve (SYSCALL+EXECVE) events"))

    return LinuxAuditdResult(events=events, diagnostics=diagnostics, parsed_record_count=parsed_record_count)


def load_linux_auditd(path: str | Path, default_host: str = "LINUX-HOST-01") -> List[Dict[str, Any]]:
    return load_linux_auditd_with_diagnostics(path, default_host=default_host).events


def iter_linux_auditd_events(path: str | Path, default_host: str = "LINUX-HOST-01") -> Iterator[Dict[str, Any]]:
    for event in load_linux_auditd(path, default_host=default_host):
        yield event
