from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator


def _to_iso_utc(dt_str: str) -> str:
    s = (dt_str or "").strip()
    if not s:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    patterns = [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ]

    for p in patterns:
        try:
            dt = datetime.strptime(s, p).replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    if s.endswith("Z") and "T" in s:
        return s

    return s


def _pick(row: Dict[str, str], *keys: str) -> str:
    for k in keys:
        if k in row and row[k] is not None and str(row[k]).strip() != "":
            return str(row[k]).strip()
    return ""


def iter_windows_security_events(csv_path: Path) -> Iterator[dict]:
    """
    Normalize Event Viewer Security CSV into SOC-Forge JSONL events:
      {"timestamp","event_id","username","ip","host","message",...}
    """
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            dt = _pick(row, "Date and Time", "Date/Time", "TimeCreated", "Time Created", "Timestamp")
            event_id = _pick(row, "Event ID", "EventID", "Id", "Event Id")
            host = _pick(row, "Computer", "MachineName", "Host", "Hostname")
            user = _pick(row, "User", "Account Name", "SubjectUserName", "TargetUserName")
            msg = _pick(row, "Message", "Description", "Details", "General")
            ip = _pick(row, "IpAddress", "IP Address", "Source Network Address", "SourceAddress")

            try:
                eid = int(event_id)
            except Exception:
                continue

            yield {
                "timestamp": _to_iso_utc(dt),
                "event_id": eid,
                "username": user or None,
                "ip": ip or None,
                "host": host or None,
                "message": msg or "",
                "source": "windows-security-csv",
                "raw": row,
            }
