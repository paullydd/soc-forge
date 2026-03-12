from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Iterator, List


def _extract_value(message: str, label: str) -> str | None:
    if not message or label not in message:
        return None
    try:
        tail = message.split(label, 1)[1]
        value = tail.splitlines()[0].strip()
        return value or None
    except Exception:
        return None


def _normalize_row(row: Dict[str, Any], default_host: str = "WINDOWS-PC") -> Dict[str, Any]:
    message = row.get("Message", "") or ""

    timestamp = (
        row.get("TimeCreated")
        or row.get("Date and Time")
        or ""
    )

    event_id_raw = (
        row.get("Id")
        or row.get("Event ID")
        or 0
    )

    host = (
        row.get("Computer")
        or row.get("Host")
        or default_host
    )

    username = (
        row.get("User")
        or row.get("Username")
        or None
    )

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


def load_windows_security_csv(path: str | Path, default_host: str = "WINDOWS-PC") -> List[Dict[str, Any]]:
    path = Path(path)
    events: List[Dict[str, Any]] = []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(_normalize_row(row, default_host=default_host))

    return events


def iter_windows_security_events(path: str | Path, default_host: str = "WINDOWS-PC") -> Iterator[Dict[str, Any]]:
    for event in load_windows_security_csv(path, default_host=default_host):
        yield event