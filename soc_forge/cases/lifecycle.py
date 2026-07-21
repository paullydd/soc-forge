from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


VALID_CASE_STATUSES = ["New", "Investigating", "Contained", "Closed", "False Positive"]
DEFAULT_OWNER = "Unassigned"
DEFAULT_ACTOR = "analyst"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_status(status: str) -> str:
    if status not in VALID_CASE_STATUSES:
        raise ValueError(f"Invalid case status: {status}")
    return status


def normalize_notes(notes: Any) -> List[Dict[str, Any]]:
    if not notes:
        return []

    if not isinstance(notes, list):
        notes = [notes]

    normalized: List[Dict[str, Any]] = []
    for note in notes:
        if isinstance(note, dict):
            text = str(note.get("text", note.get("note", ""))).strip()
            if not text:
                continue
            normalized.append(
                {
                    "text": text,
                    "author": note.get("author", DEFAULT_ACTOR),
                    "created_at": note.get("created_at", note.get("timestamp")),
                }
            )
        else:
            text = str(note).strip()
            if text:
                normalized.append({"text": text, "author": DEFAULT_ACTOR, "created_at": None})

    return normalized


def build_status_event(
    status: str,
    *,
    changed_at: Optional[str] = None,
    changed_by: str = DEFAULT_ACTOR,
    reason: str = "",
) -> Dict[str, Any]:
    validate_status(status)
    return {
        "status": status,
        "changed_at": changed_at or utc_now(),
        "changed_by": changed_by or DEFAULT_ACTOR,
        "reason": reason,
    }


def ensure_case_lifecycle(
    case: Dict[str, Any],
    *,
    now: Optional[str] = None,
    owner: Optional[str] = None,
) -> Dict[str, Any]:
    timestamp = now or case.get("created_at") or case.get("created") or utc_now()
    if not timestamp:
        timestamp = utc_now()
    status = case.get("status") or "New"
    validate_status(status)
    case["status"] = status

    case.setdefault("owner", owner or DEFAULT_OWNER)
    if not case.get("created_at"):
        case["created_at"] = timestamp
    if not case.get("updated_at"):
        case["updated_at"] = case.get("created_at", timestamp)
    case["notes"] = normalize_notes(case.get("notes", []))

    history = case.get("status_history") or []
    if not isinstance(history, list):
        history = []

    if not history:
        history.append(build_status_event(status, changed_at=case["created_at"], reason="Case created"))
    elif all(event.get("status") != status for event in history if isinstance(event, dict)):
        history.append(build_status_event(status, changed_at=case.get("updated_at") or timestamp))

    case["status_history"] = history
    case.setdefault("evidence", [])
    return case


def change_case_status(
    case: Dict[str, Any],
    status: str,
    *,
    changed_by: str = DEFAULT_ACTOR,
    reason: str = "",
    changed_at: Optional[str] = None,
) -> Dict[str, Any]:
    validate_status(status)
    ensure_case_lifecycle(case, now=changed_at)

    if case.get("status") == status:
        return case

    event = build_status_event(status, changed_at=changed_at, changed_by=changed_by, reason=reason)
    case["status"] = status
    case["updated_at"] = event["changed_at"]
    case.setdefault("status_history", []).append(event)

    header = case.get("header")
    if isinstance(header, dict):
        header["status"] = status

    return case


def assign_case_owner(
    case: Dict[str, Any],
    owner: str,
    *,
    changed_at: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_case_lifecycle(case, now=changed_at)
    clean_owner = owner.strip() if owner else ""
    case["owner"] = clean_owner or DEFAULT_OWNER
    case["updated_at"] = changed_at or utc_now()
    return case


def add_case_note(
    case: Dict[str, Any],
    text: str,
    *,
    author: str = DEFAULT_ACTOR,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    clean_text = text.strip() if text else ""
    if not clean_text:
        return case

    ensure_case_lifecycle(case, now=created_at)
    note = {
        "text": clean_text,
        "author": author or DEFAULT_ACTOR,
        "created_at": created_at or utc_now(),
    }
    case.setdefault("notes", []).append(note)
    case["updated_at"] = note["created_at"]
    return case


def preserve_evidence(case: Dict[str, Any], evidence: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    ensure_case_lifecycle(case)
    existing = case.setdefault("evidence", [])
    seen = {
        (
            item.get("timestamp"),
            item.get("rule_id"),
            item.get("title"),
        )
        for item in existing
        if isinstance(item, dict)
    }

    for item in evidence:
        if not isinstance(item, dict):
            continue
        key = (item.get("timestamp"), item.get("rule_id"), item.get("title"))
        if key in seen:
            continue
        existing.append(dict(item))
        seen.add(key)

    return case
