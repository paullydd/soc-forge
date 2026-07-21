from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from soc_forge.cases.lifecycle import ensure_case_lifecycle
from soc_forge.models import normalize_case


DEFAULT_CASES_PATH = Path("out/cases.json")


def load_cases_file(path: Path | str = DEFAULT_CASES_PATH) -> List[Dict[str, Any]]:
    case_path = Path(path)
    if not case_path.exists():
        return []

    data = json.loads(case_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if isinstance(data.get("cases"), list):
            data = data["cases"]
        else:
            data = [data]

    if not isinstance(data, list):
        return []

    return [normalize_case(case, index) for index, case in enumerate(data, start=1) if isinstance(case, dict)]


def save_cases_file(cases: Iterable[Dict[str, Any]], path: Path | str = DEFAULT_CASES_PATH) -> None:
    case_path = Path(path)
    case_path.parent.mkdir(parents=True, exist_ok=True)
    normalized = [normalize_case(case, index) for index, case in enumerate(cases, start=1)]
    case_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")


def case_has_notes(case: Dict[str, Any]) -> bool:
    ensure_case_lifecycle(case)
    return bool(case.get("notes"))


def filter_cases(cases: Iterable[Dict[str, Any]], filter_name: str, *, current_owner: str = "") -> List[Dict[str, Any]]:
    normalized = [normalize_case(case, index) for index, case in enumerate(cases, start=1)]
    key = (filter_name or "all").strip().lower().replace(" ", "_")

    if key in {"all", ""}:
        return normalized
    if key in {"open", "new"}:
        return [case for case in normalized if case.get("status") in {"New", "Investigating", "Contained"}]
    if key == "high_risk":
        return [case for case in normalized if int(case.get("risk_score", 0) or 0) >= 200]
    if key == "assigned_to_me":
        owner = current_owner.strip().lower()
        return [case for case in normalized if owner and str(case.get("owner", "")).strip().lower() == owner]
    if key == "has_notes":
        return [case for case in normalized if case_has_notes(case)]
    if key == "no_notes":
        return [case for case in normalized if not case_has_notes(case)]
    if key == "closed":
        return [case for case in normalized if case.get("status") == "Closed"]

    return normalized


def find_case_index(cases: List[Dict[str, Any]], selected_case: Dict[str, Any]) -> int | None:
    selected_id = selected_case.get("case_id") or selected_case.get("id")
    for index, case in enumerate(cases):
        case_id = case.get("case_id") or case.get("id")
        if selected_id and case_id == selected_id:
            return index
    return None


def replace_case(cases: List[Dict[str, Any]], updated_case: Dict[str, Any]) -> List[Dict[str, Any]]:
    index = find_case_index(cases, updated_case)
    if index is None:
        cases.append(updated_case)
    else:
        cases[index] = updated_case
    return cases


def sort_cases(cases: Iterable[Dict[str, Any]], sort_name: str) -> List[Dict[str, Any]]:
    normalized = [normalize_case(case, index) for index, case in enumerate(cases, start=1)]
    key = (sort_name or "risk_desc").strip().lower().replace(" ", "_")

    if key == "risk_desc":
        return sorted(normalized, key=lambda case: int(case.get("risk_score", 0) or 0), reverse=True)
    if key == "updated_desc":
        return sorted(normalized, key=lambda case: str(case.get("updated_at", "") or ""), reverse=True)
    if key == "status":
        order = {"New": 0, "Investigating": 1, "Contained": 2, "Closed": 3, "False Positive": 4}
        return sorted(normalized, key=lambda case: (order.get(case.get("status", "New"), 99), str(case.get("title", ""))))
    if key == "owner":
        return sorted(normalized, key=lambda case: (str(case.get("owner", "Unassigned")), str(case.get("title", ""))))
    if key == "title":
        return sorted(normalized, key=lambda case: str(case.get("title", "")))

    return normalized
