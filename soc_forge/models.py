from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from hashlib import sha1
from typing import Any, Dict, Iterable, List, Optional

from soc_forge.cases.lifecycle import VALID_CASE_STATUSES, ensure_case_lifecycle, preserve_evidence


CASE_STATUSES = VALID_CASE_STATUSES


@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    timestamp: str
    details: dict
    mitre: list
    score: int = 0
    status: str = "new"
    correlation_id: Optional[str] = None


def alert_to_dict(alert: Any) -> Dict[str, Any]:
    """Return the canonical dictionary shape used by the pipeline."""
    if isinstance(alert, dict):
        data = dict(alert)
    elif is_dataclass(alert):
        data = asdict(alert)
    else:
        data = {
            "rule_id": getattr(alert, "rule_id", ""),
            "severity": getattr(alert, "severity", "low"),
            "title": getattr(alert, "title", "Untitled Alert"),
            "timestamp": getattr(alert, "timestamp", ""),
            "details": getattr(alert, "details", {}) or {},
            "mitre": getattr(alert, "mitre", []) or [],
            "score": getattr(alert, "score", 0) or 0,
            "status": getattr(alert, "status", "new"),
            "correlation_id": getattr(alert, "correlation_id", None),
        }

    data.setdefault("rule_id", "")
    data.setdefault("severity", "low")
    data.setdefault("title", "Untitled Alert")
    data.setdefault("timestamp", "")
    data.setdefault("details", {})
    data.setdefault("mitre", [])
    data.setdefault("score", 0)
    data.setdefault("status", "new")
    data.setdefault("correlation_id", None)

    if not isinstance(data["details"], dict):
        data["details"] = {}
    if not isinstance(data["mitre"], list):
        data["mitre"] = [data["mitre"]]

    data["score"] = int(data.get("score") or 0)
    return data


def normalize_alerts(alerts: Iterable[Any]) -> List[Dict[str, Any]]:
    return [alert_to_dict(alert) for alert in alerts]


def build_case_id(correlation_id: str, index: int = 1) -> str:
    if correlation_id and correlation_id != "UNCORRELATED":
        digest = sha1(correlation_id.encode("utf-8")).hexdigest()[:8].upper()
        return f"CASE-{digest}"
    return f"CASE-{index:03d}"


def normalize_case(case: Dict[str, Any], index: int = 1) -> Dict[str, Any]:
    """Add stable top-level case fields while preserving existing nested report data."""
    normalized = dict(case)
    header = normalized.get("header", {}) or {}
    details = header.get("details", {}) or {}
    case_risk = details.get("case_risk", {}) or {}
    correlation_id = normalized.get("correlation_id") or header.get("correlation_id") or "UNCORRELATED"

    normalized.setdefault("case_id", build_case_id(str(correlation_id), index))
    normalized.setdefault("id", normalized["case_id"])
    normalized.setdefault("title", header.get("title", "Untitled Case"))
    normalized.setdefault("status", "New")
    normalized.setdefault("created_at", header.get("timestamp", ""))
    normalized.setdefault("severity", case_risk.get("case_severity", header.get("severity", "low")))
    normalized.setdefault("risk_score", int(case_risk.get("case_score", header.get("score", 0)) or 0))
    normalized.setdefault("summary", details.get("analyst_summary", ""))
    normalized.setdefault("case_quality", details.get("case_quality", normalized.get("case_quality", {})))
    normalized.setdefault("executive_summary", normalized.get("case_quality", {}).get("executive_summary", normalized.get("summary", "")))
    normalized.setdefault("containment_guidance", normalized.get("case_quality", {}).get("containment_guidance", []))
    normalized.setdefault("indicators", details.get("iocs", normalized.get("iocs", {})))
    normalized.setdefault("mitre", case_risk.get("tactics", []))
    normalized.setdefault("items", normalized.get("alerts", []))

    header.setdefault("case_id", normalized["case_id"])
    header.setdefault("status", normalized["status"])
    header.setdefault("risk_score", normalized["risk_score"])
    normalized["header"] = header

    ensure_case_lifecycle(normalized, now=normalized.get("created_at"))
    preserve_evidence(normalized, normalized.get("evidence", []))

    return normalized
