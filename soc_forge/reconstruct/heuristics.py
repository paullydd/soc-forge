from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


TACTIC_ORDER = {
    "Reconnaissance": 1,
    "Resource Development": 2,
    "Initial Access": 3,
    "Execution": 4,
    "Persistence": 5,
    "Privilege Escalation": 6,
    "Defense Evasion": 7,
    "Credential Access": 8,
    "Discovery": 9,
    "Lateral Movement": 10,
    "Collection": 11,
    "Command and Control": 12,
    "Exfiltration": 13,
    "Impact": 14,
}


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def time_delta_minutes(ts1: Optional[str], ts2: Optional[str]) -> Optional[float]:
    a = parse_ts(ts1)
    b = parse_ts(ts2)
    if not a or not b:
        return None
    return (b - a).total_seconds() / 60.0


def tactic_progression_ok(a: Optional[str], b: Optional[str]) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    av = TACTIC_ORDER.get(a)
    bv = TACTIC_ORDER.get(b)
    if av is None or bv is None:
        return False
    return bv >= av


def score_link(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []

    if a.get("src_ip") and a.get("src_ip") == b.get("src_ip"):
        score += 0.35
        reasons.append("same src_ip")

    if a.get("username") and a.get("username") == b.get("username"):
        score += 0.30
        reasons.append("same username")

    if a.get("host") and a.get("host") == b.get("host"):
        score += 0.20
        reasons.append("same host")

    delta = time_delta_minutes(a.get("ts"), b.get("ts"))
    if delta is not None and 0 <= delta <= 30:
        score += 0.20
        reasons.append(f"within {delta:.1f} minutes")

    if tactic_progression_ok(a.get("tactic"), b.get("tactic")):
        score += 0.20
        reasons.append("plausible tactic progression")

    if a.get("rule_id") == "SOCF-001" and b.get("rule_id") == "SOCF-006":
        score += 0.20
        reasons.append("failed authentication followed by RDP success")

    if a.get("rule_id") == "SOCF-006" and b.get("rule_id") in {"SOCF-004", "SOCF-005"}:
        score += 0.20
        reasons.append("remote access followed by persistence behavior")

    return min(score, 1.0), reasons
