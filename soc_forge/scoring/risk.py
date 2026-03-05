from __future__ import annotations

from typing import Any, Dict, List, Tuple


SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_max(a: str, b: str) -> str:
    a_l = (a or "").lower()
    b_l = (b or "").lower()
    return a if SEV_RANK.get(a_l, 0) >= SEV_RANK.get(b_l, 0) else b


def _threat_level(score: int) -> str:
    # simple + stable thresholds (tweak later)
    if score >= 180:
        return "critical"
    if score >= 120:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def score_case(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute a case-level score using:
      - base: sum of alert scores (deduped by rule_id+timestamp)
      - boosts: correlation rule presence, plus unique tactic count
      - severity: max severity observed
    Returns a dict you can embed into case header/details.
    """
    # Dedup the same alert appearing twice (common during refactors)
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for a in alerts:
        key = (a.get("rule_id"), a.get("timestamp"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(a)

    base = 0
    max_sev = "low"
    tactics = set()
    corr_rules = []

    for a in uniq:
        base += int(a.get("score", 0) or 0)
        max_sev = _sev_max(max_sev, str(a.get("severity", "low")))

        # Collect tactics from mitre list
        for m in (a.get("mitre") or []):
            t = (m.get("tactic") or "").strip()
            if t:
                tactics.add(t)

        rid = str(a.get("rule_id", ""))
        if rid.startswith("SOCF-CORR"):
            corr_rules.append(rid)

    # boosts
    boost = 0
    reasons: List[str] = []

    if corr_rules:
        boost += 30
        reasons.append(f"Correlation present (+30): {', '.join(sorted(set(corr_rules)))}")

    if len(tactics) >= 2:
        boost += 10 * min(len(tactics) - 1, 4)  # up to +40
        reasons.append(f"Multi-tactic activity (+{10 * min(len(tactics) - 1, 4)}): {', '.join(sorted(tactics))}")

    total = min(base + boost, 400)

    return {
        "base_score": base,
        "boost": boost,
        "case_score": total,
        "case_severity": max_sev,           # max of component alerts
        "case_threat_level": _threat_level(total),
        "tactics": sorted(tactics),
        "reasons": reasons,
        "alert_count": len(uniq),
    }
