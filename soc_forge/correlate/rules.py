from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha1
from typing import Any, Dict, List


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _cid(*parts: str) -> str:
    raw = "|".join([p for p in parts if p])
    return sha1(raw.encode("utf-8")).hexdigest()[:12]


def correlate_alerts(
    alerts: List[Dict[str, Any]],
    window_minutes: int = 15,
    bruteforce_lockout_enabled: bool = True,
    bruteforce_lockout_severity: str = "critical",
    bruteforce_lockout_score: int = 120,
) -> List[Dict[str, Any]]:
    """
    Correlation Rules (Phase 2 starter):
      - SOCF-CORR-001: Brute force (SOCF-001) + account lockout (SOCF-002) within window
        -> create correlated alert
    """
    # Always keep deterministic ordering
    alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""))

    if not bruteforce_lockout_enabled:
        return alerts_sorted

    window = timedelta(minutes=window_minutes)

    if not bruteforce_lockout_enabled:
        # Sort oldest->newest for correlation scanning
        alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""))

    brute_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    lockouts: List[Dict[str, Any]] = []

    for a in alerts_sorted:
        rid = a.get("rule_id")
        if rid == "SOCF-001":
            ip = (a.get("details", {}) or {}).get("ip", "unknown")
            brute_by_ip.setdefault(ip, []).append(a)
        elif rid == "SOCF-002":
            lockouts.append(a)

    correlated: List[Dict[str, Any]] = []

    # Rule: brute force + lockout close in time
    for lock in lockouts:
        lock_ts = _parse_ts(lock["timestamp"])
        lock_user = (lock.get("details", {}) or {}).get("username", "unknown")
        lock_ip = (lock.get("details", {}) or {}).get("ip")  # might be None

        # Candidate IPs:
        candidate_ips = [lock_ip] if lock_ip else list(brute_by_ip.keys())

        for ip in candidate_ips:
            for brute in brute_by_ip.get(ip, []):
                brute_ts = _parse_ts(brute["timestamp"])
                if abs(lock_ts - brute_ts) <= window:
                    corr_id = _cid("SOCF-CORR-001", ip, lock_user)

                    correlated.append({
                        "rule_id": "SOCF-CORR-001",
                        "severity": bruteforce_lockout_severity,
                        "title": "Brute force + lockout correlation (confirmed credential attack)",
                        "timestamp": max(brute["timestamp"], lock["timestamp"]),
                        "details": {
                            "ip": ip,
                            "username": lock_user,
                            "window_minutes": window_minutes,
                            "evidence": [
                                {"rule_id": brute["rule_id"], "timestamp": brute["timestamp"]},
                                {"rule_id": lock["rule_id"], "timestamp": lock["timestamp"]},
                            ],
                        },
                        "mitre": [
                            {"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"}
                        ],
                        "score": bruteforce_lockout_score,
                        "status": "new",
                        "correlation_id": corr_id,
                    })
                    # Once we correlate this lockout with one brute event for an IP, stop scanning
                    break
            else:
                continue
            break

    # De-duplicate correlated alerts by correlation_id
    seen = set()
    uniq_corr = []
    for c in correlated:
        cid = c.get("correlation_id")
        if cid and cid in seen:
            continue
        if cid:
            seen.add(cid)
        uniq_corr.append(c)

    # Also tag original alerts with correlation_id when they match
    # (Optional / nice for reports)
    for c in uniq_corr:
        ip = c["details"].get("ip")
        user = c["details"].get("username")
        cid = c.get("correlation_id")
        if not cid:
            continue
        for a in alerts_sorted:
            rid = a.get("rule_id")
            if rid in ("SOCF-001", "SOCF-002"):
                d = a.get("details", {}) or {}
                if rid == "SOCF-001" and d.get("ip") == ip:
                    a["correlation_id"] = cid
                if rid == "SOCF-002" and d.get("username") == user:
                    a["correlation_id"] = cid

    return alerts_sorted + uniq_corr
