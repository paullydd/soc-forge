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
    rdp_schtask_enabled: bool = True,
    rdp_schtask_severity: str = "high",
    rdp_schtask_score: int = 110,
    rdp_new_admin_enabled: bool = True,
    rdp_new_admin_severity: str = "critical",
    rdp_new_admin_score: int = 130,
) -> List[Dict[str, Any]]:
    """
    Correlation Rules (Phase 2 starter):
      - SOCF-CORR-001: Brute force (SOCF-001) + account lockout (SOCF-002) within window
        -> create correlated alert
    """
    # Always keep deterministic ordering
    alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""))

    window = timedelta(minutes=window_minutes)
    correlated: List[Dict[str, Any]] = []

    # -------------------------
    # SOCF-CORR-001 (Phase 2): Brute force + lockout
    # -------------------------
    if bruteforce_lockout_enabled:
        lockouts: List[Dict[str, Any]] = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-002"]
        bruteforces: List[Dict[str, Any]] = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-001"]

        for lock in lockouts:
            lock_ts = _parse_ts(lock["timestamp"])
            lock_user = (lock.get("details", {}) or {}).get("username") or "unknown"
            lock_ip = (lock.get("details", {}) or {}).get("ip")  # may be None/unknown

            for brute in bruteforces:
                brute_ts = _parse_ts(brute["timestamp"])
                if abs(lock_ts - brute_ts) <= window:
                    brute_ip = (brute.get("details", {}) or {}).get("ip")
                    ip = lock_ip or brute_ip or "unknown"

                    corr_id = _cid("SOCF-CORR-001", str(ip), str(lock_user))

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
                    break

    # -------------------------
    # SOCF-CORR-002 (Phase 3): RDP -> Scheduled Task
    # -------------------------
    if rdp_schtask_enabled:
        rdps = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-006"]
        tasks = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-005"]

        for rdp in rdps:
            rdp_ts = _parse_ts(rdp["timestamp"])
            rdp_d = (rdp.get("details", {}) or {})
            rdp_host = rdp_d.get("host") or "unknown"
            rdp_user = rdp_d.get("username") or "unknown"
            rdp_ip = rdp_d.get("ip") or "unknown"

            for task in tasks:
                task_ts = _parse_ts(task["timestamp"])
                task_host = (task.get("details", {}) or {}).get("host") or "unknown"

                if task_host != rdp_host:
                    continue

                if timedelta(0) <= (task_ts - rdp_ts) <= window:
                    corr_id = _cid("SOCF-CORR-002", str(rdp_host), str(rdp_user), str(rdp_ip))

                    correlated.append({
                        "rule_id": "SOCF-CORR-002",
                        "severity": rdp_schtask_severity,
                        "title": "RDP logon followed by scheduled task creation (possible persistence)",
                        "timestamp": task["timestamp"],
                        "details": {
                            "host": rdp_host,
                            "username": rdp_user,
                            "ip": rdp_ip,
                            "window_minutes": window_minutes,
                            "evidence": [
                                {"rule_id": rdp["rule_id"], "timestamp": rdp["timestamp"]},
                                {"rule_id": task["rule_id"], "timestamp": task["timestamp"]},
                            ],
                        },
                        "mitre": [
                            {"tactic": "Persistence", "technique": "Scheduled Task/Job", "id": "T1053"},
                            {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
                        ],
                        "score": rdp_schtask_score,
                        "status": "new",
                        "correlation_id": corr_id,
                    })
                    break

        # -------------------------
    # SOCF-CORR-003 (Phase 3): RDP -> New Admin (Privileged group change)
    # -------------------------
    if rdp_new_admin_enabled:
        rdps = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-006"]
        admins = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-003"]

        for rdp in rdps:
            rdp_ts = _parse_ts(rdp["timestamp"])
            rdp_d = (rdp.get("details", {}) or {})
            rdp_host = rdp_d.get("host") or "unknown"
            rdp_user = rdp_d.get("username") or "unknown"
            rdp_ip = rdp_d.get("ip") or "unknown"

            for adm in admins:
                adm_ts = _parse_ts(adm["timestamp"])
                adm_d = (adm.get("details", {}) or {})
                adm_host = adm_d.get("host") or "unknown"

                if adm_host != rdp_host:
                    continue

                # Require admin change after (or same time) as RDP within window
                if timedelta(0) <= (adm_ts - rdp_ts) <= window:
                    corr_id = _cid("SOCF-CORR-003", str(rdp_host), str(rdp_user), str(rdp_ip))

                    correlated.append({
                        "rule_id": "SOCF-CORR-003",
                        "severity": rdp_new_admin_severity,
                        "title": "RDP logon followed by privileged group change (possible takeover)",
                        "timestamp": adm["timestamp"],
                        "details": {
                            "host": rdp_host,
                            "username": rdp_user,
                            "ip": rdp_ip,
                            "window_minutes": window_minutes,
                            "evidence": [
                                {"rule_id": rdp["rule_id"], "timestamp": rdp["timestamp"]},
                                {"rule_id": adm["rule_id"], "timestamp": adm["timestamp"]},
                            ],
                        },
                        "mitre": [
                            {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
                            {"tactic": "Privilege Escalation", "technique": "Valid Accounts", "id": "T1078"},
                        ],
                        "score": rdp_new_admin_score,
                        "status": "new",
                        "correlation_id": corr_id,
                    })
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
    for c in uniq_corr:
        cid = c.get("correlation_id")
        if not cid:
            continue

        rule_id = c.get("rule_id")

        # --- Tag for SOCF-CORR-001 ---
        if rule_id == "SOCF-CORR-001":
            ip = c["details"].get("ip")
            user = c["details"].get("username")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-001" and d.get("ip") == ip:
                    a["correlation_id"] = cid

                if rid == "SOCF-002" and d.get("username") == user:
                    a["correlation_id"] = cid

        # --- Tag for SOCF-CORR-002 ---
        if rule_id == "SOCF-CORR-002":
            host = c["details"].get("host")
            user = c["details"].get("username")
            ip = c["details"].get("ip")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-006":
                    if d.get("host") == host and d.get("username") == user and d.get("ip") == ip:
                        a["correlation_id"] = cid

                if rid == "SOCF-005":
                    if d.get("host") == host:
                        a["correlation_id"] = cid

        if rule_id == "SOCF-CORR-003":
            host = c["details"].get("host")
            user = c["details"].get("username")
            ip = c["details"].get("ip")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-006":
                    if d.get("host") == host and d.get("username") == user and d.get("ip") == ip:
                        a["correlation_id"] = cid

                if rid == "SOCF-003":
                    if d.get("host") == host:
                        a["correlation_id"] = cid

    return alerts_sorted + uniq_corr
