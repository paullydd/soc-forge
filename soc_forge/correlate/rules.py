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
    # SOCF-CORR-003: RDP -> Privileged group change
    # -------------------------
    if rdp_new_admin_enabled:
        rdps = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-006"]
        admins = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-003", "SOCF-008"}]
        seen_corr_003 = set()

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

                if not (timedelta(0) <= (adm_ts - rdp_ts) <= window):
                    continue

                corr_id = _cid("SOCF-CORR-003", str(rdp_host), str(rdp_user), str(rdp_ip))
                if corr_id in seen_corr_003:
                    continue
                seen_corr_003.add(corr_id)

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
                        {"tactic": "Privilege Escalation", "technique": "Account Manipulation", "id": "T1098"},
                    ],
                    "score": rdp_new_admin_score,
                    "status": "new",
                    "correlation_id": corr_id,
                })


    # -------------------------
    # SOCF-CORR-004 (Phase 11): New user -> Privileged group assignment
    # -------------------------
    new_users = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-007"]
    priv_changes = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-008"]
    seen_corr_004 = set()

    for u in new_users:
        du = u.get("details", {}) or {}
        u_host = du.get("host") or "unknown"
        u_target = du.get("target_user") or "unknown"
        u_ts = _parse_ts(u["timestamp"])

        for p in priv_changes:
            dp = p.get("details", {}) or {}
            p_host = dp.get("host") or "unknown"
            p_target = dp.get("target_user") or "unknown"
            p_ts = _parse_ts(p["timestamp"])

            if u_host != p_host:
                continue

            if u_target != p_target:
                continue

            # Require privileged group change after account creation within window
            if not (timedelta(0) <= (p_ts - u_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-004", str(u_host), str(u_target))
            if corr_id in seen_corr_004:
                continue
            seen_corr_004.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-004",
                "severity": "critical",
                "title": "New account followed by privileged group assignment",
                "timestamp": p["timestamp"],
                "details": {
                    "host": u_host,
                    "target_user": u_target,
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": u["rule_id"], "timestamp": u["timestamp"]},
                        {"rule_id": p["rule_id"], "timestamp": p["timestamp"]},
                    ],
                    "source_rule_ids": ["SOCF-007", "SOCF-008"],
                },
                "mitre": [
                    {"tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
                    {"tactic": "Privilege Escalation", "technique": "Account Manipulation", "id": "T1098"},
                ],
                "score": 130,
                "status": "new",
                "correlation_id": corr_id,
            })

        # -------------------------
    # SOCF-CORR-005 (Phase 11): New account -> Privileged group -> Log clearing
    # -------------------------
    new_users = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-007"]
    priv_changes = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-008"]
    log_clears = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-009"]
    seen_corr_005 = set()

    for u in new_users:
        du = u.get("details", {}) or {}
        u_host = du.get("host") or "unknown"
        u_target = du.get("target_user") or "unknown"
        u_ts = _parse_ts(u["timestamp"])

        for p in priv_changes:
            dp = p.get("details", {}) or {}
            p_host = dp.get("host") or "unknown"
            p_target = dp.get("target_user") or "unknown"
            p_ts = _parse_ts(p["timestamp"])

            if u_host != p_host:
                continue
            if u_target != p_target:
                continue
            if not (timedelta(0) <= (p_ts - u_ts) <= window):
                continue

            for lc in log_clears:
                ld = lc.get("details", {}) or {}
                lc_host = ld.get("host") or "unknown"
                lc_actor = ld.get("actor") or ld.get("username") or "unknown"
                lc_ts = _parse_ts(lc["timestamp"])

                if lc_host != u_host:
                    continue

                # Require log clearing after privileged group change within window
                if not (timedelta(0) <= (lc_ts - p_ts) <= window):
                    continue

                # Prefer the actor clearing logs to be the new account if present
                if lc_actor not in {"unknown", u_target}:
                    continue

                corr_id = _cid("SOCF-CORR-005", str(u_host), str(u_target))
                if corr_id in seen_corr_005:
                    continue
                seen_corr_005.add(corr_id)

                correlated.append({
                    "rule_id": "SOCF-CORR-005",
                    "severity": "critical",
                    "title": "New privileged account followed by log clearing (possible account abuse)",
                    "timestamp": lc["timestamp"],
                    "details": {
                        "host": u_host,
                        "target_user": u_target,
                        "actor": lc_actor,
                        "window_minutes": window_minutes,
                        "evidence": [
                            {"rule_id": u["rule_id"], "timestamp": u["timestamp"]},
                            {"rule_id": p["rule_id"], "timestamp": p["timestamp"]},
                            {"rule_id": lc["rule_id"], "timestamp": lc["timestamp"]},
                        ],
                        "source_rule_ids": ["SOCF-007", "SOCF-008", "SOCF-009"],
                    },
                    "mitre": [
                        {"tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
                        {"tactic": "Privilege Escalation", "technique": "Account Manipulation", "id": "T1098"},
                        {"tactic": "Defense Evasion", "technique": "Indicator Removal on Host", "id": "T1070"},
                    ],
                    "score": 150,
                    "status": "new",
                    "correlation_id": corr_id,
                })

                
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

        if rule_id == "SOCF-CORR-004":
            host = c["details"].get("host")
            target_user = c["details"].get("target_user")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-007":
                    if d.get("host") == host and d.get("target_user") == target_user:
                        a["correlation_id"] = cid

                if rid == "SOCF-008":
                    if d.get("host") == host and d.get("target_user") == target_user:
                        a["correlation_id"] = cid

                if rule_id == "SOCF-CORR-005":
                    host = c["details"].get("host")
                    target_user = c["details"].get("target_user")

                    for a in alerts_sorted:
                        rid = a.get("rule_id")
                        d = a.get("details", {}) or {}

                        if rid == "SOCF-007":
                            if d.get("host") == host and d.get("target_user") == target_user:
                                a["correlation_id"] = cid

                        if rid == "SOCF-008":
                            if d.get("host") == host and d.get("target_user") == target_user:
                                a["correlation_id"] = cid

                        if rid == "SOCF-009":
                            if d.get("host") == host:
                                a["correlation_id"] = cid


    return alerts_sorted + uniq_corr
