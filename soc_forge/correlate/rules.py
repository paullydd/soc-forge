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


def _details(alert: Dict[str, Any]) -> Dict[str, Any]:
    details = alert.get("details", {}) or {}
    return details if isinstance(details, dict) else {}


def _field(alert: Dict[str, Any], *names: str) -> str:
    details = _details(alert)
    for name in names:
        value = details.get(name) or alert.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return "unknown"

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

                
    # -------------------------
    # SOCF-CORR-006: Office -> script interpreter
    # -------------------------
    office_scripts = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-013"]
    suspicious_shells = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-011"]
    seen_corr_006 = set()

    for office in office_scripts:
        office_ts = _parse_ts(office["timestamp"])
        office_host = _field(office, "host")
        office_user = _field(office, "username", "actor")
        parent = _field(office, "parent_process")
        child = _field(office, "process_name")

        for shell in suspicious_shells:
            shell_ts = _parse_ts(shell["timestamp"])
            shell_host = _field(shell, "host")
            shell_user = _field(shell, "username", "actor")

            if office_host != shell_host:
                continue
            if office_user != "unknown" and shell_user != "unknown" and office_user != shell_user:
                continue
            if not (timedelta(0) <= (shell_ts - office_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-006", office_host, office_user, parent, child)
            if corr_id in seen_corr_006:
                continue
            seen_corr_006.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-006",
                "severity": "critical",
                "title": "Office spawned suspicious script interpreter (possible malicious document)",
                "timestamp": shell["timestamp"],
                "details": {
                    "host": office_host,
                    "username": office_user,
                    "parent_process": parent,
                    "process_name": child,
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": office["rule_id"], "timestamp": office["timestamp"]},
                        {"rule_id": shell["rule_id"], "timestamp": shell["timestamp"]},
                    ],
                    "source_rule_ids": ["SOCF-013", "SOCF-011"],
                },
                "mitre": [
                    {"tactic": "Execution", "technique": "User Execution: Malicious File", "id": "T1204.002"},
                    {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
                ],
                "score": 145,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-007: Script execution -> credential dumping
    # -------------------------
    script_alerts = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-011", "SOCF-013"}]
    cred_dumps = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-014"]
    seen_corr_007 = set()

    for script in script_alerts:
        script_ts = _parse_ts(script["timestamp"])
        script_host = _field(script, "host")
        script_user = _field(script, "username", "actor")

        for dump in cred_dumps:
            dump_ts = _parse_ts(dump["timestamp"])
            dump_host = _field(dump, "host")
            dump_user = _field(dump, "username", "actor")

            if script_host != dump_host:
                continue
            if script_user != "unknown" and dump_user != "unknown" and script_user != dump_user:
                continue
            if not (timedelta(0) <= (dump_ts - script_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-007", script_host, script_user)
            if corr_id in seen_corr_007:
                continue
            seen_corr_007.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-007",
                "severity": "critical",
                "title": "Suspicious script execution followed by credential dumping",
                "timestamp": dump["timestamp"],
                "details": {
                    "host": script_host,
                    "username": script_user,
                    "target_process": _field(dump, "target_process"),
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": script["rule_id"], "timestamp": script["timestamp"]},
                        {"rule_id": dump["rule_id"], "timestamp": dump["timestamp"]},
                    ],
                    "source_rule_ids": [script["rule_id"], "SOCF-014"],
                },
                "mitre": [
                    {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
                    {"tactic": "Credential Access", "technique": "OS Credential Dumping: LSASS Memory", "id": "T1003.001"},
                ],
                "score": 170,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-008: Suspicious process -> browser credential store access
    # -------------------------
    suspicious_processes = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-011", "SOCF-012", "SOCF-013"}]
    browser_creds = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-015"]
    seen_corr_008 = set()

    for proc in suspicious_processes:
        proc_ts = _parse_ts(proc["timestamp"])
        proc_host = _field(proc, "host")
        proc_user = _field(proc, "username", "actor")

        for browser in browser_creds:
            browser_ts = _parse_ts(browser["timestamp"])
            browser_host = _field(browser, "host")
            browser_user = _field(browser, "username", "actor")

            if proc_host != browser_host:
                continue
            if proc_user != "unknown" and browser_user != "unknown" and proc_user != browser_user:
                continue
            if not (timedelta(0) <= (browser_ts - proc_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-008", proc_host, proc_user)
            if corr_id in seen_corr_008:
                continue
            seen_corr_008.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-008",
                "severity": "critical",
                "title": "Suspicious process followed by browser credential store access",
                "timestamp": browser["timestamp"],
                "details": {
                    "host": proc_host,
                    "username": proc_user,
                    "file_path": _field(browser, "file_path", "target_filename"),
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": proc["rule_id"], "timestamp": proc["timestamp"]},
                        {"rule_id": browser["rule_id"], "timestamp": browser["timestamp"]},
                    ],
                    "source_rule_ids": [proc["rule_id"], "SOCF-015"],
                },
                "mitre": [
                    {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
                    {"tactic": "Credential Access", "technique": "Credentials from Web Browsers", "id": "T1555.003"},
                ],
                "score": 155,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-009: RDP -> PsExec-style service execution
    # -------------------------
    rdps = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-006"]
    psexec_services = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-016"]
    seen_corr_009 = set()

    for rdp in rdps:
        rdp_ts = _parse_ts(rdp["timestamp"])
        rdp_host = _field(rdp, "host")
        rdp_user = _field(rdp, "username", "actor")
        rdp_ip = _field(rdp, "ip", "src_ip")

        for svc in psexec_services:
            svc_ts = _parse_ts(svc["timestamp"])
            svc_host = _field(svc, "host")
            svc_user = _field(svc, "username", "actor")

            if rdp_host != svc_host:
                continue
            if rdp_user != "unknown" and svc_user != "unknown" and rdp_user != svc_user:
                continue
            if not (timedelta(0) <= (svc_ts - rdp_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-009", rdp_host, rdp_user, rdp_ip)
            if corr_id in seen_corr_009:
                continue
            seen_corr_009.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-009",
                "severity": "critical",
                "title": "RDP logon followed by PsExec-style service execution",
                "timestamp": svc["timestamp"],
                "details": {
                    "host": rdp_host,
                    "username": rdp_user,
                    "ip": rdp_ip,
                    "service_name": _field(svc, "service_name"),
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": rdp["rule_id"], "timestamp": rdp["timestamp"]},
                        {"rule_id": svc["rule_id"], "timestamp": svc["timestamp"]},
                    ],
                    "source_rule_ids": ["SOCF-006", "SOCF-016"],
                },
                "mitre": [
                    {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
                    {"tactic": "Execution", "technique": "System Services", "id": "T1569.002"},
                ],
                "score": 165,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-010: WMI execution -> suspicious script/LOLBin
    # -------------------------
    wmi_alerts = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-017"]
    follow_on_execution = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-011", "SOCF-018"}]
    seen_corr_010 = set()

    for wmi in wmi_alerts:
        wmi_ts = _parse_ts(wmi["timestamp"])
        wmi_host = _field(wmi, "host")
        wmi_user = _field(wmi, "username", "actor")

        for exec_alert in follow_on_execution:
            exec_ts = _parse_ts(exec_alert["timestamp"])
            exec_host = _field(exec_alert, "host")
            exec_user = _field(exec_alert, "username", "actor")

            if wmi_host != exec_host:
                continue
            if wmi_user != "unknown" and exec_user != "unknown" and wmi_user != exec_user:
                continue
            if not (timedelta(0) <= (exec_ts - wmi_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-010", wmi_host, wmi_user)
            if corr_id in seen_corr_010:
                continue
            seen_corr_010.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-010",
                "severity": "critical",
                "title": "WMI execution followed by suspicious command execution",
                "timestamp": exec_alert["timestamp"],
                "details": {
                    "host": wmi_host,
                    "username": wmi_user,
                    "process_name": _field(exec_alert, "process_name"),
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": wmi["rule_id"], "timestamp": wmi["timestamp"]},
                        {"rule_id": exec_alert["rule_id"], "timestamp": exec_alert["timestamp"]},
                    ],
                    "source_rule_ids": ["SOCF-017", exec_alert["rule_id"]],
                },
                "mitre": [
                    {"tactic": "Execution", "technique": "Windows Management Instrumentation", "id": "T1047"},
                    {"tactic": "Defense Evasion", "technique": "System Binary Proxy Execution", "id": "T1218"},
                ],
                "score": 155,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-011: Credential access -> archive staging
    # -------------------------
    credential_access = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-014", "SOCF-015"}]
    archive_staging = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-020"]
    seen_corr_011 = set()

    for cred in credential_access:
        cred_ts = _parse_ts(cred["timestamp"])
        cred_host = _field(cred, "host")
        cred_user = _field(cred, "username", "actor")

        for archive in archive_staging:
            archive_ts = _parse_ts(archive["timestamp"])
            archive_host = _field(archive, "host")
            archive_user = _field(archive, "username", "actor")

            if cred_host != archive_host:
                continue
            if cred_user != "unknown" and archive_user != "unknown" and cred_user != archive_user:
                continue
            if not (timedelta(0) <= (archive_ts - cred_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-011", cred_host, cred_user)
            if corr_id in seen_corr_011:
                continue
            seen_corr_011.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-011",
                "severity": "critical",
                "title": "Credential access followed by archive staging",
                "timestamp": archive["timestamp"],
                "details": {
                    "host": cred_host,
                    "username": cred_user,
                    "process_name": _field(archive, "process_name"),
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": cred["rule_id"], "timestamp": cred["timestamp"]},
                        {"rule_id": archive["rule_id"], "timestamp": archive["timestamp"]},
                    ],
                    "source_rule_ids": [cred["rule_id"], "SOCF-020"],
                },
                "mitre": [
                    {"tactic": "Credential Access", "technique": "Credentials from Password Stores", "id": "T1555"},
                    {"tactic": "Collection", "technique": "Archive Collected Data", "id": "T1560"},
                ],
                "score": 175,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-012: Lateral movement -> credential access
    # -------------------------
    lateral_movement = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-016", "SOCF-017", "SOCF-019"}]
    credential_access = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-014", "SOCF-015"}]
    seen_corr_012 = set()

    for lateral in lateral_movement:
        lateral_ts = _parse_ts(lateral["timestamp"])
        lateral_host = _field(lateral, "host")
        lateral_user = _field(lateral, "username", "actor")

        for cred in credential_access:
            cred_ts = _parse_ts(cred["timestamp"])
            cred_host = _field(cred, "host")
            cred_user = _field(cred, "username", "actor")

            if lateral_host != cred_host:
                continue
            if lateral_user != "unknown" and cred_user != "unknown" and lateral_user != cred_user:
                continue
            if not (timedelta(0) <= (cred_ts - lateral_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-012", lateral_host, lateral_user)
            if corr_id in seen_corr_012:
                continue
            seen_corr_012.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-012",
                "severity": "critical",
                "title": "Lateral movement followed by credential access",
                "timestamp": cred["timestamp"],
                "details": {
                    "host": lateral_host,
                    "username": lateral_user,
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": lateral["rule_id"], "timestamp": lateral["timestamp"]},
                        {"rule_id": cred["rule_id"], "timestamp": cred["timestamp"]},
                    ],
                    "source_rule_ids": [lateral["rule_id"], cred["rule_id"]],
                },
                "mitre": [
                    {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
                    {"tactic": "Credential Access", "technique": "OS Credential Dumping", "id": "T1003"},
                ],
                "score": 180,
                "status": "new",
                "correlation_id": corr_id,
            })
            break

    # -------------------------
    # SOCF-CORR-013: Admin share execution -> persistence or archive staging
    # -------------------------
    admin_shares = [a for a in alerts_sorted if a.get("rule_id") == "SOCF-019"]
    staging_or_persistence = [a for a in alerts_sorted if a.get("rule_id") in {"SOCF-005", "SOCF-016", "SOCF-020"}]
    seen_corr_013 = set()

    for share in admin_shares:
        share_ts = _parse_ts(share["timestamp"])
        share_host = _field(share, "host")
        share_user = _field(share, "username", "actor")

        for follow in staging_or_persistence:
            follow_ts = _parse_ts(follow["timestamp"])
            follow_host = _field(follow, "host")
            follow_user = _field(follow, "username", "actor")

            if share_host != follow_host:
                continue
            if share_user != "unknown" and follow_user != "unknown" and share_user != follow_user:
                continue
            if not (timedelta(0) <= (follow_ts - share_ts) <= window):
                continue

            corr_id = _cid("SOCF-CORR-013", share_host, share_user)
            if corr_id in seen_corr_013:
                continue
            seen_corr_013.add(corr_id)

            correlated.append({
                "rule_id": "SOCF-CORR-013",
                "severity": "critical",
                "title": "Admin share execution followed by persistence or staging",
                "timestamp": follow["timestamp"],
                "details": {
                    "host": share_host,
                    "username": share_user,
                    "window_minutes": window_minutes,
                    "evidence": [
                        {"rule_id": share["rule_id"], "timestamp": share["timestamp"]},
                        {"rule_id": follow["rule_id"], "timestamp": follow["timestamp"]},
                    ],
                    "source_rule_ids": ["SOCF-019", follow["rule_id"]],
                },
                "mitre": [
                    {"tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares", "id": "T1021.002"},
                    {"tactic": "Collection", "technique": "Archive Collected Data", "id": "T1560"},
                ],
                "score": 160,
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
        details = c.get("details", {}) or {}

        if rule_id == "SOCF-CORR-001":
            ip = details.get("ip")
            user = details.get("username")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-001" and d.get("ip") == ip:
                    a["correlation_id"] = cid
                if rid == "SOCF-002" and d.get("username") == user:
                    a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-002":
            host = details.get("host")
            user = details.get("username")
            ip = details.get("ip")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-006" and d.get("host") == host and d.get("username") == user and d.get("ip") == ip:
                    a["correlation_id"] = cid
                if rid == "SOCF-005" and d.get("host") == host:
                    a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-003":
            host = details.get("host")
            user = details.get("username")
            ip = details.get("ip")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid == "SOCF-006" and d.get("host") == host and d.get("username") == user and d.get("ip") == ip:
                    a["correlation_id"] = cid
                if rid in {"SOCF-003", "SOCF-008"} and d.get("host") == host:
                    a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-004":
            host = details.get("host")
            target_user = details.get("target_user")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid in {"SOCF-007", "SOCF-008"} and d.get("host") == host and d.get("target_user") == target_user:
                    a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-005":
            host = details.get("host")
            target_user = details.get("target_user")

            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}

                if rid in {"SOCF-007", "SOCF-008"} and d.get("host") == host and d.get("target_user") == target_user:
                    a["correlation_id"] = cid
                if rid == "SOCF-009" and d.get("host") == host:
                    a["correlation_id"] = cid



        elif rule_id == "SOCF-CORR-006":
            host = details.get("host")
            username = details.get("username")
            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}
                if rid in {"SOCF-011", "SOCF-013"} and d.get("host") == host:
                    if username in {None, "unknown"} or d.get("username") in {None, username}:
                        a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-007":
            host = details.get("host")
            username = details.get("username")
            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}
                if rid in {"SOCF-011", "SOCF-013", "SOCF-014"} and d.get("host") == host:
                    if username in {None, "unknown"} or d.get("username") in {None, username}:
                        a["correlation_id"] = cid

        elif rule_id == "SOCF-CORR-008":
            host = details.get("host")
            username = details.get("username")
            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}
                if rid in {"SOCF-011", "SOCF-012", "SOCF-013", "SOCF-015"} and d.get("host") == host:
                    if username in {None, "unknown"} or d.get("username") in {None, username}:
                        a["correlation_id"] = cid

        elif rule_id in {"SOCF-CORR-009", "SOCF-CORR-010", "SOCF-CORR-011", "SOCF-CORR-012", "SOCF-CORR-013"}:
            host = details.get("host")
            username = details.get("username")
            source_rule_ids = set(details.get("source_rule_ids", []) or [])
            for a in alerts_sorted:
                rid = a.get("rule_id")
                d = a.get("details", {}) or {}
                if rid in source_rule_ids and d.get("host") == host:
                    if username in {None, "unknown"} or d.get("username") in {None, username}:
                        a["correlation_id"] = cid
    return alerts_sorted + uniq_corr
