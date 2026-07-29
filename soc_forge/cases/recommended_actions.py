from __future__ import annotations

from typing import Any, Dict, List, Set


def _has_rule(items: List[Dict[str, Any]], *rule_ids: str) -> bool:
    ids = {it.get("rule_id") for it in items}
    return any(r in ids for r in rule_ids)


def _first(items: List[Dict[str, Any]], field: str) -> str | None:
    for it in items:
        v = it.get(field) or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get(field)
        if v:
            return str(v)
    return None


def _collect_hosts(items: List[Dict[str, Any]]) -> Set[str]:
    hosts: Set[str] = set()
    for it in items:
        v = (
            it.get("host")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("host")
            or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("host")
        )
        if v:
            hosts.add(str(v))
    return hosts


def _collect_users(items: List[Dict[str, Any]]) -> Set[str]:
    users: Set[str] = set()
    for it in items:
        v = (
            it.get("username")
            or it.get("actor")
            or it.get("target_user")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("username")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("actor")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("target_user")
            or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("username")
        )
        if v:
            users.add(str(v))
    return users


def _collect_src_ips(items: List[Dict[str, Any]]) -> Set[str]:
    ips: Set[str] = set()
    for it in items:
        v = (
            it.get("src_ip")
            or it.get("ip")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("src_ip")
            or (it.get("details", {}) if isinstance(it.get("details"), dict) else {}).get("ip")
            or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("src_ip")
            or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("ip")
        )
        if v:
            ips.add(str(v))
    return ips


def build_recommended_actions(items_sorted: List[Dict[str, Any]]) -> List[str]:
    """
    Deterministic SOC-style next steps for a single case.
    Input: items_sorted = alerts/evidence items already grouped into a case (preferably time-sorted).
    Output: list of human-readable actions (deduped, stable order).
    """
    actions: List[str] = []

    users = sorted(_collect_users(items_sorted))
    hosts = sorted(_collect_hosts(items_sorted))
    src_ips = sorted(_collect_src_ips(items_sorted))

    if users:
        actions.append(f"Validate user access with HR/IT: {', '.join(users)}")
    if hosts:
        actions.append(f"Identify impacted endpoint(s): {', '.join(hosts)}")
    if src_ips:
        actions.append(f"Confirm source IP reputation/ownership: {', '.join(src_ips)}")

    # SOCF-006: RDP logon
    if _has_rule(items_sorted, "SOCF-006"):
        actions.append("Review the source of the RDP session and confirm whether remote access was expected.")
        actions.append("Inspect endpoint telemetry around the first RDP logon for process execution, network activity, and privilege changes.")

    # SOCF-005: Scheduled task created
    if _has_rule(items_sorted, "SOCF-005"):
        actions.append("Inspect the scheduled task name, trigger, author, and full command line to determine whether persistence was established.")
        actions.append("Capture the task XML or task definition from the endpoint and review adjacent administrative activity.")

    # SOCF-007: New user created
    if _has_rule(items_sorted, "SOCF-007"):
        actions.append("Validate whether the new account creation was authorized and tied to an approved change request.")
        actions.append("Disable or lock the newly created account if it is not approved and review who created it.")

    # SOCF-008: Privileged group assignment
    if _has_rule(items_sorted, "SOCF-008"):
        actions.append("Review the privileged group membership change for approval and business justification.")
        actions.append("Remove the user from privileged groups if the change is unauthorized and investigate the initiating actor.")

    # SOCF-009: Audit logs cleared
    if _has_rule(items_sorted, "SOCF-009"):
        actions.append("Investigate why Windows Security logs were cleared and preserve alternate telemetry sources immediately.")
        actions.append("Review suspicious activity immediately before and after log clearing, including authentication, persistence, and administrative actions.")

    # SOCF-CORR-001: Brute force + lockout
    if _has_rule(items_sorted, "SOCF-CORR-001"):
        actions.append("Review authentication logs for password spray / brute-force scope (users targeted, hosts, time window)")
        if src_ips:
            actions.append(f"Consider blocking or rate-limiting source IP(s) if unauthorized: {', '.join(src_ips)}")

    # SOCF-CORR-002: RDP -> scheduled task
    if _has_rule(items_sorted, "SOCF-CORR-002"):
        actions.append("Treat the RDP plus scheduled task sequence as possible hands-on-keyboard persistence and validate the task immediately.")
        actions.append("Review whether the same user, host, and source IP appear in other nearby alerts or endpoint telemetry.")

    # SOCF-CORR-003: RDP -> privileged group change
    if _has_rule(items_sorted, "SOCF-CORR-003"):
        actions.append("Treat the RDP session followed by privileged group change as possible account takeover or privilege escalation.")
        actions.append("Review authentication context, administrative actions, and any additional persistence or lateral movement from the same host.")

    # SOCF-CORR-004: New account -> privileged group assignment
    if _has_rule(items_sorted, "SOCF-CORR-004"):
        actions.append("Disable the newly created account immediately if the account and privilege change were not explicitly approved.")
        actions.append("Remove the account from privileged groups and review all logons or administrative actions involving that account.")

    # SOCF-CORR-005: New account -> privileged group -> log clearing
    if _has_rule(items_sorted, "SOCF-CORR-005"):
        actions.append("Treat this sequence as a high-confidence malicious chain involving account creation, privilege escalation, and defense evasion.")
        actions.append("Disable the account, revoke privileged access, and isolate the host if activity is unauthorized.")
        actions.append("Preserve forensic evidence before additional logs or artifacts are destroyed and hunt for persistence such as tasks, services, or remote access.")

    # SOCF-CORR-006: Office -> suspicious script interpreter
    if _has_rule(items_sorted, "SOCF-CORR-006"):
        actions.append("Treat the Office-to-script sequence as possible malicious document execution and collect the document, email context, and full process tree.")
        actions.append("Contain the endpoint if the Office child process or command line is unauthorized.")

    # SOCF-CORR-007: Script execution -> credential dumping
    if _has_rule(items_sorted, "SOCF-CORR-007"):
        actions.append("Treat script execution followed by credential dumping as high-confidence credential theft activity.")
        actions.append("Preserve process and memory evidence, reset potentially exposed credentials, and hunt for follow-on lateral movement.")

    # SOCF-CORR-008: Suspicious process -> browser credential store access
    if _has_rule(items_sorted, "SOCF-CORR-008"):
        actions.append("Review why the suspicious process accessed browser credential stores and preserve any copied browser database artifacts.")
        actions.append("Rotate exposed browser-saved credentials and inspect nearby process, file, and network activity.")

    # SOCF-CORR-009: RDP -> PsExec-style service execution
    if _has_rule(items_sorted, "SOCF-CORR-009"):
        actions.append("Treat RDP followed by PsExec-style service execution as likely hands-on-keyboard lateral movement.")
        actions.append("Review remote service creation, source authentication, SMB activity, and endpoint process trees for the affected host.")

    # SOCF-CORR-010: WMI -> suspicious execution
    if _has_rule(items_sorted, "SOCF-CORR-010"):
        actions.append("Treat WMI followed by suspicious execution as possible remote command execution.")
        actions.append("Hunt for the same account using WMI across nearby hosts and collect command-line/process ancestry evidence.")

    # SOCF-CORR-011: Credential access -> archive staging
    if _has_rule(items_sorted, "SOCF-CORR-011"):
        actions.append("Treat credential access followed by archive staging as possible credential collection and exfiltration preparation.")
        actions.append("Preserve the archive, identify included files, and review outbound transfer or cleanup after archive creation.")

    # SOCF-CORR-012: Lateral movement -> credential access
    if _has_rule(items_sorted, "SOCF-CORR-012"):
        actions.append("Treat lateral movement followed by credential access as possible host compromise expansion.")
        actions.append("Reset exposed credentials, inspect lateral movement paths, and contain impacted hosts if unauthorized.")

    # SOCF-CORR-013: Admin share execution -> persistence or staging
    if _has_rule(items_sorted, "SOCF-CORR-013"):
        actions.append("Review administrative share execution followed by persistence or staging as a likely remote operator sequence.")
        actions.append("Inspect SMB sessions, copied binaries, scheduled tasks/services, and staged archives on the destination host.")

    if _has_rule(items_sorted, "SOCF-006") and _has_rule(items_sorted, "SOCF-005", "SOCF-010", "SOCF-011"):
        actions.append("Pull EDR triage: process tree around first RDP logon (parent/child, network, command line)")
        actions.append("Check scheduled task details (name, triggers, command, author) and capture the full XML if available")

    if _has_rule(items_sorted, "SOCF-CORR-001") or (_has_rule(items_sorted, "SOCF-001") and _has_rule(items_sorted, "SOCF-002")):
        actions.append("Review authentication logs for password spray / brute-force scope (users targeted, hosts, time window).")
        if src_ips:
            actions.append(f"Consider blocking or rate-limiting source IP(s) if unauthorized: {', '.join(src_ips)}")

    if _has_rule(items_sorted, "SOCF-CORR-001") or (_has_rule(items_sorted, "SOCF-001") and _has_rule(items_sorted, "SOCF-002")):
        actions.append("Review authentication logs for password spray / brute-force scope (users targeted, hosts, time window).")
        if src_ips:
            actions.append(f"Consider blocking source IP(s) if unauthorized: {', '.join(src_ips)}")

    # SOCF-013: Office spawned script interpreter
    if _has_rule(items_sorted, "SOCF-013"):
        actions.append("Review the Office parent process, source document, email context, macro/script settings, and child process command line.")
        actions.append("Collect process tree evidence and isolate the host if the document or child process is unauthorized.")

    # SOCF-014: Credential dumping / LSASS access
    if _has_rule(items_sorted, "SOCF-014"):
        actions.append("Treat LSASS access or credential dumping as critical and preserve memory/process evidence before cleanup.")
        actions.append("Reset potentially exposed credentials and review lateral movement from the same host or user.")

    # SOCF-015: Browser credential store access
    if _has_rule(items_sorted, "SOCF-015"):
        actions.append("Validate why a non-browser process accessed browser credential stores and preserve copied credential database files.")
        actions.append("Rotate affected browser-saved credentials if access is unauthorized.")

    # SOCF-016: PsExec-style service execution
    if _has_rule(items_sorted, "SOCF-016"):
        actions.append("Review service creation details for PsExec-style lateral movement, including service name, binary path, source account, and remote source.")
        actions.append("Validate whether remote service execution was authorized and isolate impacted hosts if activity is suspicious.")

    # SOCF-017: WMI process execution
    if _has_rule(items_sorted, "SOCF-017"):
        actions.append("Review WMI execution context, parent process, target host, command line, and initiating account.")
        actions.append("Hunt for additional WMI-created processes across nearby hosts and timestamps.")

    # SOCF-018: Suspicious LOLBin script execution
    if _has_rule(items_sorted, "SOCF-018"):
        actions.append("Inspect the LOLBin command line, remote content URL, scriptlet path, or DLL invocation for proxy execution.")
        actions.append("Block or collect referenced remote payloads and review parent process ancestry.")

    # SOCF-019: Remote admin share execution
    if _has_rule(items_sorted, "SOCF-019"):
        actions.append("Validate administrative share execution paths and confirm whether remote file staging was approved.")
        actions.append("Review SMB/session telemetry for the source host and account associated with the admin share activity.")

    # SOCF-020: Suspicious archive staging
    if _has_rule(items_sorted, "SOCF-020"):
        actions.append("Review archive contents, destination path, and process ancestry to determine whether data collection occurred.")
        actions.append("Search for follow-on upload, external transfer, or cleanup behavior after archive creation.")

    # SOCF-021: Security control tampering
    if _has_rule(items_sorted, "SOCF-021"):
        actions.append("Validate whether the security control change was authorized and restore disabled protections or remove unsafe exclusions.")
        actions.append("Review nearby process activity and security-tool telemetry for the actor or process that changed endpoint protections.")

    # SOCF-022: Inhibit system recovery
    if _has_rule(items_sorted, "SOCF-022"):
        actions.append("Treat unexpected recovery or shadow copy deletion as possible destructive activity and isolate the endpoint if unauthorized.")
        actions.append("Verify backup integrity and recovery options before remediation, then investigate adjacent encryption, deletion, or staging activity.")

    threat = _first(items_sorted, "threat_level") or _first(items_sorted, "severity")
    if hosts and threat and str(threat).lower() in {"high", "critical"}:
        actions.append("If activity is unauthorized, initiate containment on impacted hosts and reset affected credentials.")

    # De-dupe while preserving order
    seen = set()
    deduped: List[str] = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            deduped.append(a)

    return deduped