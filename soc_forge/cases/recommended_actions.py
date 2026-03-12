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