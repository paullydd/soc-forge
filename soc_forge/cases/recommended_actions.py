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
        v = it.get("host") or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("host")
        if v:
            hosts.add(str(v))
    return hosts


def _collect_users(items: List[Dict[str, Any]]) -> Set[str]:
    users: Set[str] = set()
    for it in items:
        v = it.get("username") or (it.get("event", {}) if isinstance(it.get("event"), dict) else {}).get("username")
        if v:
            users.add(str(v))
    return users


def _collect_src_ips(items: List[Dict[str, Any]]) -> Set[str]:
    ips: Set[str] = set()
    for it in items:
        v = (
            it.get("src_ip")
            or it.get("ip")
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

    # Quick pivots (useful even if you only have 1 signal)
    users = sorted(_collect_users(items_sorted))
    hosts = sorted(_collect_hosts(items_sorted))
    src_ips = sorted(_collect_src_ips(items_sorted))

    if users:
        actions.append(f"Validate user access with HR/IT: {', '.join(users)}")
    if hosts:
        actions.append(f"Identify impacted endpoint(s): {', '.join(hosts)}")
    if src_ips:
        actions.append(f"Confirm source IP reputation/ownership: {', '.join(src_ips)}")

    # --- High-impact combos (examples you referenced) ---
    # RDP logon + scheduled task = classic persistence + remote access chain
    if _has_rule(items_sorted, "SOCF-006", "SOCF-007") and _has_rule(items_sorted, "SOCF-010", "SOCF-011"):
        actions.append("Pull EDR triage: process tree around first RDP logon (parent/child, network, command line)")
        actions.append("Check scheduled task details (name, triggers, command, author) and capture the full XML if available")

    # Brute-force + lockout (or brute + many failures)
    if _has_rule(items_sorted, "SOCF-001", "SOCF-002"):
        actions.append("Review authentication logs for password spray / brute-force scope (users targeted, hosts, time window)")
        if src_ips:
            actions.append(f"Consider blocking source IP(s) at the firewall if unauthorized: {', '.join(src_ips)}")

    # New service installed / suspicious persistence
    if _has_rule(items_sorted, "SOCF-020", "SOCF-021"):
        actions.append("Inspect new service(s): binary path, signer, start type, and recent install time correlation")
        actions.append("Acquire the service binary for hash + reputation lookup and preserve it as evidence")

    # If we have an IP and any medium/high-ish case signals, suggest containment language
    threat = _first(items_sorted, "threat_level") or _first(items_sorted, "severity")
    if src_ips and threat and str(threat).lower() in {"medium", "high", "critical"}:
        actions.append("If activity is unauthorized, initiate containment: block IP, isolate host, and reset affected credentials")

    # De-dupe while preserving order
    seen = set()
    deduped: List[str] = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            deduped.append(a)

    return deduped
