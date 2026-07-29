from __future__ import annotations

import re
from typing import Any, Dict, List

# -------------------------
# Phase 9 Helpers
# -------------------------


def _is_known_value(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "n/a"}


def _extract_ips_from_message(message: Any) -> List[str]:
    if not message:
        return []
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(message))


def _first_known(*values: Any) -> Any:
    for value in values:
        if _is_known_value(value):
            return value
    return None
def build_case_risk_fallback(items_sorted: List[Dict[str, Any]]) -> Dict[str, Any]:
    sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    raw_score = 0
    max_sev = "low"
    reasons = []

    for it in items_sorted:
        raw_score += int(it.get("score", 0) or 0)
        sev = str(it.get("severity", "low")).lower()
        if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
            max_sev = sev

    boost = 0

    if any("CORR" in str(it.get("rule_id", "")) for it in items_sorted):
        boost += 30
        reasons.append("Correlation present (+30)")

    tactic_labels = []
    for it in items_sorted:
        for t in _extract_tactic_labels_from_alert(it):
            base = t.split(" (", 1)[0]
            if base not in tactic_labels:
                tactic_labels.append(base)

    if len(tactic_labels) >= 2:
        tactic_boost = 10 * min(len(tactic_labels) - 1, 4)
        boost += tactic_boost
        reasons.append(f"Multi-tactic activity (+{tactic_boost}): {', '.join(tactic_labels)}")

    case_score = min(raw_score + boost, 400)

    return {
        "base_score": raw_score,
        "boost": boost,
        "case_score": case_score,
        "case_severity": max_sev,
        "case_threat_level": max_sev,
        "reasons": reasons,
        "tactics": tactic_labels,
        "alert_count": len(items_sorted),
    }


def describe_tactic_label(label: str) -> str:
    base = label.split(" (", 1)[0]

    descriptions = {
        "Initial Access": "The activity suggests an initial foothold or attempted entry into the environment.",
        "Execution": "The activity indicates code or commands were run on a target system.",
        "Persistence": "The activity suggests a mechanism intended to survive reboots or maintain access.",
        "Privilege Escalation": "The activity may indicate an attempt to gain elevated rights or broader permissions.",
        "Defense Evasion": "The activity may reflect attempts to avoid detection or bypass protections.",
        "Credential Access": "The activity suggests password guessing, credential theft, or account abuse.",
        "Discovery": "The activity indicates reconnaissance or environment awareness gathering.",
        "Lateral Movement": "The activity suggests movement from one host or account context to another.",
        "Collection": "The activity may indicate gathering data of interest from systems or users.",
        "Exfiltration": "The activity suggests data may be leaving the environment.",
        "Impact": "The activity may indicate disruption, destruction, or operational impairment.",
        "Command and Control": "The activity may reflect remote control or external operator communication.",
    }

    return descriptions.get(base, "This stage reflects attacker behavior associated with this case activity.")

def build_attack_graph(items_sorted: list[dict]) -> dict:
    nodes = []
    edges = []
    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id: str, label: str, node_type: str) -> None:
        key = (node_id, node_type)
        if key in seen_nodes:
            return
        seen_nodes.add(key)
        nodes.append({"id": node_id, "label": label, "type": node_type})

    def add_edge(source: str, target: str) -> None:
        key = (source, target)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({"source": source, "target": target})

    for it in items_sorted:
        details = it.get("details", {}) or {}
        event = it.get("event", {}) or {}

        message_ips = _extract_ips_from_message(details.get("message") or event.get("message"))
        ip = _first_known(
            it.get("src_ip"),
            it.get("ip"),
            details.get("src_ip"),
            details.get("ip"),
            event.get("src_ip"),
            event.get("ip"),
            message_ips[0] if message_ips else None,
        )
        user = (
            it.get("username")
            or details.get("username")
            or event.get("username")
            or event.get("target_user")
            or event.get("account_name")
        )
        host = (
            it.get("host")
            or details.get("host")
            or event.get("host")
            or event.get("computer")
            or event.get("computer_name")
        )

        action = normalize_attack_step(it)
        if not action:
            action = str(it.get("title", "")).strip() or str(it.get("rule_id", "")).strip() or "Unknown Activity"

        action_id = f"action:{action}"
        add_node(action_id, action, "action")

        ip_id = None
        user_id = None
        host_id = None

        if _is_known_value(ip):
            ip_id = f"ip:{ip}"
            add_node(ip_id, str(ip), "ip")

        if _is_known_value(user):
            user_id = f"user:{user}"
            add_node(user_id, str(user), "user")

        if _is_known_value(host):
            host_id = f"host:{host}"
            add_node(host_id, str(host), "host")

        if ip_id and user_id:
            add_edge(ip_id, user_id)

        if user_id and host_id:
            add_edge(user_id, host_id)

        if host_id:
            add_edge(host_id, action_id)
        elif user_id:
            add_edge(user_id, action_id)
        elif ip_id:
            add_edge(ip_id, action_id)

    return {"nodes": nodes, "edges": edges}

def build_attack_path(graph: dict) -> list[dict]:
    """
    Converts the attack graph {nodes, edges} into one ordered path of nodes
    for simple vertical rendering in the HTML report.
    """
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []

    if not nodes:
        return []

    node_map = {n["id"]: n for n in nodes}

    outgoing = {}
    indegree = {}

    for n in nodes:
        outgoing[n["id"]] = []
        indegree[n["id"]] = 0

    for e in edges:
        src = e.get("source")
        tgt = e.get("target")
        if src in outgoing and tgt in node_map:
            outgoing[src].append(tgt)
            indegree[tgt] = indegree.get(tgt, 0) + 1

    # find likely starting node: prefer IP, otherwise any node with indegree 0
    start_id = None

    zero_in = [nid for nid, deg in indegree.items() if deg == 0]
    ip_zero_in = [nid for nid in zero_in if node_map[nid].get("type") == "ip"]

    if ip_zero_in:
        start_id = ip_zero_in[0]
    elif zero_in:
        start_id = zero_in[0]
    else:
        start_id = nodes[0]["id"]

    ordered = []
    seen = set()
    current = start_id

    while current and current not in seen:
        seen.add(current)
        ordered.append(node_map[current])

        next_nodes = outgoing.get(current, [])
        if not next_nodes:
            break

        # prefer host/user/action ordering for cleaner path display
        def rank(node_id: str) -> int:
            t = node_map[node_id].get("type", "")
            order = {"ip": 0, "user": 1, "host": 2, "action": 3}
            return order.get(t, 99)

        next_nodes = sorted(next_nodes, key=rank)
        current = next_nodes[0]

    return ordered


def choose_case_header_alert(items_sorted: list[dict]) -> dict:
    """
    Pick the best alert to represent the case header.
    Prefer:
    1. correlation alerts
    2. highest score
    3. earliest alert with a timestamp
    """
    if not items_sorted:
        return {}

    def sort_key(a: dict):
        rule_id = str(a.get("rule_id", ""))
        is_corr = 1 if "CORR" in rule_id else 0
        score = int(a.get("score", 0) or 0)
        ts = str(a.get("timestamp", "") or "")
        return (-is_corr, -score, ts == "", ts)

    return sorted(items_sorted, key=sort_key)[0]

# -------------------------
# Phase 8 helpers
# -------------------------

def extract_mitre_ids(alert: dict) -> list[str]:
    """
    Extract MITRE technique/sub-technique IDs from an alert.
    Supports common formats like:
      [{"tactic": "...", "technique": "T1110"}]
      [{"technique_id": "T1110"}]
      ["T1110"]
    """
    mitre = alert.get("mitre", []) or []
    ids: list[str] = []

    for m in mitre:
        if isinstance(m, str):
            if m.startswith("T"):
                ids.append(m)
        elif isinstance(m, dict):
            tech = m.get("technique") or m.get("technique_id") or m.get("id")
            if tech:
                ids.append(str(tech))

    # de-dupe, preserve order
    seen = set()
    out = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def normalize_attack_step(alert: dict) -> str:
    rule_id = str(alert.get("rule_id", ""))
    title = str(alert.get("title", "")).lower()

    if rule_id in {"SOCF-001", "SOCF-002"} or "bruteforce" in title or "brute force" in title:
        return "Brute Force"

    if rule_id in {"SOCF-006", "SOCF-007"} or "rdp" in title:
        return "Remote Access"

    if rule_id in {"SOCF-010", "SOCF-011"} or "scheduled task" in title:
        return "Persistence"

    if rule_id == "SOCF-020":
        return "Collection"

    if rule_id == "SOCF-021":
        return "Defense Evasion"

    if rule_id == "SOCF-022":
        return "Impact"

    if rule_id in {"SOCF-004", "SOCF-016"} or "service" in title:
        return "Service Execution"

    if "admin" in title or "privilege" in title:
        return "Privilege Escalation"

    return str(alert.get("title", "")).strip() or rule_id or "Unknown Activity"

def build_attack_flow(items_sorted: list[dict]) -> list[dict]:
    steps = []

    for it in items_sorted:
        step_label = normalize_attack_step(it)
        ts = str(it.get("timestamp", ""))
        severity = str(it.get("severity", "")).lower()
        rule_id = str(it.get("rule_id", ""))
        mitre_ids = extract_mitre_ids(it)

        # collapse adjacent duplicate labels
        if steps and steps[-1]["label"] == step_label:
            # merge MITRE IDs into the previous step if needed
            prev_ids = steps[-1].get("mitre_ids", [])
            for mid in mitre_ids:
                if mid not in prev_ids:
                    prev_ids.append(mid)
            steps[-1]["mitre_ids"] = prev_ids
            continue

        steps.append(
            {
                "rule_id": rule_id,
                "label": step_label,
                "timestamp": ts,
                "severity": severity,
                "mitre_ids": mitre_ids,
            }
        )

    return steps

# -------------------------
# Phase 7 Helpers
# -------------------------
def build_evidence_fields(alert: dict) -> list[tuple[str, str]]:
    """
    Return a compact list of high-value fields for display in the Evidence section.
    """
    details = alert.get("details", {}) or {}
    event = alert.get("event", {}) or {}

    def pick(*keys):
        for k in keys:
            if k in alert and alert.get(k) not in (None, "", []):
                return str(alert.get(k))
            if k in details and details.get(k) not in (None, "", []):
                return str(details.get(k))
            if k in event and event.get(k) not in (None, "", []):
                return str(event.get(k))
        return None

    fields = []

    candidates = [
        ("event_id", pick("event_id")),
        ("host", pick("host", "computer", "computer_name")),
        ("username", pick("username", "user", "target_user", "account_name")),
        ("ip", pick("src_ip", "ip", "source_ip")),
        ("task_name", pick("task_name")),
        ("service_name", pick("service_name")),
        ("command", pick("command", "image_path", "process_command_line")),
    ]

    for label, value in candidates:
        if value:
            fields.append((label, value))

    return fields[:6]


# -------------------------
# Phase 5 helpers
# -------------------------
def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x).strip()


def _get_details(a: Dict[str, Any]) -> Dict[str, Any]:
    d = a.get("details")
    return d if isinstance(d, dict) else {}


def build_case_timeline(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Timeline is oldest -> newest.
    """
    rows: List[Dict[str, Any]] = []
    for a in items:
        rows.append(
            {
                "timestamp": _safe_str(a.get("timestamp")),
                "rule_id": _safe_str(a.get("rule_id")),
                "title": _safe_str(a.get("title")),
                "severity": _safe_str(a.get("severity")).lower(),
                "score": a.get("score", 0),
            }
        )

    # Sort by timestamp asc; blanks go last
    rows.sort(key=lambda r: (r.get("timestamp") == "", r.get("timestamp", "")))
    return rows


def extract_case_iocs(items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ips, users, hosts = set(), set(), set()

    for a in items:
        d = _get_details(a)
        ip = _safe_str(d.get("ip"))
        user = _safe_str(d.get("username"))
        host = _safe_str(d.get("host"))

        if ip:
            ips.add(ip)
        if user:
            users.add(user)
        if host:
            hosts.add(host)

    return {"ips": sorted(ips), "hosts": sorted(hosts), "users": sorted(users)}


def build_analyst_summary(items: List[Dict[str, Any]]) -> str:
    """
    Deterministic SOC-style narrative based on what is present in the case.
    """
    rule_ids = {_safe_str(a.get("rule_id")) for a in items if _safe_str(a.get("rule_id"))}
    titles = " ".join(_safe_str(a.get("title")).lower() for a in items)

    has_rdp = "SOCF-006" in rule_ids or ("rdp" in titles and "logon" in titles)
    has_schtask = "SOCF-005" in rule_ids or ("scheduled task" in titles)
    has_new_admin = "SOCF-003" in rule_ids or ("new admin" in titles) or ("administrators" in titles and "added" in titles)
    has_lockout = "SOCF-002" in rule_ids or ("lockout" in titles)
    has_bruteforce = "SOCF-001" in rule_ids or ("brute" in titles and "force" in titles)
    has_corr = any(rid.startswith("SOCF-CORR") for rid in rule_ids)

    iocs = extract_case_iocs(items)
    ctx_bits = []
    if iocs["users"]:
        ctx_bits.append(f"user {iocs['users'][0]}")
    if iocs["hosts"]:
        ctx_bits.append(f"host {iocs['hosts'][0]}")
    if iocs["ips"]:
        ctx_bits.append(f"ip {iocs['ips'][0]}")

    ctx = f" (e.g., {', '.join(ctx_bits[:3])})" if ctx_bits else ""
    corr_note = " A correlation rule fired, increasing confidence that these events are related." if has_corr else ""

    if has_rdp and has_schtask:
        base = (
            "This case shows RDP interactive access followed by scheduled task activity, "
            "which is consistent with post-compromise persistence and operator automation."
        )
        next_steps = (
            "Validate whether the task is authorized, confirm the source of the RDP session, "
            "and review endpoint telemetry around the first RDP logon time."
        )
    elif has_rdp and has_new_admin:
        base = (
            "This case shows RDP access combined with administrative account or group changes, "
            "which suggests potential privilege escalation or account takeover."
        )
        next_steps = (
            "Confirm who initiated the admin change, review authentication context for the RDP logon, "
            "and hunt for additional persistence mechanisms."
        )
    elif has_bruteforce and has_lockout:
        base = (
            "This case indicates repeated authentication failures followed by account lockout, "
            "consistent with an active credential attack."
        )
        next_steps = (
            "Identify targeted accounts, block or rate-limit offending sources, "
            "and review password reset and MFA coverage for impacted users."
        )
    elif has_schtask:
        base = "This case includes scheduled task creation, which can indicate persistence or automation."
        next_steps = "Confirm task legitimacy, inspect task command/arguments on the endpoint, and correlate with prior logons."
    elif has_rdp:
        base = "This case includes RDP logon activity that may indicate lateral movement or remote access."
        next_steps = "Validate source IP and user, confirm business justification, and correlate with endpoint process execution."
    else:
        base = "This case contains multiple related alerts that warrant review and correlation."
        next_steps = "Review the timeline progression, validate user/host context, and pivot to endpoint telemetry for confirmation."

    return f"{base}{corr_note}{ctx} {next_steps}"

# -------------------------
# Phase 6: Attack Chain helpers
# -------------------------

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Keywords -> tactic (fallback if alerts don't carry MITRE tags)
TACTIC_KEYWORDS = [
    ("rdp", "Lateral Movement"),
    ("remote desktop", "Lateral Movement"),
    ("logon type 10", "Lateral Movement"),
    ("scheduled task", "Persistence"),
    ("new service", "Persistence"),
    ("service installed", "Persistence"),
    ("new admin", "Privilege Escalation"),
    ("administrators", "Privilege Escalation"),
    ("brute", "Credential Access"),
    ("password spray", "Credential Access"),
    ("lockout", "Credential Access"),
]

def _extract_tactic_labels_from_alert(a: Dict[str, Any]) -> List[str]:
    """
    Extract MITRE tactic labels for display in the attack chain.
    Preferred output:
      Persistence (T1053)
      Lateral Movement (T1021)

    Falls back to tactic-only labels if technique IDs are not present.
    """
    labels: List[str] = []

    def add_label(tactic: str, technique_id: str | None = None) -> None:
        if not tactic:
            return
        if technique_id:
            labels.append(f"{tactic} ({technique_id})")
        else:
            labels.append(tactic)

    def handle_mitre_list(mitre_list: Any) -> None:
        if not isinstance(mitre_list, list):
            return
        for x in mitre_list:
            if isinstance(x, dict):
                tactic = _safe_str(x.get("tactic"))
                technique_id = _safe_str(x.get("id") or x.get("technique_id") or x.get("technique"))
                if tactic in TACTIC_ORDER:
                    add_label(tactic, technique_id or None)
            else:
                s = _safe_str(x)
                if s in TACTIC_ORDER:
                    add_label(s)

    handle_mitre_list(a.get("mitre"))

    d = _get_details(a)
    handle_mitre_list(d.get("mitre"))

    if not labels:
        title = _safe_str(a.get("title")).lower()
        for kw, tact in TACTIC_KEYWORDS:
            if kw in title:
                add_label(tact)

    out: List[str] = []
    seen = set()
    for label in labels:
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def build_attack_chain(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build an ordered list of tactics (attack chain) + per-tactic contributing rules.
    Ordering logic:
      - determine first-seen timestamp for each tactic in the case
      - sort by first-seen time, then by MITRE tactic order
    """
    first_seen: Dict[str, str] = {}
    contrib: Dict[str, List[Dict[str, str]]] = {}  # tactic -> [{"rule_id":..., "title":..., "timestamp":...}]

    for a in items:
        ts = _safe_str(a.get("timestamp"))
        rid = _safe_str(a.get("rule_id"))
        title = _safe_str(a.get("title"))
        for tact in _extract_tactic_labels_from_alert(a):
            if tact not in first_seen or (ts and ts < first_seen[tact]):
                first_seen[tact] = ts or first_seen.get(tact, "")
            contrib.setdefault(tact, []).append({"rule_id": rid, "title": title, "timestamp": ts})

    # Nothing found
    if not first_seen:
        return {"tactics": [], "by_tactic": {}}

    def tactic_rank(t: str) -> int:
      base = t.split(" (", 1)[0]
      try:
        return TACTIC_ORDER.index(base)
      except ValueError:
        return 999

    # Sort tactics by first-seen timestamp, then by MITRE order for stability
    tactics_sorted = sorted(first_seen.keys(), key=lambda t: (first_seen.get(t, "") == "", first_seen.get(t, ""), tactic_rank(t)))

    # Dedup contrib rows per tactic (rule_id, timestamp)
    by_tactic: Dict[str, Any] = {}
    for t in tactics_sorted:
        seen = set()
        rows = []
        for r in contrib.get(t, []):
            key = (r.get("rule_id", ""), r.get("timestamp", ""))
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
        # sort rows oldest->newest
        rows.sort(key=lambda x: (x.get("timestamp", "") == "", x.get("timestamp", "")))
        by_tactic[t] = {
            "first_seen": first_seen.get(t, ""),
            "events": rows,
            "description": describe_tactic_label(t),
        }

    return {"tactics": tactics_sorted, "by_tactic": by_tactic}


