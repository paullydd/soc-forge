from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple
from collections import defaultdict

from jinja2 import Template

from soc_forge import __version__
from soc_forge.scoring.risk import score_case
from soc_forge.cases.recommended_actions import build_recommended_actions

# -------------------------
# Phase 9 Helpers
# -------------------------
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

        ip = (
            it.get("src_ip")
            or it.get("ip")
            or details.get("src_ip")
            or details.get("ip")
            or event.get("src_ip")
            or event.get("ip")
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

        if ip:
            ip_id = f"ip:{ip}"
            add_node(ip_id, str(ip), "ip")

        if user:
            user_id = f"user:{user}"
            add_node(user_id, str(user), "user")

        if host:
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

    if rule_id in {"SOCF-020", "SOCF-021"} or "service" in title:
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


# -------------------------
# HTML Template
# -------------------------
HTML_TEMPLATE = Template(
    r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SOC-Forge Report</title>
  <style>
    :root{
      --bg:#0b0f14; --panel:#0f1621; --panel2:#0b121b;
      --text:#e6edf3; --muted:#98a2b3; --border:rgba(255,255,255,0.10);

      --critical:#b56cff;
      --high:#ff6b6b;
      --medium:#f7c948;
      --low:#4dd4ac;
    }
    *{box-sizing:border-box}
    body{
      margin:0; padding:24px;
      background:var(--bg);
      color:var(--text);
      font-family:ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      line-height:1.35;
    }
    .container{max-width:1100px;margin:0 auto;}
    .header{
      display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap;
      padding:18px 18px;
      border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
      border-radius:16px;
    }
    .title{font-size:20px;font-weight:800;margin:0;}
    .meta{color:var(--muted);font-size:12px;margin-top:6px;}
    .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px;}
    .stat{
      border:1px solid var(--border); background:var(--panel);
      border-radius:14px; padding:12px;
    }
    .stat .k{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:0.03em;}
    .stat .v{font-size:18px;font-weight:900;margin-top:4px;}

    .filters{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 8px;}
    .btn{
      cursor:pointer; user-select:none;
      background:rgba(255,255,255,0.06);
      border:1px solid var(--border);
      padding:8px 12px; border-radius:999px;
      color:var(--text); font-size:12px; font-weight:800;
    }
    .btn.active{outline:2px solid rgba(255,255,255,0.18);}

    .chain { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; align-items:center; }
    .chain .node {
      border:1px solid var(--border);
      background:rgba(255,255,255,0.04);
      border-radius:999px;
      padding:6px 10px;
      font-size:12px;
      font-weight:900;
      color:var(--text);
    }
    .chain .arrow { color:var(--muted); font-weight:900; }

    .evidence-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .mitre-panel {
      margin-top: 16px;
      padding: 14px;
      border: 1px solid #2a2f3a;
      border-radius: 10px;
      background: #11151c;
    }

    .mitre-row {
      display: grid;
      grid-template-columns: 180px 1fr 50px;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
    }

    .mitre-label {
      font-weight: 700;
      color: #d7dde8;
    }

    .mitre-bar-wrap {
      width: 100%;
      background: #1c2330;
      border-radius: 999px;
      height: 14px;
      overflow: hidden;
    }

    .mitre-bar {
      height: 14px;
      border-radius: 999px;
      background: linear-gradient(90deg, #4da3ff, #7cc4ff);
    }

    .mitre-count {
      text-align: right;
      color: #9fb3c8;
      font-weight: 700;
    }

    .muted {
      color: #93a1b2;
    }

    .attack-flow {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-top: 8px;
    }

    .flow-step {
      min-width: 180px;
      max-width: 240px;
      padding: 10px 12px;
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      background: rgba(255,255,255,0.03);
    }

    .flow-label {
      font-weight: 700;
      margin-bottom: 6px;
    }

    .flow-meta {
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 0.9rem;
    }

    .flow-arrow {
      font-size: 1.4rem;
      font-weight: 700;
      opacity: 0.7;
    }

    .evidence-item {
      border: 1px solid #2a2f3a;
      border-radius: 10px;
      padding: 10px;
      background: rgba(255,255,255,0.02);
    }

    .evidence-head {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      align-items: center;
      margin-bottom: 8px;
    }

    .evidence-fields {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .kv {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      padding: 4px 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      border: 1px solid #2a2f3a;
      font-size: 0.9rem;
    }

    .k {
      font-weight: 600;
      opacity: 0.85;
    }

    .v {
      opacity: 0.95;
    }

    .checklist {
      list-style: none;
      padding-left: 0;
      margin: 0.25rem 0 0;
    }
    .checklist li {
      margin: 0.35rem 0;
    }
    .checklist input[type="checkbox"] {
      margin-right: 0.5rem;
      transform: translateY(1px);
    }

    .flow-mitre {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 8px;
    }

    .mitre-tag {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid #355c7d;
      background: rgba(53, 92, 125, 0.18);
      font-size: 0.82rem;
    }

    .attack-graph {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-top: 8px;
    }

    .graph-node {
      min-width: 140px;
      max-width: 220px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid #2a2f3a;
      background: rgba(255,255,255,0.03);
    }

    .graph-node-type {
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      opacity: 0.75;
      margin-bottom: 6px;
    }

    .graph-node-label {
      font-size: 0.95rem;
    }

    .graph-ip {
      border-color: #355c7d;
    }

    .graph-user {
      border-color: #6c5b7b;
    }

    .graph-host {
      border-color: #2a9d8f;
    }

    .graph-action {
      border-color: #e9c46a;
    }

    .graph-arrow {
      font-size: 1.3rem;
      font-weight: 700;
      opacity: 0.7;
    }

    .graph-node.ip {
      border-color: #3b82f6;
      box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.user {
      border-color: #a855f7;
      box-shadow: 0 0 0 1px rgba(168, 85, 247, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.host {
      border-color: #22c55e;
      box-shadow: 0 0 0 1px rgba(34, 197, 94, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.action {
      border-color: #f59e0b;
      box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .case-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.02em;
      border: 1px solid #2b3545;
      background: #18202b;
      color: #dbe7f3;
    }

    .badge-low {
      border-color: #22c55e;
      color: #86efac;
    }

    .badge-medium {
      border-color: #f59e0b;
      color: #fcd34d;
    }

    .badge-high {
      border-color: #ef4444;
      color: #fca5a5;
    }

    .badge-critical {
      border-color: #ff4d6d;
      color: #ff9fb3;
    }

    .investigation-graph {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      margin-top: 14px;
    }

    .graph-node {
      min-width: 240px;
      max-width: 420px;
      text-align: center;
      padding: 12px 16px;
      border-radius: 14px;
      background: linear-gradient(180deg, #18202b 0%, #141b24 100%);
      border: 1px solid #2b3545;
      color: #e6edf7;
      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.28);
    }

    .graph-node-kind {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #8fa7c0;
      margin-bottom: 5px;
      font-weight: 800;
    }

    .graph-node-value {
      font-size: 15px;
      font-weight: 800;
      word-break: break-word;
    }


    .graph-arrow {
      color: #7cc4ff;
      font-size: 22px;
      font-weight: 900;
      line-height: 1;
      opacity: 0.9;
    }


    .card{
      margin-top:12px;
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:16px;
      overflow:hidden;
    }
    .card-head{padding:14px 16px;border-bottom:1px solid var(--border);background:var(--panel2);}
    .card-head .h{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;}
    .card-head .h .left{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
    .card-head .h .right{color:var(--muted);font-size:12px;display:flex;gap:10px;flex-wrap:wrap;}
    .card-body{padding:14px 16px;}

    .badge{
      display:inline-block;
      padding:4px 10px;
      border-radius:999px;
      border:1px solid var(--border);
      font-size:11px;
      font-weight:900;
      letter-spacing:0.04em;
      text-transform:uppercase;
    }
    .badge.critical{border-color:rgba(181,108,255,0.65);color:#f0ddff;}
    .badge.high{border-color:rgba(255,107,107,0.65);color:#ffd2d2;}
    .badge.medium{border-color:rgba(247,201,72,0.65);color:#fff0b8;}
    .badge.low{border-color:rgba(77,212,172,0.65);color:#c9fff0;}

    table{width:100%;border-collapse:collapse;margin-top:8px;}
    th,td{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;font-size:13px;}
    th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:0.03em;}
    .muted{color:var(--muted);}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
    .hidden{display:none;}
    details{margin-top:10px;}
    details summary{cursor:pointer;color:var(--muted);font-weight:800;}
    .footer{margin-top:18px;color:var(--muted);font-size:12px;text-align:center;}
  </style>
</head>
<body>
<div class="container">
{% set h = {} %}

  <div class="header">
    <div>
      <div class="title">SOC-Forge Report</div>
      <div class="meta">
        Input: <span class="mono">{{ input_name }}</span> • Generated: {{ generated_at }} • Version: {{ version }}
      </div>
    </div>
    <div class="meta">
      Total Alerts: <strong>{{ stats.total }}</strong>
    </div>
  </div>

  <div class="cards">
    <div class="stat"><div class="k">Critical</div><div class="v">{{ stats.critical }}</div></div>
    <div class="stat"><div class="k">High</div><div class="v">{{ stats.high }}</div></div>
    <div class="stat"><div class="k">Medium</div><div class="v">{{ stats.medium }}</div></div>
    <div class="stat"><div class="k">Low</div><div class="v">{{ stats.low }}</div></div>
  </div>

  <div class="filters">
    <div class="btn active" data-level="all" onclick="setFilter('all')">All</div>
    <div class="btn" data-level="critical" onclick="setFilter('critical')">Critical</div>
    <div class="btn" data-level="high" onclick="setFilter('high')">High</div>
    <div class="btn" data-level="medium" onclick="setFilter('medium')">Medium</div>
    <div class="btn" data-level="low" onclick="setFilter('low')">Low</div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>MITRE Coverage</strong></div>
      </div>
    </div>
    <div class="card-body">
      {% if mitre_coverage and mitre_coverage|length > 0 %}
        <table>
          <thead>
            <tr><th>Tactic</th><th>Rule Count</th></tr>
          </thead>
          <tbody>
            {% for tactic, count in mitre_coverage %}
              <tr><td>{{ tactic }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">No MITRE tactics found in loaded rules.</p>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>Correlation Summary</strong></div>
      </div>
    </div>
    <div class="card-body">
      {% if corr_summary.total > 0 %}
        <p><strong>Correlated alerts:</strong> {{ corr_summary.total }}</p>
        <table>
          <thead>
            <tr><th>Correlation Rule</th><th>Count</th></tr>
          </thead>
          <tbody>
            {% for rid, count in corr_summary.by_rule %}
              <tr><td class="mono muted">{{ rid }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">No correlated alerts in this run.</p>
      {% endif %}
    </div>
  </div>

  {% if stats.total == 0 %}
    <div class="card">
      <div class="card-head">
        <div class="h"><div class="left"><strong>No alerts</strong></div></div>
      </div>
      <div class="card-body muted">No alerts were produced for this input.</div>
    </div>
  {% else %}

    {% if cases and cases|length > 0 %}
      <div class="card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Cases</strong></div>
            <div class="right"><span class="muted">Grouped by correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">

          {% for c in cases %}
            {% set h = c.header %}
            {% set cr = (h.get('details', {}) or {}).get('case_risk', {}) %}

            <div class="case-meta">
            <span class="badge badge-{{ cr.get('case_severity', h.severity)|lower }}">
              {{ cr.get('case_severity', h.severity)|upper }}
            </span>
            <span class="badge">Score: {{ cr.get('case_score', 0) }}</span>
            <span class="badge">Case: {{ h.correlation_id }}</span>
            <span class="badge">Alerts: {{ cr.get('alert_count', 0) }}</span>
          </div>

            {% set actions = (h.get('details', {}) or {}).get('recommended_actions', []) %}
            {% if actions %}
              <div class="case-section">
                <h3>Recommended Actions</h3>
                <ul class="checklist">
                  {% for a in actions %}
                    <li>
                      <label>
                        <input type="checkbox" />
                        <span>{{ a }}</span>
                      </label>
                    </li>
                  {% endfor %}
                </ul>
              </div>
            {% endif %}

            <div class="card case-card" style="margin:10px 0;">
              <div class="card-head">
                <div class="h">
                  <div class="left">
                    <span class="badge {{ h.get('severity','')|lower }}">{{ h.get('severity','') }}</span>
                    <strong>{{ h.get('title','') }}</strong>
                  </div>
                  <div class="right">
                    <span>Case: <span class="mono">{{ c.correlation_id }}</span></span>
                    <span>Time: <span class="mono">{{ h.get('timestamp','') }}</span></span>
                    <span>Score: <span class="mono">{{ cr.get('case_score', 0) }}</span></span>
                    <span>Threat: <span class="badge {{ cr.get('case_threat_level','low') }}">{{ cr.get('case_threat_level','low') }}</span></span>
                  </div>
                </div>
              </div>

              <div class="card-body">
                {# --- Attack Chain --- #}
                {% set chain = c.get('attack_chain', {}) %}
                {% set tactics = chain.get('tactics', []) %}
                {% if tactics and tactics|length > 0 %}
                  <div style="margin-top:10px;">
                    <div class="muted" style="font-weight:900;">Attack Chain</div>

                    <div class="chain">
                      {% for t in tactics %}
                        <span class="node">{{ t }}</span>
                        {% if not loop.last %}<span class="arrow">→</span>{% endif %}
                      {% endfor %}
                    </div>

                    <details>
                      <summary>Why these stages?</summary>
                      <table>
                        <thead>
                          <tr>
                            <th>Tactic</th>
                            <th>First Seen</th>
                            <th>Description</th>
                            <th>Evidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {% for t in tactics %}
                            {% set bt = (chain.get('by_tactic', {}) or {}).get(t, {}) %}
                            <tr>
                              <td class="muted"><strong>{{ t }}</strong></td>
                              <td class="mono muted">{{ bt.get('first_seen', '') }}</td>
                              <td class="muted">{{ bt.get('description', '') }}</td>
                              <td>
                                {% set events = bt.get('events', []) %}
                                {% if events and events|length > 0 %}
                                  <ul style="margin:0; padding-left:18px;">
                                    {% for e in events %}
                                      <li class="muted">
                                        <span class="mono">{{ e.get('timestamp', '') }}</span> —
                                        <span class="mono">{{ e.get('rule_id', '') }}</span> —
                                        {{ e.get('title', '') }}
                                      </li>
                                    {% endfor %}
                                  </ul>
                                {% else %}
                                  <span class="muted">No evidence rows</span>
                                {% endif %}
                              </td>
                            </tr>
                          {% endfor %}
                        </tbody>
                      </table>
                    </details>
                  </div>
                {% endif %}
                {% if c.attack_flow %}
                  <div class="case-section">
                    <h3>Attack Flow</h3>
                    <div class="attack-flow">
                      {% for step in c.attack_flow %}
                        <div class="flow-step">
                          <div class="flow-label">{{ step.label }}</div>

                          {% if step.mitre_ids %}
                            <div class="flow-mitre">
                              {% for mid in step.mitre_ids %}
                                <span class="mitre-tag mono">{{ mid }}</span>
                              {% endfor %}
                            </div>
                          {% endif %}

                          <div class="flow-meta">
                            <span class="badge {{ step.severity }}">{{ step.severity }}</span>
                            <span class="mono">{{ step.timestamp }}</span>
                          </div>
                        </div>

                        {% if not loop.last %}
                          <div class="flow-arrow">→</div>
                        {% endif %}
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}

                {% if mitre_coverage and mitre_coverage|length > 0 %}
                  <div class="mitre-panel">
                    <div style="font-weight:900; font-size:18px;">MITRE Coverage</div>
                    <div class="muted" style="margin-top:4px;">
                      Tactic distribution across matched detections in this investigation.
                    </div>

                    {% set max_count = mitre_coverage[0][1] %}

                    {% for tactic, count in mitre_coverage %}
                      {% set width_pct = (count * 100 / max_count)|int %}
                      <div class="mitre-row">
                        <div class="mitre-label">{{ tactic }}</div>
                        <div class="mitre-bar-wrap">
                          <div class="mitre-bar" style="width: {{ width_pct }}%;"></div>
                        </div>
                        <div class="mitre-count">{{ count }}</div>
                      </div>
                    {% endfor %}
                  </div>
                {% endif %}


                {% set path = (h.get('details', {}) or {}).get('attack_path', []) %}

                {% if path and path|length > 0 %}
                  <div class="panel">
                    <div style="font-weight:900; font-size:18px;">Attack Graph</div>
                    <div class="muted" style="margin-top:4px;">
                      Relationship path between source, identity, host, and attacker actions.
                    </div>

                    <div class="investigation-graph">
                      {% for node in path %}
                        <div class="graph-node {{ node['type'] }}">
                          <div class="graph-node-kind">{{ node.type|upper }}</div>
                          <div class="graph-node-value">{{ node.label }}</div>
                        </div>
                        {% if not loop.last %}
                          <div class="graph-arrow">↓</div>
                        {% endif %}
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}



                {# Phase 5: Analyst Summary #}
                {% set analyst_summary = (h.get('details', {}) or {}).get('analyst_summary', '') %}
                {% if analyst_summary %}
                  <div style="margin-bottom:10px;">
                    <div class="muted" style="font-weight:900;">Analyst Summary</div>
                    <div style="margin-top:6px;">{{ analyst_summary }}</div>
                  </div>
                {% endif %}

                {# Phase 5: IOCs #}
                {% set iocs = (h.get('details', {}) or {}).get('iocs', {}) %}
                <div style="margin-top:10px;">
                  <div class="muted" style="font-weight:900;">Indicators (IOCs)</div>
                  <table>
                    <thead><tr><th>Type</th><th>Values</th></tr></thead>
                    <tbody>
                      <tr>
                        <td class="muted">IPs</td>
                        <td class="mono muted">
                          {% set ips = iocs.get('ips', []) %}
                          {% if ips and ips|length > 0 %}{{ ips|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                      <tr>
                        <td class="muted">Hosts</td>
                        <td class="mono muted">
                          {% set hosts = iocs.get('hosts', []) %}
                          {% if hosts and hosts|length > 0 %}{{ hosts|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                      <tr>
                        <td class="muted">Users</td>
                        <td class="mono muted">
                          {% set users = iocs.get('users', []) %}
                          {% if users and users|length > 0 %}{{ users|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {# Phase 5: Timeline #}
                {% set timeline = (h.get('details', {}) or {}).get('timeline', []) %}
                {% if timeline and timeline|length > 0 %}
                  <details>
                    <summary>Timeline ({{ timeline|length }} events)</summary>
                    <table>
                      <thead><tr><th>Timestamp</th><th>Rule</th><th>Title</th><th>Severity</th></tr></thead>
                      <tbody>
                        {% for t in timeline %}
                          <tr>
                            <td class="mono muted">{{ t.get('timestamp','') }}</td>
                            <td class="mono muted">{{ t.get('rule_id','') }}</td>
                            <td>{{ t.get('title','') }}</td>
                            <td><span class="badge {{ t.get('severity','')|lower }}">{{ t.get('severity','') }}</span></td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  </details>
                {% endif %}

                {# Existing: Evidence #}
                {% if c.evidence %}
                  <div class="case-section">
                    <h3>Evidence</h3>
                    <div class="evidence-list">
                      {% for ev in c.evidence %}
                        <div class="evidence-item">
                          <div class="evidence-head">
                            <span class="mono">{{ ev.timestamp }}</span>
                            <span class="badge {{ ev.severity|lower }}">{{ ev.severity }}</span>
                            <strong>{{ ev.rule_id }}</strong>
                            <span>{{ ev.title }}</span>
                          </div>

                          {% if ev.fields %}
                            <div class="evidence-fields">
                              {% for label, value in ev.fields %}
                                <span class="kv">
                                  <span class="k">{{ label }}</span>
                                  <span class="v mono">{{ value }}</span>
                                </span>
                              {% endfor %}
                            </div>
                          {% endif %}
                        </div>
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}

                {# Per-case scoring reasons (moved INSIDE loop so no undefined vars) #}
                {% if cr and cr.get('reasons') %}
                  <details>
                    <summary>Case scoring reasons</summary>
                    <ul>
                      {% for r in cr.get('reasons') %}
                        <li class="muted">{{ r }}</li>
                      {% endfor %}
                    </ul>
                  </details>
                {% endif %}

                <div class="muted" style="margin-top:10px;font-weight:900;">Alerts in this case</div>
                <table>
                  <thead>
                    <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th></tr>
                  </thead>
                  <tbody>
                    {% for a in c.alerts %}
                      <tr data-sev="{{ a.get('severity','')|lower }}">
                        <td class="mono muted">{{ a.get('timestamp','') }}</td>
                        <td><span class="badge {{ a.get('severity','')|lower }}">{{ a.get('severity','') }}</span></td>
                        <td class="mono muted">{{ a.get('rule_id','') }}</td>
                        <td>{{ a.get('title','') }}</td>
                        <td class="mono muted"><strong>{{ a.get('score',0) }}</strong></td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>

              </div>
            </div>
          {% endfor %}

        </div>
      </div>
    {% endif %}

    {% if standalone and standalone|length > 0 %}
      <div class="card standalone-card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Standalone Alerts</strong></div>
            <div class="right"><span class="muted">No correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">
          <table>
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th></tr>
            </thead>
            <tbody>
              {% for a in standalone %}
                <tr data-sev="{{ a.get('severity','')|lower }}">
                  <td class="mono muted">{{ a.get('timestamp','') }}</td>
                  <td><span class="badge {{ a.get('severity','')|lower }}">{{ a.get('severity','') }}</span></td>
                  <td class="mono muted">{{ a.get('rule_id','') }}</td>
                  <td>{{ a.get('title','') }}</td>
                  <td class="mono muted"><strong>{{ a.get('score',0) }}</strong></td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    {% endif %}

  {% endif %}

  <div class="footer">SOC-Forge • Case-based report view</div>

</div>

<script>
  function setFilter(level) {
    document.querySelectorAll(".btn").forEach(b => b.classList.remove("active"));
    const btn = document.querySelector(`.btn[data-level="${level}"]`);
    if (btn) btn.classList.add("active");

    // Filter rows
    document.querySelectorAll("tr[data-sev]").forEach(tr => {
      const sev = (tr.getAttribute("data-sev") || "").toLowerCase();
      const show = (level === "all" || sev === level);
      tr.classList.toggle("hidden", !show);
    });

    // Show/hide case cards based on visible rows
    document.querySelectorAll(".case-card").forEach(card => {
      if (level === "all") {
        card.classList.remove("hidden");
        return;
      }
      const visibleRows = card.querySelectorAll("tr[data-sev]:not(.hidden)");
      card.classList.toggle("hidden", visibleRows.length === 0);
    });

    // Same for standalone card
    document.querySelectorAll(".standalone-card").forEach(card => {
      if (level === "all") {
        card.classList.remove("hidden");
        return;
      }
      const visibleRows = card.querySelectorAll("tr[data-sev]:not(.hidden)");
      card.classList.toggle("hidden", visibleRows.length === 0);
    });
  }

  setFilter("all");
</script>

</body>
</html>"""
)

def choose_case_header_alert(items_sorted: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Pick the best alert to represent the case header.
    Prefer:
      1. correlation alerts
      2. highest score
      3. earliest timestamp
    """
    if not items_sorted:
        return {}

    def sort_key(a: Dict[str, Any]):
        rule_id = str(a.get("rule_id", ""))
        is_corr = 1 if "CORR" in rule_id else 0
        score = int(a.get("score", 0) or 0)
        ts = str(a.get("timestamp", "") or "")
        return (-is_corr, -score, ts == "", ts)

    return sorted(items_sorted, key=sort_key)[0]


def build_case_iocs(items_sorted: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ips: List[str] = []
    hosts: List[str] = []
    users: List[str] = []

    def add_unique(bucket: List[str], value: Any) -> None:
        if value is None:
            return
        s = str(value).strip()
        if not s:
            return
        if s not in bucket:
            bucket.append(s)

    for it in items_sorted:
        details = it.get("details", {}) or {}
        event = it.get("event", {}) or {}

        add_unique(ips, it.get("src_ip"))
        add_unique(ips, it.get("ip"))
        add_unique(ips, details.get("src_ip"))
        add_unique(ips, details.get("ip"))
        add_unique(ips, event.get("src_ip"))
        add_unique(ips, event.get("ip"))

        add_unique(hosts, it.get("host"))
        add_unique(hosts, details.get("host"))
        add_unique(hosts, event.get("host"))
        add_unique(hosts, event.get("computer"))
        add_unique(hosts, event.get("computer_name"))

        add_unique(users, it.get("username"))
        add_unique(users, details.get("username"))
        add_unique(users, event.get("username"))
        add_unique(users, event.get("target_user"))
        add_unique(users, event.get("account_name"))

    return {
        "ips": ips,
        "hosts": hosts,
        "users": users,
    }

def build_cases(alerts: List[Dict[str, Any]], input_name: str) -> List[Dict[str, Any]]:
    """
    Build case objects that can be used by:
      - HTML report rendering
      - JSON export
    """
    grouped = defaultdict(list)
    for a in alerts:
        cid = a.get("correlation_id") or "UNCORRELATED"
        grouped[cid].append(a)

    cases: List[Dict[str, Any]] = []

    for correlation_id, items in grouped.items():
        items_sorted = sorted(items, key=lambda x: str(x.get("timestamp", "")))
        header_alert = choose_case_header_alert(items_sorted)

        attack_flow = build_attack_flow(items_sorted)
        attack_graph = build_attack_graph(items_sorted)
        attack_path = build_attack_path(attack_graph)

        attack_chain = build_attack_chain(items_sorted)
        iocs = build_case_iocs(items_sorted)
        case_risk = build_case_risk_fallback(items_sorted)
       

        analyst_summary = build_analyst_summary(items_sorted)

        timeline = [
            {
                "timestamp": it.get("timestamp", ""),
                "rule_id": it.get("rule_id", ""),
                "title": it.get("title", ""),
                "severity": it.get("severity", ""),
            }
            for it in items_sorted
        ]
        
        header = {
            "correlation_id": correlation_id,
            "input_name": input_name,
            "title": header_alert.get("title", "Untitled Case"),
            "severity": header_alert.get("severity", "low"),
            "timestamp": header_alert.get("timestamp", ""),
            "score": int(header_alert.get("score", 0) or 0),
            "details": {
                "recommended_actions": build_recommended_actions(items_sorted),
                "case_risk": case_risk,
                "attack_flow": attack_flow,
                "attack_graph": attack_graph,
                "attack_path": attack_path,
                "attack_chain": attack_chain,
                "iocs": iocs,
                "timeline": timeline,
                "analyst_summary": analyst_summary,
            },
        }


        

        evidence = []
        for it in items_sorted:
            evidence.append(
                {
                    "timestamp": it.get("timestamp", ""),
                    "rule_id": it.get("rule_id", ""),
                    "title": it.get("title", ""),
                    "severity": it.get("severity", ""),
                    "fields": build_evidence_fields(it),
                }
            )

        cases.append(
            {
                "correlation_id": correlation_id,
                "header": header,
                "timeline": timeline,
                "attack_flow": attack_flow,
                "attack_graph": attack_graph,
                "attack_path": attack_path,
                "attack_chain": attack_chain,
                "iocs": iocs,
                "evidence": evidence,
                "alerts": items_sorted,
            }
        )


    cases.sort(key=lambda c: c["correlation_id"])
    return cases

def write_html_report(
    alerts: List[Dict[str, Any]],
    output_path: Path,
    input_name: str,
    mitre_coverage: List[Tuple[str, int]] | None = None,
    corr_summary: Dict[str, Any] | None = None,
) -> None:

    # Sort newest-first
    alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""), reverse=True)

    cases = build_cases(alerts, input_name)

    # Severity stats
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts_sorted:
        sev = str(a.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    stats = {
        "total": len(alerts_sorted),
        "critical": sev_counts["critical"],
        "high": sev_counts["high"],
        "medium": sev_counts["medium"],
        "low": sev_counts["low"],
    }

    # -------------------------
    # Group into cases + standalone
    # -------------------------
    cases_map: Dict[str, List[Dict[str, Any]]] = {}
    standalone: List[Dict[str, Any]] = []

    for a in alerts_sorted:
        cid = a.get("correlation_id")
        if cid:
            cases_map.setdefault(str(cid), []).append(a)
        else:
            standalone.append(a)

    # -------------------------
    # Build cases (dedup + risk scoring + Phase 5 enrich)
    # -------------------------
    cases: List[Dict[str, Any]] = []

    for cid, items in cases_map.items():
        seen = set()
        dedup: List[Dict[str, Any]] = []
        for a in items:
            key = (a.get("rule_id"), a.get("timestamp"))
            if key in seen:
                continue
            seen.add(key)
            dedup.append(a)

        # Keep case alerts newest-first for the alerts table
        items_sorted = sorted(dedup, key=lambda x: x.get("timestamp", ""), reverse=True)

        header = next(
            (x for x in items_sorted if str(x.get("rule_id", "")).startswith("SOCF-CORR")),
            items_sorted[0],
        )

        case_risk = score_case(items_sorted)

        header = dict(header)
        header.setdefault("details", {})
        header["details"]["case_risk"] = case_risk

        # -------------------------
        # Phase 5 additions
        # -------------------------
        header["details"]["timeline"] = build_case_timeline(items_sorted)
        header["details"]["iocs"] = extract_case_iocs(items_sorted)
        header["details"]["analyst_summary"] = build_analyst_summary(items_sorted)
        header["details"]["attack_chain"] = build_attack_chain(items_sorted)
        header["details"]["recommended_actions"] = build_recommended_actions(items_sorted)

        cases.append({"correlation_id": cid, "header": header, "alerts": items_sorted})

    cases = build_cases(alerts, input_name)

    html = HTML_TEMPLATE.render(
        cases=cases,
        standalone=standalone,
        stats=stats,
        input_name=input_name,
        mitre_coverage=mitre_coverage or [],
        corr_summary=corr_summary or {"total": 0, "by_rule": []},
        version=__version__,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")