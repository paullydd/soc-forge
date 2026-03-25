from __future__ import annotations
from datetime import datetime

from collections import Counter
from typing import Any, Dict, List

def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None

    text = str(value).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _fmt_time(value: Any) -> str:
    dt = _parse_ts(value)
    if not dt:
        return str(value or "")
    return dt.strftime("%H:%M")


def _item_timestamp(item: Dict[str, Any]) -> str:
    if item.get("timestamp"):
        return str(item["timestamp"])
    if item.get("first_seen"):
        return str(item["first_seen"])
    if item.get("last_seen"):
        return str(item["last_seen"])
    return ""


def _item_rule_phrase(item: Dict[str, Any]) -> str:
    rid = str(item.get("rule_id", ""))
    hid = str(item.get("hunt_id", ""))

    if rid and rid in RULE_PHRASES:
        return RULE_PHRASES[rid]
    if hid and hid in RULE_PHRASES:
        return RULE_PHRASES[hid]

    title = str(item.get("title", "")).strip()
    if title:
        return title.lower()

    summary = str(item.get("summary", "")).strip()
    if summary:
        return summary.lower()

    return "suspicious activity was observed"

def build_timeline_narrative(
    alerts: List[Dict[str, Any]],
    hunts: List[Dict[str, Any]],
) -> str:
    items: List[Dict[str, Any]] = []

    for a in alerts:
        items.append(
            {
                "timestamp": _item_timestamp(a),
                "phrase": _item_rule_phrase(a),
                "username": a.get("username") or a.get("user") or a.get("target_user"),
                "host": a.get("host") or a.get("hostname") or a.get("computer_name"),
                "src_ip": a.get("src_ip") or a.get("source_ip") or a.get("ip_address"),
            }
        )

    for h in hunts:
        entities = h.get("entities", {}) or {}
        items.append(
            {
                "timestamp": _item_timestamp(h),
                "phrase": _item_rule_phrase(h),
                "username": entities.get("username"),
                "host": entities.get("host"),
                "src_ip": entities.get("src_ip"),
            }
        )

    ordered = sorted(
        items,
        key=lambda x: _parse_ts(x.get("timestamp")) or datetime.max,
    )

    lines: List[str] = []
    for item in ordered[:4]:
        ts = _fmt_time(item.get("timestamp"))
        phrase = item.get("phrase", "suspicious activity was observed")
        user = item.get("username")
        host = item.get("host")
        src_ip = item.get("src_ip")

        sentence = f"At {ts}, {phrase}"

        extras = []
        if user:
            extras.append(f"user {user}")
        if host:
            extras.append(f"host {host}")
        if src_ip:
            extras.append(f"source IP {src_ip}")

        if extras:
            sentence += f" involving {', '.join(extras)}"

        sentence += "."
        lines.append(sentence)

    return " ".join(lines).strip()


RULE_PHRASES = {
    "SOCF-001": "multiple failed logon attempts were detected",
    "SOCF-002": "an account lockout occurred",
    "SOCF-003": "a privileged group membership change occurred",
    "SOCF-004": "a suspicious new service was installed",
    "SOCF-005": "a scheduled task was created",
    "SOCF-006": "an RDP logon was observed",
    "SOCF-007": "a new user account was created",
    "SOCF-008": "a privileged group change was detected",
    "SOCF-009": "audit logs were cleared",
    "SOCF_CORR_001": "a brute force sequence followed by account lockout was correlated",
    "SOCF_CORR_002": "RDP activity followed by scheduled task creation was correlated",
    "SOCF_CORR_003": "RDP activity followed by privileged changes was correlated",
    "HUNT-001": "a suspicious command execution was observed",
    "HUNT-002": "the user authenticated from an unusual source IP",
    "HUNT-003": "the user accessed multiple hosts in a short period",
    "HUNT-004": "a burst of failed logins was observed",
}

MITRE_MAP = {
    "SOCF-001": ["Credential Access"],
    "SOCF-002": ["Credential Access"],
    "SOCF-003": ["Privilege Escalation"],
    "SOCF-004": ["Persistence"],
    "SOCF-005": ["Execution"],
    "SOCF-006": ["Initial Access"],
    "SOCF-007": ["Persistence"],
    "SOCF-008": ["Privilege Escalation"],
    "SOCF-009": ["Defense Evasion"],
    "SOCF_CORR_001": ["Credential Access"],
    "SOCF_CORR_002": ["Execution", "Lateral Movement"],
    "SOCF_CORR_003": ["Privilege Escalation", "Lateral Movement"],
    "HUNT-001": ["Execution"],
    "HUNT-002": ["Initial Access"],
    "HUNT-003": ["Lateral Movement"],
    "HUNT-004": ["Credential Access"],
}


def _uniq(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        if not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _collect_entities(items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    users = []
    hosts = []
    ips = []

    for item in items:
        users.append(str(item.get("username") or item.get("user") or item.get("target_user") or ""))
        hosts.append(str(item.get("host") or item.get("hostname") or item.get("computer_name") or ""))
        ips.append(str(item.get("src_ip") or item.get("source_ip") or item.get("ip_address") or ""))

        entities = item.get("entities", {})
        if isinstance(entities, dict):
            users.append(str(entities.get("username") or ""))
            hosts.append(str(entities.get("host") or ""))
            ips.append(str(entities.get("src_ip") or ""))

            host_list = entities.get("hosts")
            if isinstance(host_list, list):
                hosts.extend(str(h) for h in host_list if h)

    return {
        "users": _uniq([u for u in users if u and u != "None"]),
        "hosts": _uniq([h for h in hosts if h and h != "None"]),
        "ips": _uniq([ip for ip in ips if ip and ip != "None"]),
    }


def _top_phrases(alerts: List[Dict[str, Any]], hunts: List[Dict[str, Any]]) -> List[str]:
    phrases: List[str] = []

    for a in alerts:
        rid = str(a.get("rule_id", ""))
        phrase = RULE_PHRASES.get(rid)
        if phrase:
            phrases.append(phrase)

    for h in hunts:
        hid = str(h.get("hunt_id", ""))
        phrase = RULE_PHRASES.get(hid)
        if phrase:
            phrases.append(phrase)

    counts = Counter(phrases)
    return [p for p, _ in counts.most_common(4)]


def build_case_story(
    case: Dict[str, Any],
    related_hunts: List[Dict[str, Any]] | None = None,
) -> str:
    related_hunts = related_hunts or []
    alerts = case.get("alerts", []) or []

    entities = _collect_entities(alerts + related_hunts)
    users = entities["users"]
    hosts = entities["hosts"]
    ips = entities["ips"]

    phrases = _top_phrases(alerts, related_hunts)
    timeline_text = build_timeline_narrative(alerts, related_hunts)
    tactics = extract_mitre_tactics(alerts, related_hunts)
    mitre_sentence = build_mitre_sentence(tactics)

    parts: List[str] = []

    if users:
        parts.append(f"User activity centered on {', '.join(users[:2])}.")
    elif hosts:
        parts.append(f"Suspicious activity was concentrated on {', '.join(hosts[:2])}.")

    if timeline_text:
        parts.append(timeline_text)
    if mitre_sentence:
        parts.append(mitre_sentence)
    elif phrases:
        if len(phrases) == 1:
            parts.append(f"In this case, {phrases[0]}.")
        else:
            joined = ", then ".join(phrases[:3])
            parts.append(f"The observed sequence suggests that {joined}.")

    if ips:
        parts.append(f"Relevant source IPs included {', '.join(ips[:2])}.")

    if len(hosts) >= 2:
        parts.append(
            f"Activity involved multiple hosts, including {', '.join(hosts[:3])}, which may indicate movement between systems."
        )

    risk = case.get("case_risk") or case.get("header", {}).get("details", {}).get("case_risk") or {}
    risk_level = str(risk.get("level") or "").lower()
    risk_score = risk.get("score")

    if risk_level and risk_score is not None:
        parts.append(f"Overall case risk is {risk_level} with a score of {risk_score}.")
    elif risk_level:
        parts.append(f"Overall case risk is {risk_level}.")

    if related_hunts:
        hunt_titles = _uniq([str(h.get("title", "")) for h in related_hunts if h.get("title")])
        if hunt_titles:
            parts.append(f"Related hunt findings include {', '.join(hunt_titles[:3])}.")

    return " ".join(parts).strip()

def match_hunts_to_case(case: Dict[str, Any], hunts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = case.get("alerts", []) or []
    case_entities = _collect_entities(alerts)

    case_users = set(case_entities["users"])
    case_hosts = set(case_entities["hosts"])
    case_ips = set(case_entities["ips"])

    matched: List[Dict[str, Any]] = []

    for hunt in hunts:
        entities = hunt.get("entities", {}) or {}
        hunt_users = set()
        hunt_hosts = set()
        hunt_ips = set()

        if entities.get("username"):
            hunt_users.add(str(entities["username"]))
        if entities.get("host"):
            hunt_hosts.add(str(entities["host"]))
        if entities.get("src_ip"):
            hunt_ips.add(str(entities["src_ip"]))

        host_list = entities.get("hosts")
        if isinstance(host_list, list):
            hunt_hosts.update(str(h) for h in host_list if h)

        if case_users & hunt_users or case_hosts & hunt_hosts or case_ips & hunt_ips:
            matched.append(hunt)

    return matched


def attach_case_stories(
    cases: List[Dict[str, Any]],
    hunts: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    hunts = hunts or []

    for case in cases:
        related_hunts = match_hunts_to_case(case, hunts)
        case["related_hunts"] = related_hunts
        case["story"] = build_case_story(case, related_hunts)

    return cases

def extract_mitre_tactics(
    alerts: List[Dict[str, Any]],
    hunts: List[Dict[str, Any]],
) -> List[str]:
    tactics = []

    for a in alerts:
        rid = str(a.get("rule_id", ""))
        tactics.extend(MITRE_MAP.get(rid, []))

    for h in hunts:
        hid = str(h.get("hunt_id", ""))
        tactics.extend(MITRE_MAP.get(hid, []))

    # deduplicate while preserving order
    seen = set()
    unique = []
    for t in tactics:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique

def build_mitre_sentence(tactics: List[str]) -> str:
    if not tactics:
        return ""

    if len(tactics) == 1:
        return f"This activity aligns with {tactics[0]} behavior."

    if len(tactics) == 2:
        return f"This activity aligns with {tactics[0]} and {tactics[1]} behavior."

    return f"This activity aligns with {', '.join(tactics[:-1])}, and {tactics[-1]} behavior."