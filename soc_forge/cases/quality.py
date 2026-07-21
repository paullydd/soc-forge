from __future__ import annotations

from typing import Any, Dict, Iterable, List


CORRELATION_RULE_NOTES = {
    "SOCF-CORR-001": "Authentication failures were correlated with account lockout activity.",
    "SOCF-CORR-002": "RDP activity was followed by scheduled task creation, which can indicate hands-on-keyboard persistence.",
    "SOCF-CORR-003": "RDP activity was followed by privileged account or group activity.",
    "SOCF-CORR-004": "New account creation was followed by privileged group assignment.",
    "SOCF-CORR-005": "Account creation, privilege escalation, and log clearing appeared in the same sequence.",
    "SOCF-CORR-006": "Office-launched scripting behavior correlated with suspicious command execution.",
    "SOCF-CORR-007": "Suspicious script execution was followed by credential dumping or LSASS access.",
    "SOCF-CORR-008": "Suspicious process activity was followed by browser credential store access.",
    "SOCF-CORR-009": "RDP activity was followed by PsExec-style service execution, increasing confidence in lateral movement.",
    "SOCF-CORR-010": "WMI execution was followed by suspicious command execution, suggesting remote execution with follow-on activity.",
    "SOCF-CORR-011": "Credential access was followed by archive staging, which can indicate collection or exfiltration preparation.",
    "SOCF-CORR-012": "Lateral movement activity was followed by credential access on the same host or user context.",
    "SOCF-CORR-013": "Administrative share execution was followed by persistence or archive staging behavior.",
}

RULE_FINDINGS = {
    "SOCF-002": "Account lockout activity may indicate credential attack pressure or account misuse.",
    "SOCF-003": "Privileged group membership changed and should be validated against approved administration.",
    "SOCF-004": "A new service was installed, which may indicate persistence or remote execution.",
    "SOCF-005": "A scheduled task was created and should be reviewed for persistence or suspicious commands.",
    "SOCF-006": "An RDP logon was observed and should be validated against expected remote access.",
    "SOCF-007": "A new user account was created and should be tied to an approved change.",
    "SOCF-008": "A user was added to a privileged or sensitive group.",
    "SOCF-009": "Audit logs were cleared, which can indicate defense evasion or evidence removal.",
    "SOCF-010": "Failed logons matched password spray behavior.",
    "SOCF-011": "PowerShell executed with encoded, hidden, or download-cradle style arguments.",
    "SOCF-012": "A process launched from a user-writable path, which can indicate staged malware or masquerading.",
    "SOCF-013": "An Office application spawned a script interpreter or command shell, which can indicate malicious document execution.",
    "SOCF-014": "Credential dumping or LSASS access behavior was observed and should be treated as high-risk credential access.",
    "SOCF-015": "A non-browser process accessed a browser credential store, which can indicate credential theft.",
    "SOCF-016": "PsExec-style service execution behavior was observed and may indicate lateral movement through remote services.",
    "SOCF-017": "WMI process execution was observed and should be reviewed for remote execution or lateral movement.",
    "SOCF-018": "A commonly abused Windows binary executed suspicious script or remote-content behavior.",
    "SOCF-019": "Execution from an administrative share was observed and may indicate remote staging or lateral movement.",
    "SOCF-020": "Archive tooling staged sensitive-looking files, which can indicate collection or exfiltration preparation.",
}


def _known(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "n/a"}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def _details(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("details")
    return value if isinstance(value, dict) else {}


def _event(item: Dict[str, Any]) -> Dict[str, Any]:
    value = item.get("event")
    return value if isinstance(value, dict) else {}


def _first_known(item: Dict[str, Any], fields: Iterable[str]) -> str:
    details = _details(item)
    event = _event(item)
    for field in fields:
        for source in (item, details, event):
            value = source.get(field)
            if _known(value):
                return str(value).strip()
    return ""


def _unique(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        if not _known(value):
            continue
        text = str(value).strip()
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def collect_case_entities(items: List[Dict[str, Any]], iocs: Dict[str, Any] | None = None) -> Dict[str, List[str]]:
    iocs = iocs or {}
    users: List[Any] = list(_as_list(iocs.get("users")))
    hosts: List[Any] = list(_as_list(iocs.get("hosts")))
    ips: List[Any] = list(_as_list(iocs.get("ips")))

    for item in items:
        users.append(_first_known(item, ["username", "user", "actor", "target_user", "account_name"]))
        hosts.append(_first_known(item, ["host", "hostname", "computer", "computer_name"]))
        ips.append(_first_known(item, ["src_ip", "source_ip", "ip", "ip_address"]))

    return {
        "users": _unique(users),
        "hosts": _unique(hosts),
        "ips": _unique(ips),
    }


def _extract_tactics(items: List[Dict[str, Any]], case_risk: Dict[str, Any] | None = None) -> List[str]:
    tactics: List[str] = []
    if isinstance(case_risk, dict):
        tactics.extend(_as_list(case_risk.get("tactics")))

    for item in items:
        for mapping in item.get("mitre", []) or []:
            if isinstance(mapping, dict):
                tactics.append(mapping.get("tactic"))

    return _unique(tactics)


def _time_window(items: List[Dict[str, Any]]) -> str:
    timestamps = sorted(str(item.get("timestamp") or "") for item in items if _known(item.get("timestamp")))
    if not timestamps:
        return "No timestamp available"
    if len(timestamps) == 1 or timestamps[0] == timestamps[-1]:
        return timestamps[0]
    return f"{timestamps[0]} to {timestamps[-1]}"


def _top_alert(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not items:
        return {}

    def key(item: Dict[str, Any]) -> tuple[int, int, str]:
        rule_id = str(item.get("rule_id") or "")
        score = int(item.get("score") or 0)
        return (1 if "CORR" in rule_id else 0, score, str(item.get("timestamp") or ""))

    return sorted(items, key=key, reverse=True)[0]


def build_executive_summary(items: List[Dict[str, Any]], case_risk: Dict[str, Any] | None = None, iocs: Dict[str, Any] | None = None) -> str:
    entities = collect_case_entities(items, iocs)
    tactics = _extract_tactics(items, case_risk)
    top = _top_alert(items)
    top_title = str(top.get("title") or "suspicious activity")
    risk_score = ""
    threat = ""
    if isinstance(case_risk, dict):
        risk_score = str(case_risk.get("case_score") or "")
        threat = str(case_risk.get("case_threat_level") or case_risk.get("case_severity") or "")

    parts: List[str] = []
    if threat and risk_score:
        parts.append(f"This is a {threat.lower()} case with risk score {risk_score}.")
    elif threat:
        parts.append(f"This is a {threat.lower()} case.")
    else:
        parts.append("This case contains related security activity that needs analyst review.")

    parts.append(f"The strongest signal is: {top_title}.")

    if tactics:
        parts.append(f"Observed ATT&CK tactics include {', '.join(tactics[:4])}.")

    entity_bits = []
    if entities["users"]:
        entity_bits.append(f"users {', '.join(entities['users'][:3])}")
    if entities["hosts"]:
        entity_bits.append(f"hosts {', '.join(entities['hosts'][:3])}")
    if entities["ips"]:
        entity_bits.append(f"IPs {', '.join(entities['ips'][:3])}")
    if entity_bits:
        parts.append("Key entities include " + "; ".join(entity_bits) + ".")

    parts.append(f"The observed window is {_time_window(items)}.")
    return " ".join(parts)


def build_key_findings(items: List[Dict[str, Any]]) -> List[str]:
    findings: List[str] = []
    rule_ids = [str(item.get("rule_id") or "") for item in items]

    for rule_id in rule_ids:
        note = CORRELATION_RULE_NOTES.get(rule_id) or RULE_FINDINGS.get(rule_id)
        if note and note not in findings:
            findings.append(note)

    if len([rid for rid in rule_ids if rid.startswith("SOCF-CORR")]) > 0:
        findings.append("At least one correlation rule fired, increasing confidence that this is a related activity chain rather than a single isolated event.")

    if len(items) >= 4:
        findings.append("The case contains multiple alerts, which provides enough evidence to build a timeline and compare entity overlap.")

    return findings[:6]


def build_key_evidence(items: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    evidence: List[Dict[str, str]] = []
    for item in sorted(items, key=lambda x: str(x.get("timestamp") or "")):
        rule_id = str(item.get("rule_id") or "")
        title = str(item.get("title") or "Untitled alert")
        severity = str(item.get("severity") or "").upper()
        timestamp = str(item.get("timestamp") or "")
        reason = CORRELATION_RULE_NOTES.get(rule_id) or RULE_FINDINGS.get(rule_id) or "This alert contributes to the case timeline."
        evidence.append(
            {
                "timestamp": timestamp,
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "why_it_matters": reason,
            }
        )
    return evidence[:8]


def build_containment_guidance(items: List[Dict[str, Any]], iocs: Dict[str, Any] | None = None) -> List[str]:
    rule_ids = {str(item.get("rule_id") or "") for item in items}
    entities = collect_case_entities(items, iocs)
    guidance: List[str] = []

    if rule_ids & {"SOCF-007", "SOCF-008", "SOCF-CORR-004", "SOCF-CORR-005"}:
        guidance.append("Validate account and group changes against approved change records; disable unauthorized accounts and remove unauthorized privileged membership.")
    if rule_ids & {"SOCF-006", "SOCF-CORR-002", "SOCF-CORR-003"}:
        guidance.append("Confirm whether the RDP session was expected and review endpoint telemetry around the first remote logon.")
    if rule_ids & {"SOCF-005"}:
        guidance.append("Inspect scheduled task name, trigger, author, and command line; remove the task if it is not approved.")
    if rule_ids & {"SOCF-009", "SOCF-CORR-005"}:
        guidance.append("Preserve alternate telemetry immediately because audit log clearing may have removed local evidence.")
    if rule_ids & {"SOCF-013"}:
        guidance.append("Collect the parent/child process tree and preserve the source document or email that launched the script interpreter.")
    if rule_ids & {"SOCF-014"}:
        guidance.append("Treat possible credential dumping as critical: isolate the host, preserve memory/process evidence, and reset exposed credentials.")
    if rule_ids & {"SOCF-015"}:
        guidance.append("Review browser credential-store access, preserve copied files, and rotate credentials for affected users if access was unauthorized.")
    if entities["hosts"]:
        guidance.append(f"If activity is unauthorized, isolate or contain impacted host(s): {', '.join(entities['hosts'][:3])}.")
    if entities["users"]:
        guidance.append(f"Reset credentials or review sessions for affected user(s): {', '.join(entities['users'][:3])}.")

    if not guidance:
        guidance.append("Validate the activity with the system owner, preserve relevant logs, and document the final disposition.")

    return guidance[:6]


def score_case_quality(items: List[Dict[str, Any]], iocs: Dict[str, Any] | None, recommended_actions: List[str] | None, story: str | None = None) -> Dict[str, Any]:
    score = 0
    gaps: List[str] = []

    if items:
        score += 20
    else:
        gaps.append("No alerts are attached to the case.")

    if any(_known(item.get("timestamp")) for item in items):
        score += 15
    else:
        gaps.append("No timeline timestamps are available.")

    entities = collect_case_entities(items, iocs)
    if entities["users"] or entities["hosts"] or entities["ips"]:
        score += 20
    else:
        gaps.append("No clear users, hosts, or IPs were extracted.")

    if any(str(item.get("rule_id") or "").startswith("SOCF-CORR") for item in items):
        score += 15
    else:
        gaps.append("No correlation alert is attached to the case.")

    if recommended_actions:
        score += 15
    else:
        gaps.append("No recommended actions are attached.")

    if story:
        score += 15
    else:
        gaps.append("No investigation story has been generated yet.")

    return {"score": min(score, 100), "gaps": gaps}


def build_case_quality_profile(
    items: List[Dict[str, Any]],
    *,
    case_risk: Dict[str, Any] | None = None,
    iocs: Dict[str, Any] | None = None,
    recommended_actions: List[str] | None = None,
    story: str | None = None,
) -> Dict[str, Any]:
    quality = score_case_quality(items, iocs, recommended_actions, story)
    return {
        "executive_summary": build_executive_summary(items, case_risk, iocs),
        "key_findings": build_key_findings(items),
        "key_evidence": build_key_evidence(items),
        "containment_guidance": build_containment_guidance(items, iocs),
        "quality_score": quality["score"],
        "quality_gaps": quality["gaps"],
        "analyst_questions": [
            "Was the activity approved or expected for this user, host, and time window?",
            "Do endpoint logs show follow-on process execution, persistence, or lateral movement?",
            "Should access be revoked, credentials reset, or the host isolated while investigation continues?",
        ],
    }
