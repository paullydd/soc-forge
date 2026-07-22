from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List

from soc_forge.cases.quality import build_case_quality_profile
from soc_forge.cases.recommended_actions import build_recommended_actions
from soc_forge.models import normalize_case
from soc_forge.report.html_report import (
    build_analyst_summary,
    build_attack_chain,
    build_attack_flow,
    build_attack_graph,
    build_attack_path,
    build_case_risk_fallback,
    build_evidence_fields,
)


def _is_known_value(value: Any) -> bool:
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "n/a"}


def _extract_ips_from_message(message: Any) -> List[str]:
    if not message:
        return []
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(message))


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
        if not _is_known_value(value):
            return
        s = str(value).strip()
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
        for ip in _extract_ips_from_message(details.get("message") or event.get("message")):
            add_unique(ips, ip)

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
        recommended_actions = build_recommended_actions(items_sorted)
        case_quality = build_case_quality_profile(
            items_sorted,
            case_risk=case_risk,
            iocs=iocs,
            recommended_actions=recommended_actions,
            story=analyst_summary,
        )

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
                "recommended_actions": recommended_actions,
                "case_quality": case_quality,
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
                "case_quality": case_quality,
                "executive_summary": case_quality.get("executive_summary", ""),
                "containment_guidance": case_quality.get("containment_guidance", []),
                "alerts": items_sorted,
            }
        )

    cases.sort(key=lambda c: c["correlation_id"])
    return [normalize_case(case, index) for index, case in enumerate(cases, start=1)]