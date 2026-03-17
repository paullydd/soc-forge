from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .hunts import (
    hunt_multi_host_spread,
    hunt_rare_source_ip,
    hunt_suspicious_commands,
)
from .models import HuntFinding


def run_hunts(events: Iterable[Dict[str, Any]]) -> List[HuntFinding]:
    event_list = list(events)

    findings: List[HuntFinding] = []
    findings.extend(hunt_suspicious_commands(event_list))
    findings.extend(hunt_rare_source_ip(event_list))
    findings.extend(hunt_multi_host_spread(event_list))

    return dedupe_findings(findings)


def dedupe_findings(findings: Iterable[HuntFinding]) -> List[HuntFinding]:
    seen = set()
    deduped: List[HuntFinding] = []

    for finding in findings:
        key = (
            finding.hunt_id,
            finding.entities.get("username"),
            finding.entities.get("host"),
            finding.entities.get("src_ip"),
            tuple(finding.entities.get("hosts", [])),
            finding.first_seen,
            finding.last_seen,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    return deduped


def findings_to_dicts(findings: Iterable[HuntFinding]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in findings]