from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List

from .models import HuntFinding


SUSPICIOUS_COMMAND_KEYWORDS = [
    "powershell -enc",
    "powershell.exe -enc",
    "powershell -nop",
    "powershell.exe -nop",
    "rundll32",
    "mshta",
    "wmic",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "psexec",
    "cmd.exe /c",
]


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _lower(value: Any) -> str:
    return _norm(value).lower()


def _parse_ts(value: Any) -> datetime | None:
    text = _norm(value)
    if not text:
        return None

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


def _event_time(event: Dict[str, Any]) -> str | None:
    return (
        event.get("timestamp")
        or event.get("time_created")
        or event.get("TimeCreated")
        or event.get("@timestamp")
    )


def _event_user(event: Dict[str, Any]) -> str:
    return (
        _norm(event.get("username"))
        or _norm(event.get("user"))
        or _norm(event.get("target_user"))
        or _norm(event.get("account_name"))
    )


def _event_host(event: Dict[str, Any]) -> str:
    return (
        _norm(event.get("host"))
        or _norm(event.get("hostname"))
        or _norm(event.get("computer_name"))
        or _norm(event.get("Computer"))
    )


def _event_src_ip(event: Dict[str, Any]) -> str:
    return (
        _norm(event.get("src_ip"))
        or _norm(event.get("ip_address"))
        or _norm(event.get("source_ip"))
        or _norm(event.get("IpAddress"))
    )


def _event_command(event: Dict[str, Any]) -> str:
    return (
        _norm(event.get("command_line"))
        or _norm(event.get("process_command_line"))
        or _norm(event.get("CommandLine"))
        or _norm(event.get("message"))
    )


def hunt_suspicious_commands(events: Iterable[Dict[str, Any]]) -> List[HuntFinding]:
    findings: List[HuntFinding] = []

    for event in events:
        command = _event_command(event)
        command_l = command.lower()
        if not command_l:
            continue

        matched = [k for k in SUSPICIOUS_COMMAND_KEYWORDS if k in command_l]
        if not matched:
            continue

        username = _event_user(event)
        host = _event_host(event)
        ts = _event_time(event)

        findings.append(
            HuntFinding(
                hunt_id="HUNT-001",
                title="Suspicious Command Execution",
                severity="high",
                category="execution",
                summary=f"Suspicious command observed on {host or 'unknown-host'} by {username or 'unknown-user'}",
                confidence="high",
                entities={
                    "username": username,
                    "host": host,
                    "command_line": command,
                    "matched_terms": matched,
                },
                evidence=[
                    {
                        "timestamp": ts,
                        "host": host,
                        "username": username,
                        "command_line": command,
                        "matched_terms": matched,
                        "event_id": event.get("event_id"),
                    }
                ],
                first_seen=ts,
                last_seen=ts,
                mitre=["T1059", "T1218"],
            )
        )

    return findings


def hunt_rare_source_ip(events: Iterable[Dict[str, Any]]) -> List[HuntFinding]:
    user_to_ips: Dict[str, set[str]] = defaultdict(set)
    user_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        user = _event_user(event)
        src_ip = _event_src_ip(event)
        if not user or not src_ip:
            continue
        user_to_ips[user].add(src_ip)
        user_events[user].append(event)

    findings: List[HuntFinding] = []

    for user, ips in user_to_ips.items():
        if len(ips) <= 1:
            continue

        sorted_events = sorted(
            user_events[user],
            key=lambda e: _parse_ts(_event_time(e)) or datetime.min,
        )

        baseline_ip = _event_src_ip(sorted_events[0])
        for event in sorted_events[1:]:
            src_ip = _event_src_ip(event)
            if src_ip and src_ip != baseline_ip:
                host = _event_host(event)
                ts = _event_time(event)
                findings.append(
                    HuntFinding(
                        hunt_id="HUNT-002",
                        title="Rare Source IP for User",
                        severity="medium",
                        category="authentication",
                        summary=f"User {user} authenticated from uncommon source IP {src_ip}",
                        confidence="medium",
                        entities={
                            "username": user,
                            "src_ip": src_ip,
                            "baseline_ip": baseline_ip,
                            "host": host,
                        },
                        evidence=[
                            {
                                "timestamp": ts,
                                "username": user,
                                "src_ip": src_ip,
                                "baseline_ip": baseline_ip,
                                "host": host,
                                "event_id": event.get("event_id"),
                            }
                        ],
                        first_seen=ts,
                        last_seen=ts,
                        mitre=["T1078"],
                    )
                )
                break

    return findings


def hunt_multi_host_spread(events: Iterable[Dict[str, Any]], min_hosts: int = 3) -> List[HuntFinding]:
    user_to_hosts: Dict[str, set[str]] = defaultdict(set)
    user_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        user = _event_user(event)
        host = _event_host(event)
        if not user or not host:
            continue
        user_to_hosts[user].add(host)
        user_events[user].append(event)

    findings: List[HuntFinding] = []

    for user, hosts in user_to_hosts.items():
        if len(hosts) < min_hosts:
            continue

        ordered = sorted(
            user_events[user],
            key=lambda e: _parse_ts(_event_time(e)) or datetime.min,
        )

        first_seen = _event_time(ordered[0]) if ordered else None
        last_seen = _event_time(ordered[-1]) if ordered else None

        findings.append(
            HuntFinding(
                hunt_id="HUNT-003",
                title="Multi-Host User Spread",
                severity="medium",
                category="lateral_movement",
                summary=f"User {user} touched {len(hosts)} hosts, which may indicate lateral movement",
                confidence="medium",
                entities={
                    "username": user,
                    "hosts": sorted(hosts),
                    "host_count": len(hosts),
                },
                evidence=[
                    {
                        "timestamp": _event_time(e),
                        "username": user,
                        "host": _event_host(e),
                        "src_ip": _event_src_ip(e),
                        "event_id": e.get("event_id"),
                    }
                    for e in ordered
                ],
                first_seen=first_seen,
                last_seen=last_seen,
                mitre=["T1021"],
            )
        )

    return findings