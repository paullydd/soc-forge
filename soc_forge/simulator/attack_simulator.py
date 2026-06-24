from __future__ import annotations

import json
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Any, Dict, List


def _iso_z(dt: datetime) -> str:
    """Return ISO-8601 timestamp with Z suffix."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_brute_force_scenario() -> List[Dict[str, Any]]:
    """
    Generate a simple brute-force scenario:
    - multiple failed logons (4625)
    - one successful logon (4624)
    - same username, source IP, and host
    """
    base_time = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)

    username = "alice"
    src_ip = "203.0.113.10"
    host = "DC1"

    events: List[Dict[str, Any]] = []

    # 10 failed logons
    for i in range(10):
        ts = base_time + timedelta(seconds=i * 30)
        events.append(
            {
                "timestamp": _iso_z(ts),
                "event_id": 4625,
                "username": username,
                "src_ip": src_ip,
                "host": host,
                "computer_name": host,
                "logon_type": 3,
                "message": (
                    f"An account failed to log on. "
                    f"User: {username}. "
                    f"Source Network Address: {src_ip}. "
                    f"Logon Type: 3."
                ),
            }
        )

    # 1 successful logon after failures
    success_time = base_time + timedelta(seconds=10 * 30 + 30)
    events.append(
        {
            "timestamp": _iso_z(success_time),
            "event_id": 4624,
            "username": username,
            "src_ip": src_ip,
            "host": host,
            "computer_name": host,
            "logon_type": 3,
            "message": (
                f"An account was successfully logged on. "
                f"User: {username}. "
                f"Source Network Address: {src_ip}. "
                f"Logon Type: 3."
            ),
        }
    )

    return events

def generate_password_spray_scenario() -> List[Dict[str, Any]]:
    """
    Generate a simple password spray scenario:
    - one source IP
    - many usernames
    - one failed attempt per user
    - optional final success for one user
    """
    base_time = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)

    src_ip = "203.0.113.55"
    host = "DC1"
    usernames = [
        "alice",
        "bob",
        "carol",
        "dave",
        "erin",
        "frank",
        "grace",
        "heidi",
    ]

    events: List[Dict[str, Any]] = []

    for i, username in enumerate(usernames):
        ts = base_time + timedelta(seconds=i * 20)
        events.append(
            {
                "timestamp": _iso_z(ts),
                "event_id": 4625,
                "username": username,
                "src_ip": src_ip,
                "host": host,
                "computer_name": host,
                "logon_type": 3,
                "message": (
                    f"An account failed to log on. "
                    f"User: {username}. "
                    f"Source Network Address: {src_ip}. "
                    f"Logon Type: 3."
                ),
            }
        )

    # Optional: simulate one account eventually succeeding
    success_user = "alice"
    success_time = base_time + timedelta(seconds=len(usernames) * 20 + 30)
    events.append(
        {
            "timestamp": _iso_z(success_time),
            "event_id": 4624,
            "username": success_user,
            "src_ip": src_ip,
            "host": host,
            "computer_name": host,
            "logon_type": 3,
            "message": (
                f"An account was successfully logged on. "
                f"User: {success_user}. "
                f"Source Network Address: {src_ip}. "
                f"Logon Type: 3."
            ),
        }
    )

    return events

def generate_privilege_escalation_scenario() -> List[Dict[str, Any]]:
    """
    Generate a simple privilege escalation scenario:
    - a user is added to the local Administrators group
    - optional follow-up successful logon
    """
    base_time = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=5)

    username = "alice"
    actor = "admin01"
    host = "WS-01"
    src_ip = "10.0.0.25"

    events: List[Dict[str, Any]] = []

    # Privileged group membership change
    group_change_time = base_time
    events.append(
        {
            "timestamp": _iso_z(group_change_time),
            "event_id": 4732,
            "username": username,
            "actor_username": actor,
            "src_ip": src_ip,
            "host": host,
            "computer_name": host,
            "group_name": "Administrators",
            "message": (
                f"A member was added to a security-enabled local group. "
                f"Subject: {actor}. "
                f"Member: {username}. "
                f"Group: Administrators."
            ),
        }
    )

    # Optional follow-up successful logon by that user
    success_time = base_time + timedelta(seconds=45)
    events.append(
        {
            "timestamp": _iso_z(success_time),
            "event_id": 4624,
            "username": username,
            "src_ip": src_ip,
            "host": host,
            "computer_name": host,
            "logon_type": 2,
            "message": (
                f"An account was successfully logged on. "
                f"User: {username}. "
                f"Source Network Address: {src_ip}. "
                f"Logon Type: 2."
            ),
        }
    )

    return events

def generate_benign_login_events() -> List[Dict[str, Any]]:
    """
    Generate normal-looking successful login activity across multiple users and hosts.
    """
    base_time = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=15)

    users = ["alice", "bob", "carol", "dave", "helpdesk1"]
    hosts = ["WS-01", "WS-02", "WS-03", "APP-01"]
    src_ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.20"]

    events: List[Dict[str, Any]] = []

    idx = 0
    for user in users:
        for host in hosts[:2]:
            ts = base_time + timedelta(seconds=idx * 35)
            src_ip = src_ips[idx % len(src_ips)]
            events.append(
                {
                    "timestamp": _iso_z(ts),
                    "event_id": 4624,
                    "username": user,
                    "src_ip": src_ip,
                    "host": host,
                    "computer_name": host,
                    "logon_type": 3,
                    "message": (
                        f"An account was successfully logged on. "
                        f"User: {user}. "
                        f"Source Network Address: {src_ip}. "
                        f"Logon Type: 3."
                    ),
                }
            )
            idx += 1

    return events

def generate_mixed_scenario() -> List[Dict[str, Any]]:
    """
    Generate mixed benign + malicious traffic.
    Includes normal login noise plus an embedded password spray attack.
    """
    benign_events = generate_benign_login_events()
    spray_events = generate_password_spray_scenario()

    all_events = benign_events + spray_events

    def _sort_key(event: Dict[str, Any]) -> datetime:
        ts = event.get("timestamp", "")
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)

    all_events.sort(key=_sort_key)
    return all_events

def generate_scenario(name: str) -> List[Dict[str, Any]]:
    """
    Dispatch scenario generation by name.
    """
    scenarios = {
        "brute_force": generate_brute_force_scenario,
        "password_spray": generate_password_spray_scenario,
        "privilege_escalation": generate_privilege_escalation_scenario,
        "mixed": generate_mixed_scenario,
    }

    if name not in scenarios:
        valid = ", ".join(sorted(scenarios))
        raise ValueError(f"Unknown scenario '{name}'. Valid scenarios: {valid}")

    return scenarios[name]()


def write_events_jsonl(events: List[Dict[str, Any]], output_path: str | Path) -> Path:
    """
    Write generated events to JSONL.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    return output
