from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from soc_forge.models import Alert


def parse_ts(ts: str) -> datetime:
    # Accepts ISO timestamps with Z or offset
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def detect_bruteforce(events, threshold=8, window_minutes=10, severity="high", score=60):
    """
    Rule: >= threshold failed logons (4625) from same IP in window
    """
    window = timedelta(minutes=window_minutes)
    buckets = defaultdict(deque)  # ip -> deque[timestamps]
    alerts = []

    for ev in events:
        if ev.get("event_id") != 4625:
            continue
        ip = ev.get("ip") or "unknown"
        ts = parse_ts(ev["timestamp"])

        dq = buckets[ip]
        dq.append(ts)

        # pop old
        while dq and (ts - dq[0]) > window:
            dq.popleft()

        if len(dq) == threshold:
            alerts.append(Alert(
                rule_id="SOCF-001",
                severity=severity,
                title="Possible brute-force login attempts",
                timestamp=ts.isoformat().replace("+00:00", "Z"),
                details={
                    "ip": ip,
                    "count_in_window": len(dq),
                    "window_minutes": window_minutes,
                    "example_username": ev.get("username"),
                    "host": ev.get("host"),
                },
                mitre=[{"tactic":"Credential Access","technique":"Brute Force","id":"T1110"}],
                score=score,
            ))
    return alerts
