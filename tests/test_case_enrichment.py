from __future__ import annotations

from soc_forge.report.html_report import (
    build_case_timeline,
    extract_case_iocs,
    build_analyst_summary,
)


def _alert(
    *,
    ts: str,
    rule_id: str,
    title: str,
    severity: str = "low",
    score: int = 0,
    ip: str | None = None,
    username: str | None = None,
    host: str | None = None,
) -> dict:
    d = {}
    if ip is not None:
        d["ip"] = ip
    if username is not None:
        d["username"] = username
    if host is not None:
        d["host"] = host

    return {
        "timestamp": ts,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": score,
        "details": d,
    }


def test_build_case_timeline_sorts_oldest_to_newest():
    items = [
        _alert(ts="2026-02-27T22:25:00Z", rule_id="SOCF-005", title="Scheduled task created"),
        _alert(ts="2026-02-27T22:01:00Z", rule_id="SOCF-006", title="RDP logon detected"),
        _alert(ts="2026-02-27T22:20:00Z", rule_id="SOCF-CORR-002", title="Correlation fired"),
    ]

    tl = build_case_timeline(items)

    assert [t["timestamp"] for t in tl] == [
        "2026-02-27T22:01:00Z",
        "2026-02-27T22:20:00Z",
        "2026-02-27T22:25:00Z",
    ]


def test_build_case_timeline_puts_blank_timestamps_last():
    items = [
        _alert(ts="", rule_id="SOCF-005", title="Scheduled task created"),
        _alert(ts="2026-02-27T22:01:00Z", rule_id="SOCF-006", title="RDP logon detected"),
    ]

    tl = build_case_timeline(items)

    assert tl[0]["timestamp"] == "2026-02-27T22:01:00Z"
    assert tl[-1]["timestamp"] == ""


def test_extract_case_iocs_uniques_and_ignores_blank():
    items = [
        _alert(
            ts="2026-02-27T22:01:00Z",
            rule_id="SOCF-006",
            title="RDP logon detected",
            ip="203.0.113.50",
            username="bob",
            host="WIN10",
        ),
        _alert(
            ts="2026-02-27T22:20:00Z",
            rule_id="SOCF-005",
            title="Scheduled task created",
            ip="203.0.113.50",  # duplicate
            username="bob",      # duplicate
            host="WIN10",        # duplicate
        ),
        _alert(
            ts="2026-02-27T22:25:00Z",
            rule_id="SOCF-005",
            title="Scheduled task created",
            ip="",
            username="   ",
            host=None,
        ),
    ]

    iocs = extract_case_iocs(items)

    assert iocs["ips"] == ["203.0.113.50"]
    assert iocs["users"] == ["bob"]
    assert iocs["hosts"] == ["WIN10"]


def test_analyst_summary_rdp_plus_scheduled_task_path():
    items = [
        _alert(
            ts="2026-02-27T22:01:00Z",
            rule_id="SOCF-006",
            title="RDP logon detected (LogonType 10)",
            ip="203.0.113.50",
            username="bob",
            host="WIN10",
        ),
        _alert(
            ts="2026-02-27T22:20:00Z",
            rule_id="SOCF-005",
            title="Scheduled task created",
            ip="203.0.113.50",
            username="bob",
            host="WIN10",
        ),
        _alert(
            ts="2026-02-27T22:20:00Z",
            rule_id="SOCF-CORR-002",
            title="RDP logon followed by scheduled task creation (possible persistence)",
        ),
    ]

    s = build_analyst_summary(items).lower()

    # Key narrative anchors
    assert "rdp" in s
    assert "scheduled task" in s
    assert "persistence" in s
    # Correlation note should appear when SOCF-CORR is present
    assert "correlation rule fired" in s


def test_analyst_summary_rdp_plus_new_admin_path():
    items = [
        _alert(ts="2026-02-27T22:01:00Z", rule_id="SOCF-006", title="RDP logon detected"),
        _alert(ts="2026-02-27T22:10:00Z", rule_id="SOCF-003", title="New admin user created"),
    ]

    s = build_analyst_summary(items).lower()
    assert "rdp" in s
    # Your copy uses “privilege escalation” / “account takeover” language
    assert ("privilege escalation" in s) or ("account takeover" in s)


def test_analyst_summary_bruteforce_plus_lockout_path():
    items = [
        _alert(ts="2026-02-27T22:01:00Z", rule_id="SOCF-001", title="Brute-force login attempts detected"),
        _alert(ts="2026-02-27T22:02:00Z", rule_id="SOCF-002", title="Account lockout detected"),
    ]

    s = build_analyst_summary(items).lower()
    assert "lockout" in s
    assert ("credential" in s) or ("authentication" in s)
