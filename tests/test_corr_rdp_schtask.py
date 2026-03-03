from soc_forge.correlate.rules import correlate_alerts

def test_corr_rdp_then_schtask():
    alerts = [
        {
            "rule_id": "SOCF-006",
            "severity": "medium",
            "title": "RDP logon detected (LogonType 10)",
            "timestamp": "2026-02-27T22:15:00Z",
            "details": {"host": "WIN10", "username": "bob", "ip": "203.0.113.50"},
            "mitre": [],
            "score": 55,
            "status": "new",
        },
        {
            "rule_id": "SOCF-005",
            "severity": "high",
            "title": "Scheduled task created",
            "timestamp": "2026-02-27T22:20:00Z",
            "details": {"host": "WIN10", "task_name": "\\Updater", "task_command": "powershell.exe -enc AAAA"},
            "mitre": [],
            "score": 75,
            "status": "new",
        },
    ]

    out = correlate_alerts(
        alerts,
        window_minutes=15,
        bruteforce_lockout_enabled=False,
        rdp_schtask_enabled=True,
        rdp_schtask_severity="high",
        rdp_schtask_score=110,
    )

    corr = [a for a in out if a.get("rule_id") == "SOCF-CORR-002"]
    assert len(corr) == 1

    cid = corr[0].get("correlation_id")
    assert cid

    # originals should be tagged with same correlation_id
    rdp = next(a for a in out if a.get("rule_id") == "SOCF-006")
    task = next(a for a in out if a.get("rule_id") == "SOCF-005")
    assert rdp.get("correlation_id") == cid
    assert task.get("correlation_id") == cid