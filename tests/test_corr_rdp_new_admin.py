from soc_forge.correlate.rules import correlate_alerts

def test_corr_rdp_then_new_admin():
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
            "rule_id": "SOCF-003",
            "severity": "high",
            "title": "Privileged group membership change (possible new admin)",
            "timestamp": "2026-02-27T22:20:00Z",
            "details": {"host": "WIN10", "username": "bob", "target_group": "Administrators", "actor": "alice"},
            "mitre": [],
            "score": 90,
            "status": "new",
        },
    ]

    out = correlate_alerts(
        alerts,
        window_minutes=15,
        bruteforce_lockout_enabled=False,
        rdp_schtask_enabled=False,
        rdp_new_admin_enabled=True,
        rdp_new_admin_severity="critical",
        rdp_new_admin_score=130,
    )

    corr = [a for a in out if a.get("rule_id") == "SOCF-CORR-003"]
    assert len(corr) == 1
    cid = corr[0].get("correlation_id")
    assert cid

    rdp = next(a for a in out if a.get("rule_id") == "SOCF-006")
    adm = next(a for a in out if a.get("rule_id") == "SOCF-003")
    assert rdp.get("correlation_id") == cid
    assert adm.get("correlation_id") == cid
