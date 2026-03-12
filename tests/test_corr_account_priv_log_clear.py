def test_corr_account_priv_log_clear():
    alerts = [
        {
            "rule_id": "SOCF-007",
            "timestamp": "2026-03-11T10:00:00Z",
            "details": {"host": "WIN10", "target_user": "eviluser"},
        },
        {
            "rule_id": "SOCF-008",
            "timestamp": "2026-03-11T10:02:00Z",
            "details": {"host": "WIN10", "target_user": "eviluser"},
        },
        {
            "rule_id": "SOCF-009",
            "timestamp": "2026-03-11T10:05:00Z",
            "details": {"host": "WIN10", "actor": "eviluser"},
        },
    ]

    results = correlate_alerts(alerts)

    corr = [a for a in results if a.get("rule_id") == "SOCF-CORR-005"]

    assert len(corr) == 1
