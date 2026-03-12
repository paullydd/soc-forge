from soc_forge.correlate.rules import correlate_alerts

def test_corr_new_user_priv_group():
    alerts = [
        {
            "rule_id": "SOCF-007",
            "timestamp": "2026-03-11T10:00:00Z",
            "details": {"host": "WIN10", "target_user": "eviluser"},
        },
        {
            "rule_id": "SOCF-008",
            "timestamp": "2026-03-11T10:03:00Z",
            "details": {"host": "WIN10", "target_user": "eviluser"},
        },
    ]

    results = correlate_alerts(alerts)

    corr = [a for a in results if a.get("rule_id") == "SOCF-CORR-004"]

    assert len(corr) == 1
