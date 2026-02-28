from soc_forge.correlate.rules import correlate_alerts


def test_correlation_bruteforce_plus_lockout_creates_critical():
    alerts = [
        {
            "rule_id": "SOCF-001",
            "severity": "high",
            "title": "Possible brute-force login attempts",
            "timestamp": "2026-02-27T21:07:00Z",
            "details": {"ip": "10.0.0.5", "count_in_window": 8, "window_minutes": 10},
            "mitre": [{"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"}],
            "score": 60,
            "status": "new",
            "correlation_id": None,
        },
        {
            "rule_id": "SOCF-002",
            "severity": "medium",
            "title": "Account lockout observed",
            "timestamp": "2026-02-27T21:08:00Z",
            "details": {"username": "bob", "ip": "10.0.0.5", "host": "DC01"},
            "mitre": [{"tactic": "Credential Access", "technique": "Password Guessing", "id": "T1110"}],
            "score": 40,
            "status": "new",
            "correlation_id": None,
        },
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr = [a for a in out if a["rule_id"] == "SOCF-CORR-001"]
    assert len(corr) == 1
    assert corr[0]["severity"] == "critical"
    assert corr[0]["details"]["ip"] == "10.0.0.5"
    assert corr[0]["details"]["username"] == "bob"

    # Nice-to-have: originals get correlation_id tagged
    cid = corr[0].get("correlation_id")
    assert cid
    for a in out:
        if a["rule_id"] in ("SOCF-001", "SOCF-002"):
            assert a.get("correlation_id") == cid
