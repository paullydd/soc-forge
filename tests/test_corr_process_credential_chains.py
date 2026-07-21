from soc_forge.correlate.rules import correlate_alerts


def _alert(rule_id, timestamp, host="WIN10", username="alice", **details):
    merged = {"host": host, "username": username}
    merged.update(details)
    return {
        "rule_id": rule_id,
        "severity": "high",
        "title": f"{rule_id} test alert",
        "timestamp": timestamp,
        "details": merged,
        "mitre": [],
        "score": 75,
        "status": "new",
    }


def test_corr_office_spawned_suspicious_script():
    alerts = [
        _alert(
            "SOCF-013",
            "2026-02-27T22:00:00Z",
            parent_process="WINWORD.EXE",
            process_name="powershell.exe",
        ),
        _alert("SOCF-011", "2026-02-27T22:02:00Z", process_name="powershell.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr = [a for a in out if a.get("rule_id") == "SOCF-CORR-006"]
    assert len(corr) == 1
    assert corr[0]["severity"] == "critical"
    assert corr[0]["details"]["source_rule_ids"] == ["SOCF-013", "SOCF-011"]

    cid = corr[0].get("correlation_id")
    assert cid
    for rule_id in ("SOCF-013", "SOCF-011"):
        original = next(a for a in out if a.get("rule_id") == rule_id)
        assert original.get("correlation_id") == cid


def test_corr_script_execution_followed_by_credential_dumping():
    alerts = [
        _alert("SOCF-011", "2026-02-27T22:00:00Z", process_name="powershell.exe"),
        _alert("SOCF-014", "2026-02-27T22:04:00Z", target_process="lsass.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr = [a for a in out if a.get("rule_id") == "SOCF-CORR-007"]
    assert len(corr) == 1
    assert corr[0]["score"] == 170
    assert corr[0]["details"]["source_rule_ids"] == ["SOCF-011", "SOCF-014"]

    cid = corr[0].get("correlation_id")
    assert cid
    for rule_id in ("SOCF-011", "SOCF-014"):
        original = next(a for a in out if a.get("rule_id") == rule_id)
        assert original.get("correlation_id") == cid


def test_corr_suspicious_process_followed_by_browser_credential_access():
    alerts = [
        _alert("SOCF-012", "2026-02-27T22:00:00Z", process_name="update.exe"),
        _alert(
            "SOCF-015",
            "2026-02-27T22:05:00Z",
            file_path=r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        ),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr = [a for a in out if a.get("rule_id") == "SOCF-CORR-008"]
    assert len(corr) == 1
    assert corr[0]["score"] == 155
    assert corr[0]["details"]["source_rule_ids"] == ["SOCF-012", "SOCF-015"]

    cid = corr[0].get("correlation_id")
    assert cid
    for rule_id in ("SOCF-012", "SOCF-015"):
        original = next(a for a in out if a.get("rule_id") == rule_id)
        assert original.get("correlation_id") == cid


def test_process_credential_correlations_respect_host_boundaries():
    alerts = [
        _alert("SOCF-011", "2026-02-27T22:00:00Z", host="WIN10", process_name="powershell.exe"),
        _alert("SOCF-014", "2026-02-27T22:04:00Z", host="WIN11", target_process="lsass.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    assert not any(a.get("rule_id") == "SOCF-CORR-007" for a in out)
