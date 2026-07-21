from soc_forge.correlate.rules import correlate_alerts


def _alert(rule_id, timestamp, host="WS-02", username="alice", **details):
    merged = {"host": host, "username": username}
    merged.update(details)
    return {
        "rule_id": rule_id,
        "severity": "high",
        "title": f"{rule_id} test alert",
        "timestamp": timestamp,
        "details": merged,
        "mitre": [],
        "score": 80,
        "status": "new",
    }


def _corr(out, rule_id):
    matches = [a for a in out if a.get("rule_id") == rule_id]
    assert len(matches) == 1
    return matches[0]


def test_corr_rdp_followed_by_psexec_service_execution():
    alerts = [
        _alert("SOCF-006", "2026-07-21T14:00:00Z", ip="198.51.100.44"),
        _alert("SOCF-016", "2026-07-21T14:04:00Z", service_name="PSEXESVC"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-009")

    assert corr["score"] == 165
    assert corr["details"]["source_rule_ids"] == ["SOCF-006", "SOCF-016"]
    cid = corr["correlation_id"]
    assert next(a for a in out if a["rule_id"] == "SOCF-006")["correlation_id"] == cid
    assert next(a for a in out if a["rule_id"] == "SOCF-016")["correlation_id"] == cid


def test_corr_wmi_followed_by_lolbin_execution():
    alerts = [
        _alert("SOCF-017", "2026-07-21T14:00:00Z", process_name="wmic.exe"),
        _alert("SOCF-018", "2026-07-21T14:03:00Z", process_name="regsvr32.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-010")

    assert corr["details"]["source_rule_ids"] == ["SOCF-017", "SOCF-018"]


def test_corr_credential_access_followed_by_archive_staging():
    alerts = [
        _alert("SOCF-014", "2026-07-21T14:00:00Z", target_process="lsass.exe"),
        _alert("SOCF-020", "2026-07-21T14:05:00Z", process_name="7z.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-011")

    assert corr["score"] == 175
    assert corr["details"]["source_rule_ids"] == ["SOCF-014", "SOCF-020"]


def test_corr_lateral_movement_followed_by_credential_access():
    alerts = [
        _alert("SOCF-019", "2026-07-21T14:00:00Z", command_line=r"\\WS-03\ADMIN$\update.exe"),
        _alert("SOCF-015", "2026-07-21T14:06:00Z", file_path=r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-012")

    assert corr["details"]["source_rule_ids"] == ["SOCF-019", "SOCF-015"]


def test_corr_admin_share_followed_by_archive_staging():
    alerts = [
        _alert("SOCF-019", "2026-07-21T14:00:00Z", command_line=r"\\WS-03\ADMIN$\update.exe"),
        _alert("SOCF-020", "2026-07-21T14:08:00Z", process_name="7z.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-013")

    assert corr["score"] == 160
    assert corr["details"]["source_rule_ids"] == ["SOCF-019", "SOCF-020"]


def test_lateral_collection_correlations_respect_time_window():
    alerts = [
        _alert("SOCF-014", "2026-07-21T14:00:00Z", target_process="lsass.exe"),
        _alert("SOCF-020", "2026-07-21T15:00:00Z", process_name="7z.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    assert not any(a.get("rule_id") == "SOCF-CORR-011" for a in out)
