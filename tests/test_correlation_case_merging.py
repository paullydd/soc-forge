from soc_forge.correlate.rules import correlate_alerts


def _alert(rule_id, timestamp, host="WS-01", username="alice", **details):
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


def test_overlapping_existing_correlations_merge_into_one_lineage():
    # SOCF-CORR-005's gates are a strict superset of SOCF-CORR-004's, so any
    # time 005 fires, 004 necessarily fires too on the same SOCF-007/SOCF-008
    # pair - a guaranteed real bridge, not a hypothetical one.
    alerts = [
        _alert("SOCF-007", "2026-07-17T12:00:00Z", target_user="svc-backup"),
        _alert("SOCF-008", "2026-07-17T12:02:00Z", target_user="svc-backup"),
        _alert("SOCF-009", "2026-07-17T12:04:00Z", username="svc-backup"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr_004 = next(a for a in out if a["rule_id"] == "SOCF-CORR-004")
    corr_005 = next(a for a in out if a["rule_id"] == "SOCF-CORR-005")
    bridge_007 = next(a for a in out if a["rule_id"] == "SOCF-007")
    bridge_008 = next(a for a in out if a["rule_id"] == "SOCF-008")
    tail_009 = next(a for a in out if a["rule_id"] == "SOCF-009")

    cids = {
        corr_004["correlation_id"],
        corr_005["correlation_id"],
        bridge_007["correlation_id"],
        bridge_008["correlation_id"],
        tail_009["correlation_id"],
    }
    assert len(cids) == 1, f"expected one shared correlation_id, got {cids}"


def test_unrelated_correlations_stay_distinct():
    alerts = [
        _alert("SOCF-002", "2026-07-17T12:00:00Z", host="DC1", username="bob", ip="203.0.113.10"),
        _alert("SOCF-001", "2026-07-17T12:01:00Z", host="DC1", username="bob", ip="203.0.113.10"),
        _alert("SOCF-017", "2026-07-21T09:00:00Z", host="WS-99", username="carol", process_name="wmic.exe"),
        _alert("SOCF-018", "2026-07-21T09:02:00Z", host="WS-99", username="carol", process_name="regsvr32.exe"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    corr_001 = next(a for a in out if a["rule_id"] == "SOCF-CORR-001")
    corr_010 = next(a for a in out if a["rule_id"] == "SOCF-CORR-010")
    assert corr_001["correlation_id"] != corr_010["correlation_id"]
