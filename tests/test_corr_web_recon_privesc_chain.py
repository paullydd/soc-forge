from soc_forge.correlate.rules import correlate_alerts


def _alert(rule_id, timestamp, host="dispatch-ops01", **details):
    merged = {"host": host}
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


def test_corr_web_discovery_burst_followed_by_sensitive_exposure():
    alerts = [
        _alert("SOCF-029", "2026-09-16T03:11:00Z", ip="203.0.113.7"),
        _alert("SOCF-030", "2026-09-16T03:11:59Z", ip="203.0.113.7", uri="/.git/HEAD"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-015")

    assert corr["score"] == 145
    assert corr["details"]["source_rule_ids"] == ["SOCF-029", "SOCF-030"]
    cid = corr["correlation_id"]
    assert next(a for a in out if a["rule_id"] == "SOCF-029")["correlation_id"] == cid
    assert next(a for a in out if a["rule_id"] == "SOCF-030")["correlation_id"] == cid


def test_corr_web_discovery_burst_ignores_different_source_ip():
    alerts = [
        _alert("SOCF-029", "2026-09-16T03:11:00Z", ip="203.0.113.7"),
        _alert("SOCF-030", "2026-09-16T03:11:59Z", ip="198.51.100.9", uri="/.git/HEAD"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    assert not any(a.get("rule_id") == "SOCF-CORR-015" for a in out)


def test_corr_sensitive_exposure_followed_by_external_ssh_logon():
    alerts = [
        _alert("SOCF-030", "2026-09-16T03:11:59Z", ip="203.0.113.7", uri="/.git/HEAD"),
        _alert("SOCF-027", "2026-09-16T03:14:07Z", ip="203.0.113.7", username="dispatch-svc"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-016")

    assert corr["score"] == 155
    assert corr["details"]["source_rule_ids"] == ["SOCF-030", "SOCF-027"]
    cid = corr["correlation_id"]
    assert next(a for a in out if a["rule_id"] == "SOCF-030")["correlation_id"] == cid
    assert next(a for a in out if a["rule_id"] == "SOCF-027")["correlation_id"] == cid


def test_corr_ssh_logon_followed_by_privesc_despite_differing_usernames():
    # SOCF-028 reflects the hijacked root cron process, not the attacker's own
    # login identity - this is the whole reason SOCF-CORR-017 must not gate on
    # username. Confirm the correlation fires anyway.
    alerts = [
        _alert("SOCF-027", "2026-09-16T03:14:07Z", ip="203.0.113.7", username="dispatch-svc"),
        _alert("SOCF-028", "2026-09-16T03:20:00Z", username="root", process_name="tar"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    corr = _corr(out, "SOCF-CORR-017")

    assert corr["score"] == 165
    assert corr["details"]["source_rule_ids"] == ["SOCF-027", "SOCF-028"]
    cid = corr["correlation_id"]
    assert next(a for a in out if a["rule_id"] == "SOCF-027")["correlation_id"] == cid
    tagged_privesc = next(a for a in out if a["rule_id"] == "SOCF-028")
    assert tagged_privesc["correlation_id"] == cid


def test_corr_ssh_logon_to_privesc_still_requires_same_host():
    alerts = [
        _alert("SOCF-027", "2026-09-16T03:14:07Z", host="dispatch-ops01", ip="203.0.113.7", username="dispatch-svc"),
        _alert("SOCF-028", "2026-09-16T03:20:00Z", host="other-host", username="root"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    assert not any(a.get("rule_id") == "SOCF-CORR-017" for a in out)


def test_web_recon_privesc_chain_respects_time_window():
    alerts = [
        _alert("SOCF-029", "2026-09-16T03:11:00Z", ip="203.0.113.7"),
        _alert("SOCF-030", "2026-09-16T05:00:00Z", ip="203.0.113.7", uri="/.git/HEAD"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)
    assert not any(a.get("rule_id") == "SOCF-CORR-015" for a in out)


def test_full_web_to_privesc_chain_shares_one_correlation_lineage():
    alerts = [
        _alert("SOCF-029", "2026-09-16T03:11:00Z", ip="203.0.113.7"),
        _alert("SOCF-030", "2026-09-16T03:11:59Z", ip="203.0.113.7", uri="/.git/HEAD"),
        _alert("SOCF-027", "2026-09-16T03:14:07Z", ip="203.0.113.7", username="dispatch-svc"),
        _alert("SOCF-028", "2026-09-16T03:20:00Z", username="root", process_name="tar"),
    ]

    out = correlate_alerts(alerts, window_minutes=15)

    assert any(a.get("rule_id") == "SOCF-CORR-015" for a in out)
    assert any(a.get("rule_id") == "SOCF-CORR-016" for a in out)
    assert any(a.get("rule_id") == "SOCF-CORR-017" for a in out)

    # All four source alerts, plus all three correlation pseudo-alerts, should
    # share one canonical correlation_id (via the union-find merge in
    # correlate_alerts) so build_cases groups the whole chain into one case.
    cids = set()
    for rule_id in ("SOCF-029", "SOCF-030", "SOCF-027", "SOCF-028", "SOCF-CORR-015", "SOCF-CORR-016", "SOCF-CORR-017"):
        alert = next(a for a in out if a["rule_id"] == rule_id)
        assert alert.get("correlation_id"), f"{rule_id} was not tagged with a correlation_id"
        cids.add(alert["correlation_id"])
    assert len(cids) == 1, f"expected one shared correlation_id across the whole chain, got {cids}"
