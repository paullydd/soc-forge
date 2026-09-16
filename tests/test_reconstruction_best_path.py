from soc_forge.reconstruct.engine import reconstruct_case


def _item(rule_id: str, timestamp: str, **details) -> dict:
    return {
        "rule_id": rule_id,
        "severity": "high",
        "title": f"{rule_id} test alert",
        "timestamp": timestamp,
        "details": {"host": "WS-01", **details},
        "mitre": [],
        "score": 80,
        "status": "new",
    }


def test_disconnected_component_is_excluded_from_path_but_surfaced_in_gaps():
    # SOCF-006 (alice, 203.0.113.10) and SOCF-016 (alice, same host, within
    # window) score well together. SOCF-021 belongs to a totally different
    # actor/host with no qualifying edge to either - a genuine disconnected
    # component, not just a locally-bad greedy choice.
    header = {"case_id": "CASE-DISCONNECTED"}
    items = [
        _item("SOCF-006", "2026-07-17T12:00:00Z", src_ip="203.0.113.10", username="alice"),
        _item("SOCF-016", "2026-07-17T12:04:00Z", src_ip="203.0.113.10", username="alice", service_name="PSEXESVC"),
        _item("SOCF-021", "2026-07-17T18:00:00Z", host="WS-99", username="carol"),
    ]

    recon = reconstruct_case(header, items)

    path_rule_ids = [step.evidence[0].rule_id for step in recon.attack_path]
    assert path_rule_ids == ["SOCF-006", "SOCF-016"]

    assert any("SOCF-021" in gap and "1 additional alert" in gap for gap in recon.gaps)


def test_best_path_search_recovers_the_stronger_chain_despite_a_weak_first_step():
    # SOCF-002 (bob, HOST-A) is the earliest event but is a poor bridge to
    # anything else in the case (different host/user from what follows). The
    # real, strongly-connected narrative is SOCF-006 -> SOCF-005 -> SOCF-016
    # (all alice, WS-01), which starts second chronologically. The old
    # greedy walk (fixed start at index 0) could never reach that chain if
    # SOCF-002 had zero qualifying outgoing edges; the DP-based search must
    # recover it regardless of where it starts.
    header = {"case_id": "CASE-WEAK-START"}
    items = [
        _item("SOCF-002", "2026-07-17T11:00:00Z", host="HOST-A", username="bob"),
        _item("SOCF-006", "2026-07-17T12:00:00Z", src_ip="203.0.113.10", username="alice", host="WS-01"),
        _item("SOCF-005", "2026-07-17T12:03:00Z", src_ip="203.0.113.10", username="alice", host="WS-01"),
        _item("SOCF-016", "2026-07-17T12:06:00Z", src_ip="203.0.113.10", username="alice", host="WS-01", service_name="PSEXESVC"),
    ]

    recon = reconstruct_case(header, items)

    path_rule_ids = [step.evidence[0].rule_id for step in recon.attack_path]
    assert path_rule_ids == ["SOCF-006", "SOCF-005", "SOCF-016"]
    assert len(recon.relationships) == 2

    assert any("SOCF-002" in gap for gap in recon.gaps)


def test_fully_connected_chain_has_no_orphan_gap():
    header = {"case_id": "CASE-CONNECTED"}
    items = [
        _item("SOCF-006", "2026-07-17T12:00:00Z", src_ip="203.0.113.10", username="alice"),
        _item("SOCF-005", "2026-07-17T12:03:00Z", src_ip="203.0.113.10", username="alice"),
    ]

    recon = reconstruct_case(header, items)

    assert len(recon.attack_path) == 2
    assert not any("additional alert" in gap for gap in recon.gaps)
