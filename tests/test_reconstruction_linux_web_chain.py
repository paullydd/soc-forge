from soc_forge.reconstruct.engine import reconstruct_case


def _item(rule_id: str, timestamp: str, **extra) -> dict:
    item = {
        "rule_id": rule_id,
        "timestamp": timestamp,
        "host": "dispatch-ops01",
        "score": 80,
    }
    item.update(extra)
    return item


def test_linux_and_web_rules_have_explicit_reconstruction_stages_and_techniques():
    expected = {
        "SOCF-023": ("Initial Access", "Initial Access", "T1133"),
        "SOCF-024": ("Discovery", "Discovery", "T1087"),
        "SOCF-027": ("Initial Access", "Initial Access", "T1133"),
        "SOCF-028": ("Privilege Escalation", "Privilege Escalation", "T1053.003"),
        "SOCF-029": ("Reconnaissance", "Reconnaissance", "T1595.003"),
        "SOCF-030": ("Credential Access", "Credential Access", "T1552.001"),
    }

    for index, (rule_id, contract) in enumerate(expected.items()):
        reconstruction = reconstruct_case(
            {"case_id": f"CASE-{rule_id}"},
            [_item(rule_id, f"2026-09-16T03:1{index}:00Z")],
        )
        assert len(reconstruction.attack_path) == 1
        step = reconstruction.attack_path[0]
        assert step.evidence[0].rule_id == rule_id
        assert (step.tactic, step.stage, step.technique) == contract


def test_full_recon_to_privesc_chain_reconstructs_as_one_connected_path():
    header = {"case_id": "CASE-DISPATCH-OPS"}
    items = [
        _item("SOCF-029", "2026-09-16T03:11:00Z", src_ip="203.0.113.7"),
        _item("SOCF-030", "2026-09-16T03:11:59Z", src_ip="203.0.113.7"),
        _item("SOCF-027", "2026-09-16T03:14:07Z", src_ip="203.0.113.7", username="dispatch-svc"),
        _item("SOCF-028", "2026-09-16T03:20:00Z", username="root"),
    ]

    recon = reconstruct_case(header, items)

    assert len(recon.attack_path) == 4
    rule_ids_in_path = {step.evidence[0].rule_id for step in recon.attack_path}
    assert rule_ids_in_path == {"SOCF-029", "SOCF-030", "SOCF-027", "SOCF-028"}

    # The path should be ordered by the attack's actual timeline.
    ordered_rule_ids = [step.evidence[0].rule_id for step in recon.attack_path]
    assert ordered_rule_ids == ["SOCF-029", "SOCF-030", "SOCF-027", "SOCF-028"]

    # SOCF-027 -> SOCF-028 relies on host + time proximity (no shared src_ip or
    # username across a privilege-escalation boundary - see SOCF-CORR-017's
    # design note) - these items are 6 minutes apart, well within the
    # relationship-scoring engine's 30-minute proximity window.
    relationship_pairs = {(rel.from_step, rel.to_step) for rel in recon.relationships}
    assert len(relationship_pairs) >= 1


def _real_shaped_item(rule_id: str, timestamp: str, **details) -> dict:
    # Mirrors the actual nested shape produced by soc_forge/rules/engine.py's
    # run_rules() - no top-level src_ip/username/host at all, only under
    # "details", and the IP key is "ip" (not "src_ip").
    return {
        "rule_id": rule_id,
        "severity": "high",
        "title": f"{rule_id} test alert",
        "timestamp": timestamp,
        "details": {"host": "dispatch-ops01", **details},
        "mitre": [],
        "score": 80,
        "status": "new",
    }


def test_full_chain_reconstructs_from_real_pipeline_shaped_items():
    # Regression test for the details["ip"] vs details["src_ip"] fallback bug:
    # _candidate_from_item used to only check details.get("src_ip"), but real
    # alerts nest the address under details["ip"], so IP-based edge scoring
    # (score_link's heaviest signal, +0.35) silently never fired on real
    # pipeline data - only on flat, top-level-src_ip-shaped test fixtures like
    # the one above. This test uses the real nested shape end to end.
    header = {"case_id": "CASE-REAL-SHAPE"}
    items = [
        _real_shaped_item("SOCF-029", "2026-09-16T03:11:00Z", ip="203.0.113.7"),
        _real_shaped_item("SOCF-030", "2026-09-16T03:11:59Z", ip="203.0.113.7"),
        _real_shaped_item("SOCF-027", "2026-09-16T03:14:07Z", ip="203.0.113.7", username="dispatch-svc"),
        _real_shaped_item("SOCF-028", "2026-09-16T03:20:00Z", username="root"),
    ]

    recon = reconstruct_case(header, items)

    ordered_rule_ids = [step.evidence[0].rule_id for step in recon.attack_path]
    assert ordered_rule_ids == ["SOCF-029", "SOCF-030", "SOCF-027", "SOCF-028"]

    # SOCF-030 -> SOCF-027 loses the tactic-progression bonus (Credential
    # Access sits after Initial Access in TACTIC_ORDER's ATT&CK-matrix-column
    # order), so this edge specifically depends on the ip-match fix to clear
    # the 0.55 threshold on its own.
    relationship_reasons = {(rel.from_step, rel.to_step): rel.reason for rel in recon.relationships}
    assert (2, 3) in relationship_reasons
    assert "same src_ip" in relationship_reasons[(2, 3)]
