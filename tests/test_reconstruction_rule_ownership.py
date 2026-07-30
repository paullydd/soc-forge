from soc_forge.reconstruct.engine import reconstruct_case


def _item(rule_id: str, timestamp: str) -> dict:
    return {
        "rule_id": rule_id,
        "timestamp": timestamp,
        "host": "WIN-ENDPOINT-01",
        "username": "analyst",
        "score": 80,
    }


def test_v23_rules_have_explicit_reconstruction_stages_and_techniques():
    expected = {
        "SOCF-020": ("Collection", "Collection", "T1560"),
        "SOCF-021": ("Defense Evasion", "Defense Evasion", "T1562.001"),
        "SOCF-022": ("Impact", "Impact", "T1490"),
    }

    for index, (rule_id, contract) in enumerate(expected.items()):
        reconstruction = reconstruct_case(
            {"case_id": f"CASE-{rule_id}"},
            [_item(rule_id, f"2026-07-29T12:0{index}:00Z")],
        )
        assert len(reconstruction.attack_path) == 1
        step = reconstruction.attack_path[0]
        assert step.evidence[0].rule_id == rule_id
        assert (step.stage, step.tactic, step.technique) == contract


def test_service_execution_ownership_remains_limited_to_service_rules():
    reconstruction = reconstruct_case(
        {"case_id": "CASE-SERVICE"},
        [
            _item("SOCF-004", "2026-07-29T12:00:00Z"),
            _item("SOCF-016", "2026-07-29T12:01:00Z"),
            _item("SOCF-021", "2026-07-29T12:02:00Z"),
        ],
    )

    stages_by_rule = {
        evidence.rule_id: step.stage
        for step in reconstruction.attack_path
        for evidence in step.evidence
        if evidence.rule_id
    }
    assert stages_by_rule["SOCF-004"] == "Service Execution"
    assert stages_by_rule["SOCF-016"] == "Service Execution"
    assert stages_by_rule["SOCF-021"] == "Defense Evasion"


def test_unrelated_alert_does_not_acquire_a_v23_stage():
    reconstruction = reconstruct_case(
        {"case_id": "CASE-UNRELATED"},
        [_item("UNRELATED-001", "2026-07-29T12:00:00Z")],
    )

    assert reconstruction.attack_path == []
