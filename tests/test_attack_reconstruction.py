from soc_forge.reconstruct.engine import reconstruct_case

def test_reconstruction_builds_expected_path():
    header = {"case_id": "CASE-1"}
    items = [
        {
            "rule_id": "SOCF-001",
            "timestamp": "2026-03-25T09:10:00Z",
            "src_ip": "203.0.113.50",
            "username": "alice",
            "host": "DC1",
            "score": 60,
        },
        {
            "rule_id": "SOCF-006",
            "timestamp": "2026-03-25T09:14:00Z",
            "src_ip": "203.0.113.50",
            "username": "alice",
            "host": "WEB01",
            "score": 55,
        },
        {
            "rule_id": "SOCF-005",
            "timestamp": "2026-03-25T09:18:00Z",
            "username": "alice",
            "host": "WEB01",
            "score": 75,
        },
    ]

    recon = reconstruct_case(header, items)

    assert recon.case_id == "CASE-1"
    assert len(recon.attack_path) >= 3
    titles = [s.title for s in recon.attack_path]
    assert any("Brute force" in t for t in titles)
    assert any("RDP" in t or "remote" in t.lower() for t in titles)
    assert any("scheduled task" in t.lower() for t in titles)

def test_reconstruction_infers_access_step_between_failures_and_rdp():
    header = {"case_id": "CASE-2"}
    items = [
        {
            "rule_id": "SOCF-001",
            "timestamp": "2026-03-25T09:10:00Z",
            "src_ip": "203.0.113.50",
            "username": "alice",
            "host": "DC1",
            "score": 60,
        },
        {
            "rule_id": "SOCF-006",
            "timestamp": "2026-03-25T09:14:00Z",
            "src_ip": "203.0.113.50",
            "username": "alice",
            "host": "WEB01",
            "score": 55,
        },
    ]

    recon = reconstruct_case(header, items)
    assert any(step.inferred for step in recon.attack_path)

def test_reconstruction_collects_key_entities():
    header = {"case_id": "CASE-3"}
    items = [
        {
            "rule_id": "SOCF-006",
            "timestamp": "2026-03-25T09:14:00Z",
            "src_ip": "203.0.113.50",
            "username": "alice",
            "host": "WEB01",
            "score": 55,
        }
    ]

    recon = reconstruct_case(header, items)
    assert "203.0.113.50" in recon.key_entities["src_ips"]
    assert "alice" in recon.key_entities["users"]
    assert "WEB01" in recon.key_entities["hosts"]

def test_reconstruction_handles_empty_case():
    recon = reconstruct_case({"case_id": "CASE-EMPTY"}, [])
    assert recon.case_id == "CASE-EMPTY"
    assert recon.attack_path == []
    assert recon.confidence == 0.0
