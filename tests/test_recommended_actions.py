from soc_forge.cases.recommended_actions import build_recommended_actions


def test_recommended_actions_rdp_plus_schtask_combo():
    items = [
        {"rule_id": "SOCF-006", "username": "bob", "host": "WIN10", "src_ip": "203.0.113.50", "severity": "medium"},
        {"rule_id": "SOCF-010", "username": "bob", "host": "WIN10", "src_ip": "203.0.113.50", "severity": "medium"},
    ]
    actions = build_recommended_actions(items)

    # Pivots
    assert any("Validate user access" in a for a in actions)
    assert any("impacted endpoint" in a.lower() for a in actions)
    assert any("Confirm source IP" in a for a in actions)

    # Combo-driven actions
    assert any("process tree around first RDP logon" in a for a in actions)
    assert any("scheduled task details" in a for a in actions)


def test_recommended_actions_bruteforce_lockout_suggests_block():
    items = [
        {"rule_id": "SOCF-001", "username": "alice", "host": "DC1", "src_ip": "203.0.113.99", "severity": "high"},
        {"rule_id": "SOCF-002", "username": "alice", "host": "DC1", "src_ip": "203.0.113.99", "severity": "high"},
    ]
    actions = build_recommended_actions(items)
    assert any("password spray" in a.lower() or "brute-force scope" in a.lower() for a in actions)
    assert any("blocking source ip" in a.lower() for a in actions)
