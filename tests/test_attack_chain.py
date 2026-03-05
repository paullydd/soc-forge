from soc_forge.report.html_report import build_attack_chain

def _a(ts, rid, title):
    return {"timestamp": ts, "rule_id": rid, "title": title, "severity": "low", "details": {}}

def test_attack_chain_orders_by_first_seen_and_is_deterministic():
    items = [
        _a("2026-02-27T22:20:00Z", "SOCF-005", "Scheduled task created"),
        _a("2026-02-27T22:01:00Z", "SOCF-006", "RDP logon detected (LogonType 10)"),
    ]
    chain = build_attack_chain(items)

    # RDP should infer Lateral Movement; scheduled task -> Persistence
    assert chain["tactics"] == ["Lateral Movement", "Persistence"]

    lm = chain["by_tactic"]["Lateral Movement"]
    ps = chain["by_tactic"]["Persistence"]

    assert lm["first_seen"] == "2026-02-27T22:01:00Z"
    assert ps["first_seen"] == "2026-02-27T22:20:00Z"
