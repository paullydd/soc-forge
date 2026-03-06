from soc_forge.report.html_report import build_attack_flow


def test_build_attack_flow_includes_mitre_ids():
    items = [
        {
            "rule_id": "SOCF-001",
            "title": "Bruteforce detected",
            "timestamp": "2025-07-01T10:21:00",
            "severity": "medium",
            "mitre": [{"tactic": "Credential Access", "technique": "T1110"}],
        },
        {
            "rule_id": "SOCF-006",
            "title": "RDP logon detected",
            "timestamp": "2025-07-01T10:22:00",
            "severity": "medium",
            "mitre": [{"tactic": "Lateral Movement", "technique": "T1021"}],
        },
    ]

    flow = build_attack_flow(items)

    assert flow[0]["label"] == "Brute Force"
    assert "T1110" in flow[0]["mitre_ids"]

    assert flow[1]["label"] == "Remote Access"
    assert "T1021" in flow[1]["mitre_ids"]