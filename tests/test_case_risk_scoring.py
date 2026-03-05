from soc_forge.scoring.risk import score_case

def test_case_score_increases_with_corr_and_multiple_tactics():
    alerts = [
        {"rule_id": "SOCF-006", "timestamp": "t1", "severity": "medium", "score": 55,
         "mitre": [{"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"}]},
        {"rule_id": "SOCF-005", "timestamp": "t2", "severity": "high", "score": 95,
         "mitre": [{"tactic": "Persistence", "technique": "Scheduled Task/Job", "id": "T1053"}]},
        {"rule_id": "SOCF-CORR-002", "timestamp": "t3", "severity": "high", "score": 110,
         "mitre": [{"tactic": "Persistence", "technique": "Scheduled Task/Job", "id": "T1053"}]},
    ]

    r = score_case(alerts)
    assert r["case_score"] > r["base_score"]
    assert r["case_threat_level"] in {"medium", "high", "critical"}
    assert "Correlation present" in " ".join(r["reasons"])
    assert "Multi-tactic activity" in " ".join(r["reasons"])
