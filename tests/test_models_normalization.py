from soc_forge.models import Alert, alert_to_dict, normalize_case


def test_alert_to_dict_preserves_canonical_fields():
    alert = Alert(
        rule_id="SOCF-001",
        severity="high",
        title="Possible brute-force login attempts",
        timestamp="2026-01-01T00:00:00Z",
        details={"ip": "203.0.113.10"},
        mitre=[{"tactic": "Credential Access", "id": "T1110"}],
        score=60,
    )

    data = alert_to_dict(alert)

    assert data["rule_id"] == "SOCF-001"
    assert data["details"]["ip"] == "203.0.113.10"
    assert data["score"] == 60
    assert data["status"] == "new"
    assert data["correlation_id"] is None


def test_normalize_case_adds_console_friendly_fields():
    case = {
        "correlation_id": "abc123",
        "header": {
            "title": "RDP logon followed by scheduled task creation",
            "severity": "high",
            "timestamp": "2026-01-01T00:05:00Z",
            "score": 110,
            "details": {
                "case_risk": {
                    "case_score": 260,
                    "case_severity": "high",
                    "tactics": ["Lateral Movement", "Persistence"],
                },
                "iocs": {"ips": ["203.0.113.10"], "hosts": ["DC1"], "users": ["alice"]},
                "analyst_summary": "Suspicious RDP activity followed by persistence.",
            },
        },
        "alerts": [{"rule_id": "SOCF-CORR-002"}],
    }

    normalized = normalize_case(case)

    assert normalized["case_id"].startswith("CASE-")
    assert normalized["title"] == "RDP logon followed by scheduled task creation"
    assert normalized["status"] == "New"
    assert normalized["risk_score"] == 260
    assert normalized["indicators"]["hosts"] == ["DC1"]
    assert normalized["items"] == [{"rule_id": "SOCF-CORR-002"}]
    assert normalized["header"]["case_id"] == normalized["case_id"]
