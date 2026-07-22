from soc_forge.cases.quality import build_case_quality_profile
from soc_forge.cases.builder import build_cases
from soc_forge.report.html_report import build_cases as legacy_build_cases


def _alert(rule_id, title, ts="2026-07-17T12:00:00Z", score=50, severity="high", details=None):
    return {
        "timestamp": ts,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": score,
        "correlation_id": "demo-chain",
        "details": details or {"host": "WS-ENG-01", "target_user": "svc-backup-admin", "ip": "198.51.100.77", "message": title},
        "mitre": [{"tactic": "Persistence", "technique": "Create Account", "id": "T1136"}],
    }


def test_case_quality_profile_builds_summary_evidence_and_guidance():
    items = [
        _alert("SOCF-007", "New user account created"),
        _alert("SOCF-008", "User added to privileged group"),
        _alert("SOCF-009", "Audit logs cleared"),
        _alert("SOCF-CORR-005", "New privileged account followed by log clearing", score=120),
    ]

    profile = build_case_quality_profile(
        items,
        case_risk={"case_score": 350, "case_threat_level": "critical", "tactics": ["Persistence", "Defense Evasion"]},
        iocs={"hosts": ["WS-ENG-01"], "users": ["svc-backup-admin"], "ips": ["198.51.100.77"]},
        recommended_actions=["Disable account"],
        story="A generated story exists.",
    )

    assert "critical" in profile["executive_summary"].lower()
    assert profile["key_evidence"]
    assert any("audit log" in finding.lower() or "log clearing" in finding.lower() for finding in profile["key_findings"])
    assert any("disable" in action.lower() or "privileged" in action.lower() for action in profile["containment_guidance"])
    assert profile["quality_score"] == 100


def test_build_cases_attaches_case_quality_profile():
    cases = build_cases([
        _alert("SOCF-007", "New user account created"),
        _alert("SOCF-CORR-005", "New privileged account followed by log clearing", score=120),
    ], "demo.jsonl")

    case = cases[0]
    assert case["case_quality"]["executive_summary"]
    assert case["header"]["details"]["case_quality"]["key_evidence"]


def test_build_cases_new_and_legacy_import_paths_match():
    alerts = [
        _alert("SOCF-007", "New user account created", score=80),
        _alert("SOCF-CORR-005", "New privileged account followed by log clearing", score=120),
    ]

    new_cases = build_cases(alerts, "demo.jsonl")
    legacy_cases = legacy_build_cases(alerts, "demo.jsonl")

    assert new_cases == legacy_cases
    assert [case["case_id"] for case in new_cases] == [case["case_id"] for case in legacy_cases]
    assert [case["title"] for case in new_cases] == [case["title"] for case in legacy_cases]
    assert [case["risk_score"] for case in new_cases] == [case["risk_score"] for case in legacy_cases]
    assert new_cases[0]["evidence"] == legacy_cases[0]["evidence"]
