from soc_forge.investigations.export import build_closure_report


def test_build_closure_report_includes_disposition_and_summary():
    report = build_closure_report(
        {
            "case_id": "CASE-001",
            "title": "Suspicious activity",
            "status": "Closed",
            "owner": "analyst",
            "updated_at": "2026-07-16T12:00:00Z",
            "disposition": "True Positive",
            "closure_summary": "Confirmed malicious activity.",
            "containment_action": "Disabled account.",
            "status_history": [
                {
                    "changed_at": "2026-07-16T12:00:00Z",
                    "changed_by": "analyst",
                    "status": "Closed",
                    "reason": "Confirmed",
                }
            ],
        }
    )

    assert "Disposition: True Positive" in report
    assert "Confirmed malicious activity." in report
    assert "Disabled account." in report
    assert "2026-07-16T12:00:00Z | analyst | Closed | Confirmed" in report


def test_build_case_brief_includes_quality_sections():
    from soc_forge.investigations.export import build_case_brief

    brief = build_case_brief(
        {
            "case_id": "CASE-123",
            "title": "Privileged account abuse",
            "risk_score": 400,
            "case_quality": {
                "quality_score": 100,
                "executive_summary": "Critical account abuse sequence.",
                "key_findings": ["Audit logs were cleared."],
                "key_evidence": [
                    {
                        "timestamp": "2026-07-17T12:00:00Z",
                        "rule_id": "SOCF-009",
                        "title": "Audit logs cleared",
                        "why_it_matters": "Possible evidence removal.",
                    }
                ],
                "containment_guidance": ["Disable unauthorized account."],
                "quality_gaps": [],
            },
        }
    )

    assert "Executive Summary:" in brief
    assert "Critical account abuse sequence." in brief
    assert "Key Evidence:" in brief
    assert "Possible evidence removal." in brief
    assert "Containment Guidance:" in brief
