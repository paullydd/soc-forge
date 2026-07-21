from soc_forge.rules.quality import evaluate_rule_quality, evaluate_rule_quality_from_paths, format_rule_quality_report


def test_builtin_rules_pass_quality_gate():
    report = evaluate_rule_quality_from_paths(["soc_forge/rules"])

    assert report.passed, format_rule_quality_report(report)


def test_rule_quality_flags_missing_metadata_and_emit_details():
    report = evaluate_rule_quality(
        [
            {
                "id": "BAD-1",
                "title": "Thin rule",
                "severity": "medium",
                "score": 10,
                "mitre": [],
                "match": {"all": [{"field": "event_id", "op": "eq", "value": 1}]},
            }
        ]
    )

    text = format_rule_quality_report(report)
    assert not report.passed
    assert "description" in text
    assert "emit.details" in text
    assert "MITRE" in text
