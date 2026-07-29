from pathlib import Path

import pytest

from soc_forge.cases.helpers import normalize_attack_step
from soc_forge.cases.recommended_actions import build_recommended_actions
from soc_forge.pipeline import AnalysisOptions, run_analysis_for_events
from soc_forge.rules.engine import load_rules, run_rules


RULE_CASES = [
    (
        "SOCF-021.yml",
        "SOCF-021",
        "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        "powershell.exe Get-MpComputerStatus",
    ),
    (
        "SOCF-021.yml",
        "SOCF-021",
        "powershell.exe Add-MpPreference -ExclusionPath C:\\Temp",
        "powershell.exe Update-MpSignature",
    ),
    (
        "SOCF-022.yml",
        "SOCF-022",
        "vssadmin.exe delete shadows /all /quiet",
        "vssadmin.exe list shadows",
    ),
    (
        "SOCF-022.yml",
        "SOCF-022",
        "wbadmin.exe delete catalog -quiet",
        "wbadmin.exe get versions",
    ),
]


def _event(command_line: str, event_id: int = 4688, provider: str | None = None):
    event = {
        "timestamp": "2026-07-17T12:00:00Z",
        "event_id": event_id,
        "host": "WS-LAB-01",
        "username": "alice",
        "process_name": command_line.split()[0],
        "command_line": command_line,
        "message": command_line,
    }
    if provider is not None:
        event["provider"] = provider
    return event


def _run(rule_file: str, event: dict) -> list[dict]:
    path = Path("soc_forge/rules") / rule_file
    return run_rules([event], load_rules([str(path)]))


@pytest.mark.parametrize(
    "rule_file,rule_id,positive_command,negative_command",
    RULE_CASES,
)
def test_new_rules_have_specific_positive_and_negative_commands(
    rule_file,
    rule_id,
    positive_command,
    negative_command,
):
    positive = _run(rule_file, _event(positive_command))
    negative = _run(rule_file, _event(negative_command))

    assert [alert["rule_id"] for alert in positive] == [rule_id]
    assert negative == []


@pytest.mark.parametrize(
    "rule_file,rule_id,command",
    [
        (
            "SOCF-021.yml",
            "SOCF-021",
            "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
        ),
        (
            "SOCF-022.yml",
            "SOCF-022",
            "vssadmin.exe delete shadows /all /quiet",
        ),
    ],
)
def test_new_rules_source_qualify_sysmon_event_one(rule_file, rule_id, command):
    valid = _run(
        rule_file,
        _event(command, event_id=1, provider="Microsoft-Windows-Sysmon"),
    )
    missing = _run(rule_file, _event(command, event_id=1))
    unrelated = _run(
        rule_file,
        _event(command, event_id=1, provider="Unrelated-Windows-Provider"),
    )

    assert [alert["rule_id"] for alert in valid] == [rule_id]
    assert missing == []
    assert unrelated == []


def test_new_rules_reach_pipeline_cases_and_analyst_guidance(tmp_path):
    events = [
        _event("powershell.exe Add-MpPreference -ExclusionPath C:\\Temp"),
        {
            **_event("vssadmin.exe delete shadows /all /quiet"),
            "timestamp": "2026-07-17T12:03:00Z",
        },
    ]

    result = run_analysis_for_events(
        AnalysisOptions(
            events=events,
            input_name="defense-impact-events.jsonl",
            output_dir=tmp_path,
            rules_only=True,
        )
    )

    alerts = [
        alert
        for alert in result.alerts
        if alert["rule_id"] in {"SOCF-021", "SOCF-022"}
    ]
    assert [alert["rule_id"] for alert in alerts] == ["SOCF-021", "SOCF-022"]
    assert result.cases
    assert len(result.reconstructions) == len(result.cases)
    assert all(path.exists() for path in result.artifacts.values())

    actions = build_recommended_actions(alerts)
    assert any("security control" in action.lower() for action in actions)
    assert any("recovery" in action.lower() for action in actions)
    assert normalize_attack_step(alerts[0]) == "Defense Evasion"
    assert normalize_attack_step(alerts[1]) == "Impact"
    assert normalize_attack_step({"rule_id": "SOCF-020"}) == "Collection"
