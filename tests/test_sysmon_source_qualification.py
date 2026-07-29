from pathlib import Path

import pytest

from soc_forge.rules.engine import load_rules, run_rules


SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

SYSMON_CASES = [
    ("SOCF-014.yml", 1, {"command_line": "mimikatz.exe sekurlsa::logonpasswords"}),
    ("SOCF-014.yml", 10, {"target_process": r"C:\Windows\System32\lsass.exe"}),
    (
        "SOCF-015.yml",
        11,
        {
            "file_path": r"C:\Users\alice\Chrome\User Data\Default\Login Data",
            "process_name": "powershell.exe",
        },
    ),
    (
        "SOCF-015.yml",
        15,
        {
            "target_filename": r"C:\Users\alice\Firefox\Profiles\default\logins.json",
            "process_name": "python.exe",
        },
    ),
    (
        "SOCF-017.yml",
        1,
        {
            "process_name": "wmic.exe",
            "command_line": "wmic process call create cmd.exe",
        },
    ),
    (
        "SOCF-018.yml",
        1,
        {
            "process_name": "mshta.exe",
            "command_line": "mshta.exe https://example.invalid/a.hta",
        },
    ),
    ("SOCF-019.yml", 1, {"command_line": r"\\server\ADMIN$\payload.exe"}),
    (
        "SOCF-020.yml",
        1,
        {
            "process_name": "7z.exe",
            "command_line": r"7z.exe a loot.zip C:\Users\alice\Documents",
        },
    ),
]

SECURITY_CASES = [
    ("SOCF-014.yml", 4688, {"command_line": "mimikatz.exe sekurlsa::logonpasswords"}),
    (
        "SOCF-015.yml",
        4663,
        {
            "file_path": r"C:\Users\alice\Chrome\User Data\Default\Login Data",
            "process_name": "powershell.exe",
        },
    ),
    (
        "SOCF-017.yml",
        4688,
        {
            "process_name": "wmic.exe",
            "command_line": "wmic process call create cmd.exe",
        },
    ),
    (
        "SOCF-018.yml",
        4688,
        {
            "process_name": "mshta.exe",
            "command_line": "mshta.exe https://example.invalid/a.hta",
        },
    ),
    ("SOCF-019.yml", 4688, {"command_line": r"\\server\ADMIN$\payload.exe"}),
    (
        "SOCF-020.yml",
        4688,
        {
            "process_name": "7z.exe",
            "command_line": r"7z.exe a loot.zip C:\Users\alice\Documents",
        },
    ),
]


def _event(event_id: int, fields: dict, provider: str | None = None) -> dict:
    event = {
        "timestamp": "2026-07-17T12:00:00Z",
        "event_id": event_id,
        "host": "WS-LAB-01",
        "username": "alice",
        "message": "Synthetic source-qualification test event",
        **fields,
    }
    if provider is not None:
        event["provider"] = provider
    return event


def _alerts(rule_file: str, event: dict) -> list[dict]:
    rule_path = Path("soc_forge/rules") / rule_file
    return run_rules([event], load_rules([str(rule_path)]))


@pytest.mark.parametrize("rule_file,event_id,fields", SYSMON_CASES)
def test_sysmon_event_ids_require_sysmon_provider(rule_file, event_id, fields):
    valid = _alerts(rule_file, _event(event_id, fields, SYSMON_PROVIDER))
    missing = _alerts(rule_file, _event(event_id, fields))
    unrelated = _alerts(
        rule_file,
        _event(event_id, fields, "Unrelated-Windows-Provider"),
    )

    assert len(valid) == 1
    assert missing == []
    assert unrelated == []


@pytest.mark.parametrize("rule_file,event_id,fields", SECURITY_CASES)
def test_native_security_branches_do_not_require_sysmon_provider(
    rule_file,
    event_id,
    fields,
):
    assert len(_alerts(rule_file, _event(event_id, fields))) == 1
