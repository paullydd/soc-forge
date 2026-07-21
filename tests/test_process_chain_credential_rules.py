from pathlib import Path

from soc_forge.rules.engine import load_rules, run_rules


def run_rule(rule_file: str, event: dict) -> list[dict]:
    return run_rules([event], load_rules([str(Path("soc_forge/rules") / rule_file)]))


def test_socf_013_detects_office_spawning_powershell():
    alerts = run_rule(
        "SOCF-013.yml",
        {
            "timestamp": "2026-07-17T12:11:00Z",
            "event_id": 4688,
            "host": "WS-01",
            "username": "alice",
            "parent_process": "winword.exe",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoP -enc SQBFAFgA",
            "message": "Parent winword.exe created powershell.exe",
        },
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-013"
    assert alerts[0]["details"]["parent_process"] == "winword.exe"


def test_socf_013_ignores_office_spawning_browser():
    alerts = run_rule(
        "SOCF-013.yml",
        {
            "timestamp": "2026-07-17T12:11:00Z",
            "event_id": 4688,
            "host": "WS-01",
            "username": "alice",
            "parent_process": "winword.exe",
            "process_name": "chrome.exe",
            "command_line": "chrome.exe https://example.com",
            "message": "Parent winword.exe created chrome.exe",
        },
    )

    assert alerts == []


def test_socf_014_detects_lsass_dump_command():
    alerts = run_rule(
        "SOCF-014.yml",
        {
            "timestamp": "2026-07-17T12:12:00Z",
            "event_id": 4688,
            "host": "WS-01",
            "username": "alice",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 500 C:\\Temp\\lsass.dmp full",
            "message": "rundll32 comsvcs.dll MiniDump lsass",
        },
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-014"
    assert alerts[0]["severity"] == "critical"


def test_socf_014_ignores_normal_process_dump():
    alerts = run_rule(
        "SOCF-014.yml",
        {
            "timestamp": "2026-07-17T12:12:00Z",
            "event_id": 4688,
            "host": "WS-01",
            "username": "alice",
            "process_name": "procdump64.exe",
            "command_line": "procdump64.exe -ma notepad.exe C:\\Temp\\notepad.dmp",
            "message": "procdump notepad",
        },
    )

    assert alerts == []


def test_socf_015_detects_browser_credential_store_access():
    alerts = run_rule(
        "SOCF-015.yml",
        {
            "timestamp": "2026-07-17T12:13:00Z",
            "event_id": 4663,
            "host": "WS-01",
            "username": "alice",
            "process_name": "python.exe",
            "file_path": "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "message": "python.exe read Chrome Login Data",
        },
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-015"
    assert "Login Data" in alerts[0]["details"]["file_path"]


def test_socf_015_ignores_browser_accessing_own_store():
    alerts = run_rule(
        "SOCF-015.yml",
        {
            "timestamp": "2026-07-17T12:13:00Z",
            "event_id": 4663,
            "host": "WS-01",
            "username": "alice",
            "process_name": "chrome.exe",
            "file_path": "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "message": "chrome.exe read Chrome Login Data",
        },
    )

    assert alerts == []
