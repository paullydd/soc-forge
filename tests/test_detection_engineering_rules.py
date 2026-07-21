from pathlib import Path

from soc_forge.rules.engine import load_rules, run_rules


def run_rule(rule_file: str, event: dict) -> list[dict]:
    rules = load_rules([str(Path("soc_forge/rules") / rule_file)])
    return run_rules([event], rules)


def test_socf_011_detects_encoded_powershell():
    alerts = run_rule(
        "SOCF-011.yml",
        {
            "timestamp": "2026-07-17T12:00:00Z",
            "event_id": 4688,
            "host": "WS-ENG-01",
            "username": "alice",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -NoP -W Hidden -enc SQBFAFgA",
            "message": "New process powershell.exe -enc SQBFAFgA",
        },
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-011"
    assert alerts[0]["details"]["suspicious"] is True
    assert alerts[0]["details"]["command_line"].startswith("powershell.exe")


def test_socf_011_ignores_normal_powershell_admin_command():
    alerts = run_rule(
        "SOCF-011.yml",
        {
            "timestamp": "2026-07-17T12:00:00Z",
            "event_id": 4688,
            "host": "WS-ENG-01",
            "username": "admin01",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Get-Service WinDefend",
            "message": "New process powershell.exe Get-Service WinDefend",
        },
    )

    assert alerts == []


def test_socf_012_detects_user_writable_path_execution_and_boosts_masquerade():
    alerts = run_rule(
        "SOCF-012.yml",
        {
            "timestamp": "2026-07-17T12:03:00Z",
            "event_id": 4688,
            "host": "WS-ENG-01",
            "username": "alice",
            "process_name": "svchost.exe",
            "parent_process": "explorer.exe",
            "image_path": r"C:\Users\alice\AppData\Roaming\svchost.exe",
            "command_line": r"C:\Users\alice\AppData\Roaming\svchost.exe",
            "message": r"New process C:\Users\alice\AppData\Roaming\svchost.exe",
        },
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SOCF-012"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["score"] == 75
    assert alerts[0]["details"]["masquerade_risk"] is True


def test_socf_012_ignores_system32_execution():
    alerts = run_rule(
        "SOCF-012.yml",
        {
            "timestamp": "2026-07-17T12:03:00Z",
            "event_id": 4688,
            "host": "WS-ENG-01",
            "username": "alice",
            "process_name": "svchost.exe",
            "image_path": r"C:\Windows\System32\svchost.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "message": r"New process C:\Windows\System32\svchost.exe",
        },
    )

    assert alerts == []
