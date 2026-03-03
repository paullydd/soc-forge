from soc_forge.cli import detect_new_service_installed

def test_new_service_installed_7045_triggers():
    events = [
        {
            "timestamp": "2026-02-27T22:20:00Z",
            "event_id": 7045,
            "host": "WIN10",
            "service_name": "UpdaterSvc",
            "image_path": r"C:\Users\bob\AppData\Roaming\updater.exe",
            "service_account": "LocalSystem",
            "message": "service installed",
        }
    ]

    alerts = detect_new_service_installed(events, severity="high", score=80)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SOCF-004"
    assert alerts[0].severity == "high"
    assert alerts[0].score == 80
    assert alerts[0].details["service_name"] == "UpdaterSvc"
