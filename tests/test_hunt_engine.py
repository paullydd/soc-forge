from soc_forge.hunts.engine import run_hunts

def test_run_hunts_multiple_findings():
    events = [
        {
            "timestamp": "2026-03-12T08:00:00",
            "host": "WIN10",
            "username": "bob",
            "src_ip": "10.0.0.5",
        },
        {
            "timestamp": "2026-03-12T08:05:00",
            "host": "DC01",
            "username": "bob",
            "src_ip": "203.0.113.50",
        },
        {
            "timestamp": "2026-03-12T08:10:00",
            "host": "WIN10",
            "username": "bob",
            "command_line": "powershell -enc test",
        },
    ]

    findings = run_hunts(events)

    assert len(findings) >= 2
