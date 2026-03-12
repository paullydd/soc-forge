from pathlib import Path
from soc_forge.ingest.windows_security_csv import load_windows_security_csv


def test_windows_security_csv_ingest(tmp_path: Path):
    p = tmp_path / "security.csv"
    p.write_text(
        "Date and Time,Event ID,Computer,User,Message\n"
        "02/28/2026 09:01:00 PM,4625,WIN10,bob,An account failed to log on\n"
        "02/28/2026 09:08:00 PM,4740,DC01,bob,An account was locked out\n",
        encoding="utf-8",
    )

    events = list(load_windows_security_csv(p))
    assert len(events) == 2
    assert events[0]["event_id"] == 4625
    assert events[0]["username"] == "bob"
    assert events[0]["host"] == "WIN10"
    assert "timestamp" in events[0]
