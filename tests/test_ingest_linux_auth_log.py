from pathlib import Path

from soc_forge.ingest.linux_auth_log import (
    load_linux_auth_log,
    load_linux_auth_log_with_diagnostics,
)


def test_linux_auth_log_happy_path(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Sep 16 03:14:07 ubuntu-victim sshd[8842]: Accepted password for dispatch-svc from 192.168.128.2 port 51000 ssh2\n"
        "Sep 16 03:15:02 ubuntu-victim sshd[8850]: Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2\n"
        "Sep 16 03:15:10 ubuntu-victim sshd[8851]: Invalid user test from 203.0.113.7 port 41010\n"
        "Sep 16 03:16:00 ubuntu-victim CRON[9001]: (root) CMD (run-parts /etc/cron.hourly)\n",
        encoding="utf-8",
    )

    result = load_linux_auth_log_with_diagnostics(p, default_year=2026)
    events = result.events

    # The CRON line is out of scope for this adapter and must be excluded entirely.
    assert len(events) == 3
    assert result.row_count == 3

    accepted = events[0]
    assert accepted["process_name"] == "sshd"
    assert accepted["host"] == "ubuntu-victim"
    assert accepted["pid"] == 8842
    assert accepted["username"] == "dispatch-svc"
    assert accepted["ip"] == "192.168.128.2"
    assert accepted["auth_result"] == "success"
    assert accepted["auth_method"] == "password"
    assert accepted["invalid_user"] is False
    assert accepted["timestamp"] == "2026-09-16T03:14:07Z"

    failed = events[1]
    assert failed["auth_result"] == "failure"
    assert failed["auth_method"] == "password"
    assert failed["username"] == "admin"
    assert failed["invalid_user"] is True

    invalid = events[2]
    assert invalid["auth_result"] == "failure"
    assert invalid["username"] == "test"
    assert invalid["invalid_user"] is True


def test_linux_auth_log_simple_loader_matches_full_result(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Sep 16 03:14:07 ubuntu-victim sshd[8842]: Accepted password for dispatch-svc from 192.168.128.2 port 51000 ssh2\n",
        encoding="utf-8",
    )
    events = load_linux_auth_log(p)
    assert len(events) == 1
    assert events[0]["username"] == "dispatch-svc"


def test_linux_auth_log_journalctl_iso_variant_parses_like_syslog(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text(
        "2026-09-16T03:14:07+0000 ubuntu-victim sshd[8842]: Accepted password for dispatch-svc from 192.168.128.2 port 51000 ssh2\n",
        encoding="utf-8",
    )
    result = load_linux_auth_log_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]
    assert event["username"] == "dispatch-svc"
    assert event["auth_result"] == "success"
    assert event["timestamp"] == "2026-09-16T03:14:07+0000"


def test_linux_auth_log_malformed_line_produces_warning_diagnostic(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text("this is not a valid auth log line at all\n", encoding="utf-8")

    result = load_linux_auth_log_with_diagnostics(p)
    assert result.events == []
    levels = [d.level for d in result.diagnostics]
    assert "warning" in levels
    assert "Traceback" not in str(result.diagnostics)


def test_linux_auth_log_missing_file_fails_with_controlled_diagnostic(tmp_path: Path):
    missing = tmp_path / "does-not-exist.log"

    result = load_linux_auth_log_with_diagnostics(missing)

    assert result.events == []
    assert [d.to_dict() for d in result.diagnostics] == [
        {"level": "error", "message": "Linux auth log file not found", "field": "input_path"}
    ]
    assert "Traceback" not in str(result.diagnostics)
    assert str(missing) not in str(result.diagnostics)


def test_linux_auth_log_unrecognized_sshd_message_still_emits_minimal_event(tmp_path: Path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Sep 16 03:14:07 ubuntu-victim sshd[8842]: Server listening on 0.0.0.0 port 22.\n",
        encoding="utf-8",
    )

    result = load_linux_auth_log_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]
    assert event["host"] == "ubuntu-victim"
    assert event["process_name"] == "sshd"
    assert "message" in event
    assert "username" not in event

    info_diagnostics = [d for d in result.diagnostics if d.level == "info"]
    assert any("did not match a known auth event pattern" in d.message for d in info_diagnostics)
