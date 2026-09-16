from pathlib import Path

from soc_forge.ingest.nginx_access_log import (
    load_nginx_access_log,
    load_nginx_access_log_with_diagnostics,
)


def test_nginx_access_log_happy_path(tmp_path: Path):
    p = tmp_path / "access.log"
    p.write_text(
        '192.168.128.2 - - [16/Sep/2026:03:10:00 +0000] "GET /login HTTP/1.1" 200 536 "-" "curl/8.4.0"\n'
        '203.0.113.7 - - [16/Sep/2026:03:11:05 +0000] "GET /.git/HEAD HTTP/1.1" 200 23 "-" "gobuster/3.8.2"\n'
        '203.0.113.7 - - [16/Sep/2026:03:11:06 +0000] "GET /admin1 HTTP/1.1" 404 162 "-" "gobuster/3.8.2"\n',
        encoding="utf-8",
    )

    result = load_nginx_access_log_with_diagnostics(p)
    events = result.events
    assert len(events) == 3
    assert result.row_count == 3

    login = events[0]
    assert login["ip"] == "192.168.128.2"
    assert login["method"] == "GET"
    assert login["uri"] == "/login"
    assert login["status_code"] == 200
    assert login["bytes_sent"] == 536
    assert login["user_agent"] == "curl/8.4.0"
    assert "referrer" not in login
    assert login["timestamp"] == "2026-09-16T03:10:00Z"

    git_hit = events[1]
    assert git_hit["uri"] == "/.git/HEAD"
    assert git_hit["status_code"] == 200
    assert git_hit["user_agent"] == "gobuster/3.8.2"

    not_found = events[2]
    assert not_found["status_code"] == 404


def test_nginx_access_log_simple_loader_matches_full_result(tmp_path: Path):
    p = tmp_path / "access.log"
    p.write_text(
        '192.168.128.2 - - [16/Sep/2026:03:10:00 +0000] "GET /login HTTP/1.1" 200 536 "-" "curl/8.4.0"\n',
        encoding="utf-8",
    )
    events = load_nginx_access_log(p)
    assert len(events) == 1
    assert events[0]["uri"] == "/login"


def test_nginx_access_log_malformed_line_produces_warning_diagnostic(tmp_path: Path):
    p = tmp_path / "access.log"
    p.write_text("this is not a valid access log line at all\n", encoding="utf-8")

    result = load_nginx_access_log_with_diagnostics(p)
    assert result.events == []
    levels = [d.level for d in result.diagnostics]
    assert "warning" in levels
    assert "Traceback" not in str(result.diagnostics)


def test_nginx_access_log_missing_file_fails_with_controlled_diagnostic(tmp_path: Path):
    missing = tmp_path / "does-not-exist.log"

    result = load_nginx_access_log_with_diagnostics(missing)

    assert result.events == []
    assert [d.to_dict() for d in result.diagnostics] == [
        {"level": "error", "message": "Nginx access log file not found", "field": "input_path"}
    ]
    assert "Traceback" not in str(result.diagnostics)
    assert str(missing) not in str(result.diagnostics)


def test_nginx_access_log_malformed_request_field_still_emits_minimal_event(tmp_path: Path):
    p = tmp_path / "access.log"
    p.write_text(
        '192.168.128.2 - - [16/Sep/2026:03:10:00 +0000] "-" 400 0 "-" "-"\n',
        encoding="utf-8",
    )

    result = load_nginx_access_log_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]
    assert event["ip"] == "192.168.128.2"
    assert event["status_code"] == 400
    assert "uri" not in event
    assert "user_agent" not in event

    info_diagnostics = [d for d in result.diagnostics if d.level == "info"]
    assert any("did not parse into method/uri/protocol" in d.message for d in info_diagnostics)
