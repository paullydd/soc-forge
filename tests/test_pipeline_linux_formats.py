from unittest.mock import patch

import pytest

from soc_forge.ingest.linux_auditd import LinuxAuditdResult
from soc_forge.ingest.linux_auth_log import LinuxAuthLogResult
from soc_forge.pipeline import AnalysisOptions, load_events_with_diagnostics, run_analysis


def test_pipeline_calls_linux_auth_log_loader_and_runs_standard_rules(tmp_path):
    auth_event = {
        "timestamp": "2026-09-16T03:14:07Z",
        "host": "ubuntu-victim",
        "process_name": "sshd",
        "pid": 8842,
        "username": "dispatch-svc",
        "actor": "dispatch-svc",
        "ip": "203.0.113.7",
        "auth_result": "success",
        "auth_method": "password",
        "invalid_user": False,
        "message": "Accepted password for dispatch-svc from 203.0.113.7 port 51000 ssh2",
    }
    loader_result = LinuxAuthLogResult(
        events=[auth_event],
        diagnostics=[],
        row_count=1,
    )

    with patch(
        "soc_forge.pipeline.load_linux_auth_log_with_diagnostics", return_value=loader_result
    ) as loader:
        result = run_analysis(
            AnalysisOptions(
                input_path=tmp_path / "auth.log",
                input_format="linux-auth-log",
                output_dir=tmp_path,
                write_outputs=False,
                write_report=False,
                rules_only=True,
            )
        )

    loader.assert_called_once_with(tmp_path / "auth.log")
    assert result.event_count == 1
    assert result.ingest_diagnostics == loader_result.diagnostics_as_dicts()
    assert any(alert.get("rule_id") == "SOCF-027" for alert in result.alerts)


def test_linux_auth_log_diagnostics_propagate_without_explicit_format(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("this is not a valid auth log line at all\n", encoding="utf-8")

    events, diagnostics = load_events_with_diagnostics(p, input_format="linux-auth-log")

    assert events == []
    assert any(d["level"] == "warning" for d in diagnostics)


def test_pipeline_calls_linux_auditd_loader_and_runs_standard_rules(tmp_path):
    auditd_event = {
        "timestamp": "2026-09-16T03:20:00.123Z",
        "host": "dispatch-ops01",
        "process_name": "tar",
        "exe": "/usr/bin/tar",
        "pid": 4820,
        "ppid": 4812,
        "command_line": "tar -czf backup.tgz --checkpoint-action=exec=sh shell.sh",
        "uid": "0",
        "message": "execve pid=4820 exe=/usr/bin/tar: tar -czf backup.tgz --checkpoint-action=exec=sh shell.sh",
    }
    loader_result = LinuxAuditdResult(
        events=[auditd_event],
        diagnostics=[],
        parsed_record_count=2,
    )

    with patch(
        "soc_forge.pipeline.load_linux_auditd_with_diagnostics", return_value=loader_result
    ) as loader:
        result = run_analysis(
            AnalysisOptions(
                input_path=tmp_path / "audit.log",
                input_format="linux-auditd",
                output_dir=tmp_path,
                write_outputs=False,
                write_report=False,
                rules_only=True,
            )
        )

    loader.assert_called_once_with(tmp_path / "audit.log")
    assert result.event_count == 1
    assert result.ingest_diagnostics == loader_result.diagnostics_as_dicts()
    assert any(alert.get("rule_id") == "SOCF-028" for alert in result.alerts)


def test_dot_log_file_with_no_explicit_format_is_unsupported(tmp_path):
    unformatted = tmp_path / "auth.log"
    unformatted.write_text(
        "Sep 16 03:14:07 ubuntu-victim sshd[8842]: Accepted password for dispatch-svc from 203.0.113.7 port 51000 ssh2\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported input format"):
        load_events_with_diagnostics(unformatted)
