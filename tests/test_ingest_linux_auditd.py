from pathlib import Path

from soc_forge.ingest.linux_auditd import (
    load_linux_auditd,
    load_linux_auditd_with_diagnostics,
)


def test_linux_auditd_happy_path_reassembles_execve_and_pairs_syscall(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990400.123:4821): arch=c000003e syscall=59 success=yes '
        'exit=0 items=2 ppid=4812 pid=4820 auid=1000 uid=0 gid=0 euid=0 comm="tar" '
        'exe="/usr/bin/tar" key="proc_exec"\n'
        'type=EXECVE msg=audit(1757990400.123:4821): argc=4 a0="tar" a1="-czf" '
        'a2="backup.tgz" a3="--checkpoint-action=exec=sh shell.sh"\n'
        'type=CWD msg=audit(1757990400.123:4821):  cwd="/var/backups/app"\n'
        'type=PROCTITLE msg=audit(1757990400.123:4821): proctitle=746172002D637A66\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]

    assert event["pid"] == 4820
    assert event["ppid"] == 4812
    assert event["process_name"] == "tar"
    assert event["exe"] == "/usr/bin/tar"
    assert event["command_line"] == "tar -czf backup.tgz --checkpoint-action=exec=sh shell.sh"
    assert event["uid"] == "0"
    assert "username" not in event
    assert event["timestamp"].startswith("2025-") or event["timestamp"].startswith("2026-")
    assert "execve pid=4820 exe=/usr/bin/tar:" in event["message"]
    assert result.parsed_record_count == 4


def test_linux_auditd_syscall_without_execve_or_path_is_skipped_with_info_diagnostic(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990500.100:5000): syscall=2 success=yes exit=3 '
        'ppid=1 pid=100 uid=0 comm="cat" exe="/bin/cat" key="proc_open"\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert result.events == []
    info_diagnostics = [d for d in result.diagnostics if d.level == "info"]
    assert any("no matching EXECVE or PATH records" in d.message for d in info_diagnostics)


def test_linux_auditd_interleaved_ids_are_grouped_by_id_not_line_position(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1758000000.100:5001): ppid=1 pid=100 uid=0 comm="bash" exe="/bin/bash"\n'
        'type=SYSCALL msg=audit(1758000000.150:5002): ppid=1 pid=200 uid=0 comm="ls" exe="/bin/ls"\n'
        'type=EXECVE msg=audit(1758000000.100:5001): argc=1 a0="bash"\n'
        'type=EXECVE msg=audit(1758000000.150:5002): argc=2 a0="ls" a1="-la"\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert len(result.events) == 2

    by_pid = {event["pid"]: event for event in result.events}
    assert by_pid[100]["process_name"] == "bash"
    assert by_pid[100]["command_line"] == "bash"
    assert by_pid[200]["process_name"] == "ls"
    assert by_pid[200]["command_line"] == "ls -la"


def test_linux_auditd_continuation_field_execve_warns_and_still_assembles(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990600.200:6000): ppid=4900 pid=5000 uid=0 comm="tar" exe="/usr/bin/tar"\n'
        'type=EXECVE msg=audit(1757990600.200:6000): argc=2 a0="tar" '
        'a1[0]="--checkpoint-action=exec=sh " a1[1]="shell.sh"\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]
    assert event["command_line"] == "tar --checkpoint-action=exec=sh shell.sh"

    warnings = [d for d in result.diagnostics if d.level == "warning"]
    assert any("continuation fields" in d.message for d in warnings)


def test_linux_auditd_enriched_uid_resolves_username(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990700.300:7000): ppid=1 pid=300 uid=0(root) comm="tar" exe="/usr/bin/tar"\n'
        'type=EXECVE msg=audit(1757990700.300:7000): argc=1 a0="tar"\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]
    assert event["username"] == "root"
    assert event["actor"] == "root"
    assert "uid" not in event


def test_linux_auditd_malformed_line_produces_warning_diagnostic(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text("this is not a valid audit log line at all\n", encoding="utf-8")

    result = load_linux_auditd_with_diagnostics(p)
    assert result.events == []
    levels = [d.level for d in result.diagnostics]
    assert "warning" in levels
    assert "Traceback" not in str(result.diagnostics)


def test_linux_auditd_missing_file_fails_with_controlled_diagnostic(tmp_path: Path):
    missing = tmp_path / "does-not-exist.log"

    result = load_linux_auditd_with_diagnostics(missing)

    assert result.events == []
    assert [d.to_dict() for d in result.diagnostics] == [
        {"level": "error", "message": "Linux auditd log file not found", "field": "input_path"}
    ]
    assert "Traceback" not in str(result.diagnostics)
    assert str(missing) not in str(result.diagnostics)


def test_linux_auditd_simple_loader_matches_full_result(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990400.123:4821): ppid=4812 pid=4820 uid=0 comm="tar" exe="/usr/bin/tar"\n'
        'type=EXECVE msg=audit(1757990400.123:4821): argc=1 a0="tar"\n',
        encoding="utf-8",
    )
    events = load_linux_auditd(p)
    assert len(events) == 1
    assert events[0]["pid"] == 4820


def test_linux_auditd_file_watch_event_uses_last_path_record_and_multiple_paths_not_overwritten(tmp_path: Path):
    # A watched-file write typically emits multiple PATH records sharing one
    # audit id (e.g. the containing directory, then the target file itself).
    # Regression test for the bug where the second PATH record used to
    # silently overwrite the first in the per-id "types" dict.
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990600.100:6100): arch=c000003e syscall=257 success=yes '
        'ppid=1 pid=6001 uid=0 comm="sh" exe="/usr/bin/dash" key="ssh_persistence"\n'
        'type=PATH msg=audit(1757990600.100:6100): item=0 name="/root/.ssh" nametype=PARENT\n'
        'type=PATH msg=audit(1757990600.100:6100): item=1 name="/root/.ssh/authorized_keys" nametype=NORMAL\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert len(result.events) == 1
    event = result.events[0]

    assert event["path"] == "/root/.ssh/authorized_keys"
    assert event["pid"] == 6001
    assert event["ppid"] == 1
    assert event["process_name"] == "sh"
    assert event["exe"] == "/usr/bin/dash"
    assert event["audit_key"] == "ssh_persistence"
    assert event["uid"] == "0"
    assert "username" not in event
    assert "command_line" not in event
    assert "write path=/root/.ssh/authorized_keys" in event["message"]


def test_linux_auditd_path_record_without_name_is_skipped_with_info_diagnostic(tmp_path: Path):
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990700.200:7100): ppid=1 pid=7001 uid=0 comm="sh" exe="/bin/sh"\n'
        'type=PATH msg=audit(1757990700.200:7100): item=0 nametype=UNKNOWN\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)
    assert result.events == []
    info_diagnostics = [d for d in result.diagnostics if d.level == "info"]
    assert any("none had a usable name field" in d.message for d in info_diagnostics)


def test_linux_auditd_hex_encodes_execve_arg_containing_a_space(tmp_path: Path):
    # Regression test for a real bug: real auditd prints an EXECVE argument as
    # an unquoted hex string (not a quoted string) when the argument contains
    # a character unsafe to print bare - notably whitespace, which an
    # injected "--checkpoint-action=exec=sh x.sh" payload contains. This is
    # the user's own real captured record from a lab VM (decoded by hand:
    # "2D2D...7368" -> "--checkpoint-action=exec=sh x.sh"), not a synthetic
    # approximation. The original fixture in the happy-path test above used
    # a3="--checkpoint-action=exec=sh shell.sh" (quoted), which real auditd
    # never emits for an argument containing a space, so it never exercised
    # this path and the bug went undetected until tested against real data.
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1789621829.835:222): arch=c000003e syscall=59 success=yes '
        'exit=0 items=2 ppid=4000 pid=4822 auid=1000 uid=0 gid=0 euid=0 comm="tar" '
        'exe="/usr/bin/tar" key="proc_exec"\n'
        'type=EXECVE msg=audit(1789621829.835:222): argc=4 a0="tar" a1="-czf" '
        'a2="/tmp/t.tgz" a3=2D2D636865636B706F696E742D616374696F6E3D657865633D736820782E7368\n',
        encoding="utf-8",
    )

    result = load_linux_auditd_with_diagnostics(p)

    assert len(result.events) == 1
    event = result.events[0]
    assert event["command_line"] == "tar -czf /tmp/t.tgz --checkpoint-action=exec=sh x.sh"
    assert result.diagnostics == []


def test_linux_auditd_hex_decode_does_not_corrupt_coincidentally_hex_looking_syscall_fields(tmp_path: Path):
    # pid=4822, ppid=4000, and uid=0 are all even-length strings consisting
    # solely of hex digit characters - exactly the shape _maybe_hex_decode
    # looks for - but SYSCALL's own numeric fields must never be run through
    # it; only EXECVE argN / PATH name are auditd's hex-encodable fields.
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1789621829.835:222): arch=c000003e syscall=59 success=yes '
        'exit=0 items=2 ppid=4000 pid=4822 auid=1000 uid=0 gid=0 euid=0 comm="tar" '
        'exe="/usr/bin/tar" key="proc_exec"\n'
        'type=EXECVE msg=audit(1789621829.835:222): argc=1 a0="tar"\n',
        encoding="utf-8",
    )

    event = load_linux_auditd_with_diagnostics(p).events[0]

    assert event["pid"] == 4822
    assert event["ppid"] == 4000
    assert event["uid"] == "0"


def test_linux_auditd_hex_decodes_path_name_containing_a_space(tmp_path: Path):
    # Same auditd mechanism as the EXECVE case, applied to a file-watch PATH
    # record's name - relevant to SOCF-031/032, which match on an
    # attacker-controlled filename that could itself contain a space.
    p = tmp_path / "audit.log"
    p.write_text(
        'type=SYSCALL msg=audit(1757990600.100:6100): arch=c000003e syscall=2 success=yes '
        'exit=3 ppid=1 pid=200 uid=0 comm="touch" exe="/usr/bin/touch" key="ssh_persistence"\n'
        'type=PATH msg=audit(1757990600.100:6100): item=0 '
        'name=2F726F6F742F2E7373682F617574686F72697A65642D6B65797320286261636B757029 '
        'nametype=NORMAL\n',
        encoding="utf-8",
    )

    event = load_linux_auditd_with_diagnostics(p).events[0]

    assert event["path"] == "/root/.ssh/authorized-keys (backup)"


def test_maybe_hex_decode_falls_back_on_odd_length_and_invalid_utf8(tmp_path: Path):
    from soc_forge.ingest.linux_auditd import _maybe_hex_decode

    # Odd-length -> never treated as hex, regardless of content.
    assert _maybe_hex_decode("abc") == "abc"
    # Even-length, all hex digits, but not valid UTF-8 once decoded -> falls
    # back to the original string rather than raising or returning garbage.
    assert _maybe_hex_decode("ff") == "ff"
    # Documented, unavoidable ambiguity: a literal unquoted value that
    # happens to consist solely of hex digit characters and even length
    # decodes as text anyway, same limitation real audit tooling has.
    assert _maybe_hex_decode("64656164") == "dead"
