import argparse
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_forge.report.html_report import write_html_report
from soc_forge.correlate.rules import correlate_alerts
from soc_forge.config import load_config
from soc_forge.ingest.windows_security_csv import iter_windows_security_events
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

console = Console()

# ---------- Models ----------
@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    timestamp: str
    details: dict
    mitre: list
    score: int = 0
    status: str = "new"
    correlation_id: str | None = None

# ---------- Helpers ----------
def parse_ts(ts: str) -> datetime:
    # Accepts ISO timestamps with Z or offset
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)

def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)

def _contains_any(s: str | None, needles: list[str]) -> bool:
    if not s:
        return False
    hay = s.lower()
    return any(n.lower() in hay for n in needles)

def _bump_severity(base: str) -> str:
    order = ["low", "medium", "high", "critical"]
    try:
        idx = order.index((base or "medium").lower())
    except ValueError:
        idx = 1
    return order[min(idx + 1, len(order) - 1)]

def _contains_any(s: str | None, needles: list[str]) -> bool:
    if not s:
        return False
    hay = s.lower()
    return any(n.lower() in hay for n in needles)

def _bump_severity(base: str) -> str:
    order = ["low", "medium", "high", "critical"]
    try:
        idx = order.index((base or "medium").lower())
    except ValueError:
        idx = 1
    return order[min(idx + 1, len(order) - 1)]

def _extract_logon_type(msg: str) -> int | None:
    if not msg:
        return None
    m = re.search(r"logon\s*type:\s*(\d+)", msg, flags=re.IGNORECASE)
    return int(m.group(1)) if m else None

# ---------- Detectors ----------
def detect_bruteforce(events, threshold=8, window_minutes=10, severity="high", score=60):
    """
    Rule: >= threshold failed logons (4625) from same IP in window
    """
    window = timedelta(minutes=window_minutes)
    buckets = defaultdict(deque)  # ip -> deque[timestamps]
    alerts = []

    for ev in events:
        if ev.get("event_id") != 4625:
            continue
        ip = ev.get("ip") or "unknown"
        ts = parse_ts(ev["timestamp"])

        dq = buckets[ip]
        dq.append(ts)

        # pop old
        while dq and (ts - dq[0]) > window:
            dq.popleft()

        if len(dq) == threshold:
            alerts.append(Alert(
                rule_id="SOCF-001",
                severity=severity,
                title="Possible brute-force login attempts",
                timestamp=ts.isoformat().replace("+00:00", "Z"),
                details={
                    "ip": ip,
                    "count_in_window": len(dq),
                    "window_minutes": window_minutes,
                    "example_username": ev.get("username"),
                    "host": ev.get("host"),
                },
                mitre=[{"tactic":"Credential Access","technique":"Brute Force","id":"T1110"}],
                score=score,
            ))
    return alerts

def detect_account_lockout(events, severity="medium", score=40):
    alerts = []
    for ev in events:
        if ev.get("event_id") == 4740:
            ts = parse_ts(ev["timestamp"])
            alerts.append(Alert(
                rule_id="SOCF-002",
                severity="medium",
                title="Account lockout observed",
                timestamp=ts.isoformat().replace("+00:00", "Z"),
                details={"username": ev.get("username"), "host": ev.get("host"), "ip": ev.get("ip")},
                mitre=[{"tactic":"Credential Access","technique":"Password Guessing","id":"T1110"}]
            ))
    return alerts

def detect_new_admin(events, severity="high", score=90):
    """
    Basic: group membership changes that might grant admin rights.
    You can refine later once you normalize exact fields.
    """
    admin_event_ids = {4728, 4732}  # added to security-enabled global/local group (common)
    alerts = []
    for ev in events:
        if ev.get("event_id") in admin_event_ids:
            ts = parse_ts(ev["timestamp"])
            alerts.append(Alert(
                rule_id="SOCF-003",
                severity="high",
                title="Privileged group membership change (possible new admin)",
                timestamp=ts.isoformat().replace("+00:00", "Z"),
                details={
                    "username": ev.get("username"),
                    "target_group": ev.get("group", "unknown"),
                    "host": ev.get("host"),
                    "actor": ev.get("actor"),
                },
                mitre=[{"tactic":"Privilege Escalation","technique":"Valid Accounts","id":"T1078"}],
                score=90,
            ))
    return alerts

def detect_new_service_installed(events, severity="high", score=80, suspicious_markers=None, score_boost=20):
    """
    Rule: New service installed (System Event ID 7045)
    """
    suspicious_path_markers = [
        r"\users\\", r"\appdata\\", r"\temp\\", r"\programdata\\"
    ]
    suspicious_lolbins = [
        "powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe"
    ]

    suspicious_markers = suspicious_markers or []

    alerts = []
    for ev in events:
        if ev.get("event_id") != 7045:
            continue

        ts = parse_ts(ev["timestamp"])

        blob = (ev.get("image_path") or "") + " " + (ev.get("message") or "")
        is_suspicious = _contains_any(blob, suspicious_markers)

        sev = severity
        sc = score
        if is_suspicious:
            # bump severity one level (high->critical, medium->high, etc.)
            sev = _bump_severity(sev)
            sc += score_boost

        alerts.append(Alert(
            rule_id="SOCF-004",
            severity=sev,
            title="New service installed",
            timestamp=ts.isoformat().replace("+00:00", "Z"),
            details={
                "host": ev.get("host"),
                "service_name": ev.get("service_name"),
                "image_path": ev.get("image_path"),
                "service_account": ev.get("service_account"),
                "suspicious": is_suspicious,
                "message": ev.get("message"),
            },
            mitre=[{"tactic": "Persistence", "technique": "Create or Modify System Process", "id": "T1543"}],
            score=sc,
        ))
    return alerts

def detect_scheduled_task_created(events, severity="high", score=75, suspicious_markers=None, score_boost=20):
    """
    Rule: Scheduled task created (Security Event ID 4698)
    """
    suspicious_keywords = [
        "powershell", " -enc ", "cmd.exe", "rundll32", "mshta", "wscript"
    ]

    suspicious_markers = suspicious_markers or []

    alerts = []
    for ev in events:
        if ev.get("event_id") != 4698:
            continue

        ts = parse_ts(ev["timestamp"])
        
        blob = (ev.get("task_command") or "") + " " + (ev.get("message") or "")
        is_suspicious = _contains_any(blob, suspicious_markers)

        sev = severity
        sc = score
        if is_suspicious:
            sev = _bump_severity(sev)
            sc += score_boost

        alerts.append(Alert(
            rule_id="SOCF-005",
            severity=sev,
            title="Scheduled task created",
            timestamp=ts.isoformat().replace("+00:00", "Z"),
            details={
                "host": ev.get("host"),
                "actor": ev.get("actor"),
                "task_name": ev.get("task_name"),
                "task_command": ev.get("task_command"),
                "suspicious": is_suspicious,
                "message": ev.get("message"),
            },
            mitre=[{"tactic": "Persistence", "technique": "Scheduled Task/Job", "id": "T1053"}],
            score=sc,
        ))
    return alerts

def detect_suspicious_rdp_logon(events, logon_type=10, severity="medium", score=55):
    """
    Rule: Successful RDP logon (4624) with LogonType=10
    """
    alerts = []
    for ev in events:
        if ev.get("event_id") != 4624:
            continue

        # Prefer normalized field if present
        lt = ev.get("logon_type")
        try:
            lt = int(lt) if lt is not None else None
        except (TypeError, ValueError):
            lt = None

        if lt is None:
            lt = _extract_logon_type(ev.get("message", ""))

        if lt != logon_type:
            continue

        ts = parse_ts(ev["timestamp"])
        alerts.append(Alert(
            rule_id="SOCF-006",
            severity=severity,
            title="RDP logon detected (LogonType 10)",
            timestamp=ts.isoformat().replace("+00:00", "Z"),
            details={
                "username": ev.get("username"),
                "ip": ev.get("ip"),
                "host": ev.get("host"),
                "logon_type": lt,
                "message": ev.get("message"),
            },
            mitre=[{"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"}],
            score=score,
        ))
    return alerts

# ---------- Output ----------
def write_alerts(path: Path, alerts):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([asdict(a) for a in alerts], f, indent=2)

def print_summary(alerts):
    table = Table(title="SOC-Forge Alerts")
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Title")
    table.add_column("Time (UTC)")
    table.add_column("Key Detail")

    for a in alerts:
        key = ""
        if "ip" in a.details:
            key = f"ip={a.details.get('ip')}"
        elif "username" in a.details:
            key = f"user={a.details.get('username')}"
        table.add_row(a.severity, a.rule_id, a.title, a.timestamp, key)

    console.print(table)

def main():
    ap = argparse.ArgumentParser(prog="soc-forge", description="Mini SOC detection engine (Phase 1)")
    ap.add_argument("--input", required=True, help="Path to JSONL events file")
    ap.add_argument("--out", default=None, help="Output alerts.json path (overrides config)")
    ap.add_argument("--bf-threshold", type=int, default=None, help="Bruteforce threshold (overrides config)")
    ap.add_argument("--bf-window", type=int, default=None, help="Bruteforce window minutes (overrides config)")
    ap.add_argument("--config", default="config.yml", help="Path to YAML config (default: config.yml)")
    ap.add_argument("--html", default=None, help="Output HTML report path (overrides config)")
    ap.add_argument("--format", default="jsonl", choices=["jsonl", "windows-security-csv"], help="Input format")
    ap.add_argument("--write-events", default=None, help="Write normalized events to this JSON path")
    args = ap.parse_args()

    cfg = load_config(args.config)

    out_json = args.out or cfg.output.alerts_json
    out_html = args.html or cfg.output.report_html

    bf_threshold = args.bf_threshold if args.bf_threshold is not None else cfg.bruteforce.threshold
    bf_window = args.bf_window if args.bf_window is not None else cfg.bruteforce.window_minutes
    input_path = Path(args.input)

    if args.format == "jsonl":
        events = list(read_jsonl(input_path))
    elif args.format == "windows-security-csv":
        events = list(iter_windows_security_events(input_path))
    else:
        raise ValueError(f"Unsupported format: {args.format}")

    if args.write_events:
        out_events = Path(args.write_events)
        out_events.parent.mkdir(parents=True, exist_ok=True)
        with out_events.open("w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

    alerts = []
    alerts += detect_bruteforce(events, threshold=bf_threshold, window_minutes=bf_window, severity=cfg.bruteforce.severity, score=cfg.bruteforce.score)
    alerts += detect_account_lockout(events, severity=cfg.account_lockout.severity, score=cfg.account_lockout.score)
    alerts += detect_new_admin(events, severity=cfg.new_admin.severity, score=cfg.new_admin.score)
    alerts += detect_new_service_installed(
        events,
        severity=cfg.new_service_installed.severity,
        score=cfg.new_service_installed.score,
        suspicious_markers=cfg.new_service_installed.suspicious_markers,
        score_boost=cfg.new_service_installed.score_boost,
    )

    alerts += detect_scheduled_task_created(
        events,
        severity=cfg.scheduled_task_created.severity,
        score=cfg.scheduled_task_created.score,
        suspicious_markers=cfg.scheduled_task_created.suspicious_markers,
        score_boost=cfg.scheduled_task_created.score_boost,
    )

    alerts += detect_suspicious_rdp_logon(events, logon_type=cfg.suspicious_rdp_logon.logon_type, severity=cfg.suspicious_rdp_logon.severity, score=cfg.suspicious_rdp_logon.score,)

    alert_dicts = [asdict(a) for a in alerts]
    alert_dicts = correlate_alerts(
        alert_dicts,
        window_minutes=cfg.correlation.window_minutes,
        
        bruteforce_lockout_enabled=cfg.correlation.bruteforce_lockout_enabled,
        bruteforce_lockout_severity=cfg.correlation.bruteforce_lockout_severity,
        bruteforce_lockout_score=cfg.correlation.bruteforce_lockout_score,
        
        rdp_schtask_enabled=cfg.correlation.rdp_schtask_enabled,
        rdp_schtask_severity=cfg.correlation.rdp_schtask_severity,
        rdp_schtask_score=cfg.correlation.rdp_schtask_score,

        rdp_new_admin_enabled=cfg.correlation.rdp_new_admin_enabled,
        rdp_new_admin_severity=cfg.correlation.rdp_new_admin_severity,
        rdp_new_admin_score=cfg.correlation.rdp_new_admin_score,
        )

    out_path = Path(out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(alert_dicts, f, indent=2)

    html_path = Path(out_html)
    write_html_report(
        alerts=alert_dicts,
        output_path=html_path,
        input_name=str(input_path.name),
    )

    print_summary(alerts)

    console.print(f"\nSaved alerts to: [bold]{out_path}[/bold]")
    console.print(f"Saved HTML report to: [bold]{html_path}[/bold]")
    corr_count = sum(1 for a in alert_dicts if a.get("rule_id", "").startswith("SOCF_CORR"))
    console.print(f"[bold]Correlated alerts:[/bold] {corr_count}")
if __name__ == "__main__":
    main()
