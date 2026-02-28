import argparse
import json
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_forge.report.html_report import write_html_report
from soc_forge.correlate.rules import correlate_alerts
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

# ---------- Detectors ----------
def detect_bruteforce(events, threshold=8, window_minutes=10):
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
                severity="high",
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
                score=40,
            ))
    return alerts

def detect_account_lockout(events):
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

def detect_new_admin(events):
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
    ap.add_argument("--out", default="out/alerts.json", help="Output alerts.json path")
    ap.add_argument("--bf-threshold", type=int, default=8)
    ap.add_argument("--bf-window", type=int, default=10)
    ap.add_argument("--html", default="out/report.html", help="Output HTML report path")    
    args = ap.parse_args()

    input_path = Path(args.input)
    events = list(read_jsonl(input_path))

    alerts = []
    alerts += detect_bruteforce(events, threshold=args.bf_threshold, window_minutes=args.bf_window)
    alerts += detect_account_lockout(events)
    alerts += detect_new_admin(events)

    alert_dicts = [asdict(a) for a in alerts]
    alert_dicts = correlate_alerts(alert_dicts, window_minutes=15)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        import json
        json.dump(alert_dicts, f, indent=2)
    write_alerts(out_path, alerts)
 
    html_path = Path(args.html)
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
