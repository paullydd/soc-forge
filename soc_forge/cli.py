import argparse
import json
import re
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_forge.report.html_report import write_html_report
from soc_forge.correlate.rules import correlate_alerts
from soc_forge.config import load_config
from soc_forge import __version__
from soc_forge.ingest.windows_security_csv import load_windows_security_csv
from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.models import Alert
from soc_forge.hunts import findings_to_dicts, run_hunts
from soc_forge.intelligence.aggregator import build_risk_summary
from soc_forge.rules.coverage import mitre_coverage_by_tactic, format_coverage_table
from soc_forge.report.html_report import write_html_report, build_cases
from soc_forge.export.cases_export import export_cases_json
from soc_forge.reconstruct.engine import reconstruct_case
from soc_forge.simulator import generate_scenario, write_events_jsonl
from soc_forge.intelligence import attach_case_stories, build_risk_summary
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List

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


# ---------- Output ----------
def write_alerts(path: Path, alerts):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([asdict(a) for a in alerts], f, indent=2)

def _as_alert_dict(a: Any) -> Dict[str, Any]:
    """Accept Alert dataclass or dict and return a dict shape."""
    if isinstance(a, dict):
        return a
    if is_dataclass(a):
        return asdict(a)
    # last resort: try attribute access
    return {
        "severity": getattr(a, "severity", ""),
        "rule_id": getattr(a, "rule_id", ""),
        "title": getattr(a, "title", ""),
        "timestamp": getattr(a, "timestamp", ""),
        "details": getattr(a, "details", {}) or {},
    }

def print_summary(alerts: List[Any]) -> None:
    """
    Print a Rich table summary for alerts.
    Works for both:
      - Alert dataclass instances (legacy detectors)
      - dict alerts (YAML engine + correlation)
    """
    console = Console()

    table = Table(title="SOC-Forge Alerts", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Rule", style="cyan")
    table.add_column("Title")
    table.add_column("Time (UTC)")
    table.add_column("Key Detail")

    # Sort: severity then time (optional). Keep simple: by timestamp string.
    def _sort_key(a: Any):
        d = _as_alert_dict(a)
        return (str(d.get("severity", "")), str(d.get("timestamp", "")))

    for a in sorted(alerts, key=_sort_key):
        d = _as_alert_dict(a)
        details = d.get("details", {}) or {}

        key_detail = ""
        if isinstance(details, dict):
            if details.get("ip"):
                key_detail = f"ip={details.get('ip')}"
            elif details.get("host"):
                key_detail = f"host={details.get('host')}"
            elif details.get("username"):
                key_detail = f"username={details.get('username')}"

        table.add_row(
            str(d.get("severity", "")),
            str(d.get("rule_id", "")),
            str(d.get("title", "")),
            str(d.get("timestamp", "")),
            key_detail,
        )

    console.print(table)

def run_simulator(args) -> int:
    events = generate_scenario(args.simulate)
    output_path = write_events_jsonl(events, args.sim_output)
    print(f"[+] Generated {len(events)} events for scenario: {args.simulate}")
    print(f"[+] Wrote simulated events to: {output_path}")
    return 0

def main():
    ap = argparse.ArgumentParser(prog="soc-forge", description="SOC-Forge detection engine with attack simulation")
    ap.add_argument("--version", action="version", version=f"soc-forge {__version__}")
    ap.add_argument("--input", required=False, help="Path to JSONL events file")
    ap.add_argument("--out", default=None, help="Output alerts.json path (overrides config)")
    ap.add_argument("--bf-threshold", type=int, default=None, help="Bruteforce threshold (overrides config)")
    ap.add_argument("--bf-window", type=int, default=None, help="Bruteforce window minutes (overrides config)")
    ap.add_argument("--config", default="config.yml", help="Path to YAML config (default: config.yml)")
    ap.add_argument("--html", default=None, help="Output HTML report path (overrides config)")
    ap.add_argument("--format", default="jsonl", choices=["jsonl", "windows-security-csv"], help="Input format")
    ap.add_argument("--write-events", default=None, help="Write normalized events to this JSON path")
    ap.add_argument("--rules", action="append", help="Rule file or directory (repeatable)")
    ap.add_argument("--rules-only", action="store_true", help="Run YAML rules only (skip built-in detectors)")
    ap.add_argument("--coverage", action="store_true", help="Print MITRE coverage for for loaded YAML rules and exit")
    ap.add_argument(
        "--simulate",
        default=None,
        choices=["brute_force", "password_spray"],
        help="Generate a simulated attack scenario and exit",
    )
    ap.add_argument(
        "--sim-output",
        default="out/simulated_events.jsonl",
        help="Output path for simulated JSONL events"
    )
    args = ap.parse_args()
    if not args.simulate and not args.input:
        ap.error("--input is required unless --simulate is used")

    if args.simulate:
        return run_simulator(args)

    cfg = load_config(args.config)

    out_json = args.out or cfg.output.alerts_json
    out_html = args.html or cfg.output.report_html

    bf_threshold = args.bf_threshold if args.bf_threshold is not None else cfg.bruteforce.threshold
    bf_window = args.bf_window if args.bf_window is not None else cfg.bruteforce.window_minutes
    
    input_path = Path(args.input)

    if input_path.suffix.lower() == ".csv":
        events = load_windows_security_csv(input_path)
    elif input_path.suffix.lower() == ".jsonl":
        events = []
        with input_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
    else:
        raise ValueError(f"Unsupported input format: {input_path.suffix}. Use .jsonl or .csv")

    # -----------------------------
    # Phase 4: YAML rules execution
    # -----------------------------
    rule_paths: list[str] = []

    rule_paths.append("soc_forge/rules")

    if args.rules:
        rule_paths.extend(args.rules)

    seen = set()
    rule_paths = [p for p in rule_paths if not (p in seen or seen.add(p))]

    rules = load_rules(rule_paths)
    yaml_alerts = run_rules(events, rules)
    coverage_rows = mitre_coverage_by_tactic(rules, enabled_only=True)

    if args.coverage:
        rows = mitre_coverage_by_tactic(rules, enabled_only=True)
        print(format_coverage_table(rows))
        return 0

    # -----------------------------
    # Legacy detectors
    # -----------------------------
    alerts: list[Alert] = []
    if not args.rules_only:
        alerts += detect_bruteforce(
            events,
            threshold=bf_threshold,
            window_minutes=bf_window,
            severity=cfg.bruteforce.severity,
            score=cfg.bruteforce.score,
        )

    # Merge legacy + YAML once
    alert_dicts = [asdict(a) for a in alerts] + yaml_alerts

    # Correlation
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

    corr_alerts = [a for a in alert_dicts if str(a.get("rule_id", "")).startswith("SOCF_CORR")]
    corr_counts = {}
    for a in corr_alerts:
        rid = a.get("rule_id", "SOCF_CORR_UNKNOWN")
        corr_counts[rid] = corr_counts.get(rid, 0) + 1

    corr_summary = {
        "total": len(corr_alerts),
        "by_rule": sorted(corr_counts.items(), key=lambda x: (-x[1], x[0])),
    }

    # Hunts
    hunt_findings = run_hunts(events)
    hunt_findings_json = findings_to_dicts(hunt_findings)

    if hunt_findings:
        print("\nHUNT RESULTS")
        print("------------")
        for h in hunt_findings:
            print(f"{h.title} [{h.severity}]")
            print(f"  {h.summary}")
    else:
        print("\nHUNT RESULTS")
        print("------------")
        print("No hunt findings.")

    # Risk summary
    risk_summary = build_risk_summary(
        alerts=alert_dicts,
        hunts=hunt_findings_json,
        correlations=corr_summary,
    )

    print("\nRISK SUMMARY")
    print("------------")
    print(f"Overall Risk: {risk_summary['level'].upper()} ({risk_summary['overall_score']})")
    print(f"Alerts: {risk_summary['alerts']}")
    print(f"Hunts: {risk_summary['hunts']}")
    print(f"Correlations: {risk_summary['correlations']}")    


    out_path = Path(out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(alert_dicts, f, indent=2)

    Path("out").mkdir(exist_ok=True)
    with open("out/hunts.json", "w", encoding="utf-8") as f:
        json.dump(hunt_findings_json, f, indent=2)

    html_path = Path(out_html)
    coverage_rows = mitre_coverage_by_tactic(rules, enabled_only=True)
   
    corr_alerts = [a for a in alert_dicts if str(a.get("rule_id", "")).startswith("SOCF-CORR")]
    corr_summary = {
        "total": len(corr_alerts),
        "by_rule": sorted(Counter(a["rule_id"] for a in corr_alerts).items()),
    }

    cases = build_cases(alert_dicts, str(input_path))
    cases = attach_case_stories(cases, hunt_findings_json)
    export_cases_json(cases, Path(html_path).parent)

    reconstructions = []

    for case in cases:
        header = case.get("header", {}) or {}
        items = case.get("items", []) or []

        reconstruction = reconstruct_case(header, items)

        reconstructions.append(
            {
                "case_id": reconstruction.case_id,
                "summary": reconstruction.summary,
                "confidence": reconstruction.confidence,
                "attack_path": [
                    {
                        "step_no": step.step_no,
                        "stage": step.stage,
                        "title": step.title,
                        "technique": step.technique,
                        "tactic": step.tactic,
                        "timestamp": step.timestamp,
                        "confidence": step.confidence,
                        "entities": step.entities,
                        "evidence": [
                            {
                                "kind": ev.kind,
                                "ref": ev.ref,
                                "timestamp": ev.timestamp,
                                "rule_id": ev.rule_id,
                                "event_id": ev.event_id,
                                "summary": ev.summary,
                            }
                            for ev in step.evidence
                        ],
                        "notes": step.notes,
                        "inferred": step.inferred,
                    }
                    for step in reconstruction.attack_path
                ],
                "relationships": [
                    {
                        "from_step": rel.from_step,
                        "to_step": rel.to_step,
                        "reason": rel.reason,
                        "weight": rel.weight,
                    }
                    for rel in reconstruction.relationships
                ],
                "key_entities": reconstruction.key_entities,
                "gaps": reconstruction.gaps,
                "assumptions": reconstruction.assumptions,
            }
        )

    recon_path = out_path.parent / "reconstructions.json"
    recon_path.write_text(json.dumps(reconstructions, indent=2), encoding="utf-8")


    write_html_report(
        alerts=alert_dicts,
        output_path=html_path,
        input_name=str(input_path.name),
        mitre_coverage=coverage_rows,
        corr_summary=corr_summary,
        reconstructions=reconstructions,
        hunt_findings=hunt_findings_json,
        risk_summary=risk_summary,
        cases=cases,
    )

    print_summary(alert_dicts)

    console.print(f"\nSaved alerts to: [bold]{out_path}[/bold]")
    console.print(f"Saved HTML report to: [bold]{html_path}[/bold]")
    corr_count = sum(1 for a in alert_dicts if str(a.get("rule_id", "")).startswith("SOCF_CORR"))
    console.print(f"[bold]Correlated alerts:[/bold] {corr_count}")
if __name__ == "__main__":
    main()
