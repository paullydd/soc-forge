import argparse
from pathlib import Path
from typing import Any, List

from soc_forge.config import load_config
from soc_forge.models import alert_to_dict
from soc_forge.pipeline import AnalysisOptions, run_analysis
from soc_forge import __version__
from soc_forge.rules.coverage import mitre_coverage_by_tactic, format_coverage_table
from soc_forge.rules.engine import load_rules
from soc_forge.rules.quality import evaluate_rule_quality_from_paths, format_rule_quality_report
from soc_forge.simulator import generate_scenario, write_events_jsonl

from rich.console import Console
from rich.table import Table

console = Console()

# ---------- Helpers ----------
def print_summary(alerts: List[Any]) -> None:
    """
    Print a Rich table summary for alerts.
    Works for both:
      - Alert dataclass instances (legacy detectors)
      - dict alerts (YAML engine + correlation)
    """
    table = Table(title="SOC-Forge Alerts", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Rule", style="cyan")
    table.add_column("Title")
    table.add_column("Time (UTC)")
    table.add_column("Key Detail")

    # Sort: severity then time (optional). Keep simple: by timestamp string.
    def _sort_key(a: Any):
        d = alert_to_dict(a)
        return (str(d.get("severity", "")), str(d.get("timestamp", "")))

    for a in sorted(alerts, key=_sort_key):
        d = alert_to_dict(a)
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
def print_ingest_diagnostics(diagnostics: List[dict[str, Any]]) -> None:
    if not diagnostics:
        return
    print("\nINGEST DIAGNOSTICS")
    print("------------------")
    for diagnostic in diagnostics[:10]:
        row = f" row={diagnostic['row']}" if diagnostic.get("row") is not None else ""
        field = f" field={diagnostic['field']}" if diagnostic.get("field") else ""
        print(f"{diagnostic.get('level', 'info').upper()}:{row}{field} {diagnostic.get('message', '')}")
    if len(diagnostics) > 10:
        print(f"... {len(diagnostics) - 10} more diagnostics")

def run_simulator(args) -> int:
    events = generate_scenario(args.simulate)
    output_path = write_events_jsonl(events, args.sim_output)
    print(f"[+] Generated {len(events)} events for scenario: {args.simulate}")
    print(f"[+] Wrote simulated events to: {output_path}")
    return 0

def main():
    ap = argparse.ArgumentParser(prog="soc-forge", description="SOC-Forge detection engine with attack simulation")
    ap.add_argument("--version", action="version", version=f"soc-forge {__version__}")
    ap.add_argument("--input", required=False, help="Path to events file (.jsonl or Windows Security .csv)")
    ap.add_argument("--out", default=None, help="Output alerts.json path (overrides config)")
    ap.add_argument("--bf-threshold", type=int, default=None, help="Bruteforce threshold (overrides config)")
    ap.add_argument("--bf-window", type=int, default=None, help="Bruteforce window minutes (overrides config)")
    ap.add_argument("--config", default="config.yml", help="Path to YAML config (default: config.yml)")
    ap.add_argument("--html", default=None, help="Output HTML report path (overrides config)")
    ap.add_argument("--format", default=None, choices=["jsonl", "windows-security-csv"], help="Input format override; defaults to auto-detect from file extension")
    ap.add_argument("--write-events", default=None, help="Write normalized loaded events to this JSON path during --input analysis")
    ap.add_argument("--rules", action="append", help="Rule file or directory (repeatable)")
    ap.add_argument("--rules-only", action="store_true", help="Run YAML rules only (skip built-in detectors)")
    ap.add_argument("--coverage", action="store_true", help="Print MITRE coverage for loaded YAML rules and exit")
    ap.add_argument("--rule-quality", action="store_true", help="Run rule quality checks for loaded YAML rules and exit")
    ap.add_argument(
        "--simulate",
        default=None,
        choices=["brute_force", "password_spray", "privilege_escalation", "mixed", "attack_chain", "detection_lab"],
        help="Generate a simulated attack scenario and exit",
    )
    ap.add_argument(
        "--sim-output",
        default="out/simulated_events.jsonl",
        help="Output path for simulated JSONL events"
    )
    args = ap.parse_args()
    if not args.input and not args.simulate and not args.coverage and not args.rule_quality:
        ap.error("--input is required unless --simulate, --coverage, or --rule-quality is used")

    if args.simulate:
        return run_simulator(args)

    if args.coverage:
        rule_paths = args.rules or ["soc_forge/rules"]
        rules = load_rules(rule_paths)
        rows = mitre_coverage_by_tactic(rules)
        print(format_coverage_table(rows))
        return 0

    if args.rule_quality:
        rule_paths = args.rules or ["soc_forge/rules"]
        load_rules(rule_paths)
        report = evaluate_rule_quality_from_paths(rule_paths)
        print(format_rule_quality_report(report))
        return 0 if report.passed else 1

    cfg = load_config(args.config)

    out_json = args.out or cfg.output.alerts_json
    out_html = args.html or cfg.output.report_html

    bf_threshold = args.bf_threshold if args.bf_threshold is not None else cfg.bruteforce.threshold
    bf_window = args.bf_window if args.bf_window is not None else cfg.bruteforce.window_minutes

    input_path = Path(args.input)
    rule_paths: list[str] = ["soc_forge/rules"]
    if args.rules:
        rule_paths.extend(args.rules)

    result = run_analysis(
        AnalysisOptions(
            input_path=input_path,
            input_name=input_path.name,
            output_dir=Path(out_html).parent,
            config_path=args.config,
            rule_paths=rule_paths,
            rules_only=args.rules_only,
            events_path=Path(args.write_events) if args.write_events else None,
            input_format=args.format,
            alerts_path=Path(out_json),
            report_path=Path(out_html),
            cases_output_dir=Path(out_html).parent,
            hunts_path=Path("out") / "hunts.json",
            reconstructions_path=Path(out_json).parent / "reconstructions.json",
            brute_force_threshold=bf_threshold,
            brute_force_window_minutes=bf_window,
        )
    )

    print_ingest_diagnostics(result.ingest_diagnostics)

    if result.hunt_findings:
        print("\nHUNT RESULTS")
        print("------------")
        for h in result.hunt_findings:
            print(f"{h.get('title')} [{h.get('severity')}]")
            print(f"  {h.get('summary')}")
    else:
        print("\nHUNT RESULTS")
        print("------------")
        print("No hunt findings.")

    print("\nRISK SUMMARY")
    print("------------")
    print(f"Overall Risk: {result.risk_summary['level'].upper()} ({result.risk_summary['overall_score']})")
    print(f"Alerts: {result.risk_summary['alerts']}")
    print(f"Hunts: {result.risk_summary['hunts']}")
    print(f"Correlations: {result.risk_summary['correlations']}")

    print_summary(result.alerts)

    console.print(f"\nSaved alerts to: [bold]{Path(out_json)}[/bold]")
    console.print(f"Saved HTML report to: [bold]{Path(out_html)}[/bold]")
    console.print(f"[bold]Correlated alerts:[/bold] {result.correlations['total']}")

if __name__ == "__main__":
    main()
