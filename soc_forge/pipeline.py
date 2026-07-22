from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from soc_forge.config import load_config
from soc_forge.correlate.rules import correlate_alerts
from soc_forge.export.cases_export import export_cases_json
from soc_forge.hunts import findings_to_dicts, run_hunts
from soc_forge.intelligence import attach_case_stories, build_risk_summary
from soc_forge.models import normalize_alerts
from soc_forge.reconstruct.engine import reconstruct_case
from soc_forge.report.html_report import build_cases, write_html_report
from soc_forge.rules.coverage import mitre_coverage_by_tactic
from soc_forge.rules.engine import load_rules
from soc_forge.rules.engine import run_rules
from soc_forge.rules.legacy import detect_bruteforce


@dataclass
class AnalysisOptions:
    events: List[Dict[str, Any]]
    input_name: str
    output_dir: Path = Path("out")
    config_path: str | Path = "config.yml"
    rule_paths: List[str] | None = None
    rules_only: bool = False
    write_outputs: bool = True
    write_report: bool = True
    events_path: Path | None = None
    alerts_path: Path | None = None
    report_path: Path | None = None


@dataclass
class AnalysisResult:
    input_name: str
    input_path: Path | None
    output_dir: Path
    alerts_path: Path | None
    report_path: Path | None
    events_path: Path | None
    event_count: int
    events: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    legacy_alerts: List[Any]
    yaml_alerts: List[Dict[str, Any]]
    correlations: Dict[str, Any]
    hunt_findings: List[Dict[str, Any]]
    risk_summary: Dict[str, Any]
    cases: List[Dict[str, Any]]
    reconstructions: List[Dict[str, Any]]
    mitre_coverage: List[Any]
    artifacts: Dict[str, Path] = field(default_factory=dict)


def _correlation_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    corr_alerts = [a for a in alerts if str(a.get("rule_id") or "").startswith("SOCF-CORR")]
    return {
        "total": len(corr_alerts),
        "by_rule": sorted(Counter(a["rule_id"] for a in corr_alerts).items()),
    }


def _serialize_reconstruction(case: Dict[str, Any]) -> Dict[str, Any]:
    header = case.get("header", {}) or {}
    reconstruction = reconstruct_case(header, case.get("items", []) or [])
    return {
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


def _write_outputs(result: AnalysisResult) -> None:
    result.output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = result.artifacts

    if result.alerts_path:
        result.alerts_path.parent.mkdir(parents=True, exist_ok=True)
        result.alerts_path.write_text(json.dumps(result.alerts, indent=2), encoding="utf-8")
        artifacts["alerts"] = result.alerts_path

    export_cases_json(result.cases, result.output_dir)
    artifacts["cases"] = result.output_dir / "cases.json"

    hunts_path = result.output_dir / "hunts.json"
    hunts_path.write_text(json.dumps(result.hunt_findings, indent=2), encoding="utf-8")
    artifacts["hunts"] = hunts_path

    recon_path = result.output_dir / "reconstructions.json"
    recon_path.write_text(json.dumps(result.reconstructions, indent=2), encoding="utf-8")
    artifacts["reconstructions"] = recon_path


def run_analysis_for_events(options: AnalysisOptions) -> AnalysisResult:
    output_dir = Path(options.output_dir)
    alerts_path = Path(options.alerts_path) if options.alerts_path else output_dir / "alerts.json"
    report_path = Path(options.report_path) if options.report_path else output_dir / "report.html"
    events_path = Path(options.events_path) if options.events_path else None
    events = list(options.events)

    cfg = load_config(str(options.config_path))
    rule_paths = options.rule_paths or ["soc_forge/rules"]
    rules = load_rules(rule_paths)
    yaml_alerts = run_rules(events, rules)

    legacy_alerts: List[Any] = []
    if not options.rules_only:
        legacy_alerts = detect_bruteforce(
            events,
            threshold=cfg.bruteforce.threshold,
            window_minutes=cfg.bruteforce.window_minutes,
            severity=cfg.bruteforce.severity,
            score=cfg.bruteforce.score,
        )

    alert_dicts = normalize_alerts(legacy_alerts) + normalize_alerts(yaml_alerts)
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

    corr_summary = _correlation_summary(alert_dicts)
    hunt_findings = findings_to_dicts(run_hunts(events))
    risk_summary = build_risk_summary(alerts=alert_dicts, hunts=hunt_findings, correlations=corr_summary)
    cases = attach_case_stories(build_cases(alert_dicts, options.input_name), hunt_findings)
    reconstructions = [_serialize_reconstruction(case) for case in cases]
    coverage_rows = mitre_coverage_by_tactic(rules, enabled_only=True)

    result = AnalysisResult(
        input_name=options.input_name,
        input_path=None,
        output_dir=output_dir,
        alerts_path=alerts_path if options.write_outputs else None,
        report_path=report_path if options.write_report else None,
        events_path=events_path,
        event_count=len(events),
        events=events,
        alerts=alert_dicts,
        legacy_alerts=legacy_alerts,
        yaml_alerts=yaml_alerts,
        correlations=corr_summary,
        hunt_findings=hunt_findings,
        risk_summary=risk_summary,
        cases=cases,
        reconstructions=reconstructions,
        mitre_coverage=coverage_rows,
        artifacts={},
    )

    if events_path:
        result.artifacts["events"] = events_path
    if options.write_outputs:
        _write_outputs(result)
    if options.write_report and result.report_path:
        result.report_path.parent.mkdir(parents=True, exist_ok=True)
        write_html_report(
            alerts=result.alerts,
            output_path=result.report_path,
            input_name=result.input_name,
            mitre_coverage=result.mitre_coverage,
            corr_summary=result.correlations,
            reconstructions=result.reconstructions,
            hunt_findings=result.hunt_findings,
            risk_summary=result.risk_summary,
            cases=result.cases,
        )
        result.artifacts["report"] = result.report_path

    return result
