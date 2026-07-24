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
from soc_forge.ingest.windows_evtx import load_windows_security_evtx_with_diagnostics
from soc_forge.ingest.windows_security_csv import load_windows_security_csv_with_diagnostics
from soc_forge.intelligence import attach_case_stories, build_risk_summary
from soc_forge.models import normalize_alerts
from soc_forge.reconstruct.engine import reconstruct_case
from soc_forge.cases.builder import build_cases
from soc_forge.report.html_report import write_html_report
from soc_forge.rules.coverage import mitre_coverage_by_tactic
from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.rules.legacy import detect_bruteforce

CANONICAL_EVTX_FORMAT = "windows-security-evtx"
EVTX_FORMAT_ALIASES = {"evtx", CANONICAL_EVTX_FORMAT}


@dataclass
class AnalysisOptions:
    events: List[Dict[str, Any]] | None = None
    input_name: str | None = None
    input_path: Path | None = None
    output_dir: Path = Path("out")
    config_path: str | Path = "config.yml"
    rule_paths: List[str] | None = None
    rules_only: bool = False
    write_outputs: bool = True
    write_report: bool = True
    events_path: Path | None = None
    input_format: str | None = None
    alerts_path: Path | None = None
    report_path: Path | None = None
    cases_output_dir: Path | None = None
    hunts_path: Path | None = None
    reconstructions_path: Path | None = None
    case_input_name: str | None = None
    brute_force_threshold: int | None = None
    brute_force_window_minutes: int | None = None
    ingest_diagnostics: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AnalysisResult:
    input_name: str
    input_path: Path | None
    output_dir: Path
    alerts_path: Path | None
    report_path: Path | None
    cases_output_dir: Path | None
    hunts_path: Path | None
    reconstructions_path: Path | None
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
    ingest_diagnostics: List[Dict[str, Any]] = field(default_factory=list)


def _correlation_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    corr_alerts = [a for a in alerts if str(a.get("rule_id") or "").startswith("SOCF-CORR")]
    return {
        "total": len(corr_alerts),
        "by_rule": sorted(Counter(a["rule_id"] for a in corr_alerts).items()),
    }


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


class InputLoadError(ValueError):
    def __init__(self, message: str, diagnostics: List[Dict[str, Any]] | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics or []


def _normalize_input_format(input_format: str | None) -> str | None:
    if input_format in EVTX_FORMAT_ALIASES:
        return CANONICAL_EVTX_FORMAT
    return input_format


def _detect_input_format(input_path: Path, input_format: str | None = None) -> str | None:
    detected_format = _normalize_input_format(input_format)
    if detected_format is None:
        suffix = input_path.suffix.lower()
        if suffix == ".csv":
            detected_format = "windows-security-csv"
        elif suffix == ".jsonl":
            detected_format = "jsonl"
        elif suffix == ".evtx":
            detected_format = CANONICAL_EVTX_FORMAT
    return detected_format


def load_events_with_diagnostics(path: str | Path, input_format: str | None = None) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    input_path = Path(path)
    detected_format = _detect_input_format(input_path, input_format)
    if detected_format == "windows-security-csv":
        result = load_windows_security_csv_with_diagnostics(input_path)
        return result.events, result.diagnostics_as_dicts()
    if detected_format == CANONICAL_EVTX_FORMAT:
        result = load_windows_security_evtx_with_diagnostics(input_path)
        if not result.events:
            raise InputLoadError("No normalized EVTX events were loaded", diagnostics=result.diagnostics)
        return result.events, result.diagnostics
    if detected_format == "jsonl":
        return _read_jsonl(input_path), []
    raise ValueError(f"Unsupported input format: {input_path.suffix}. Use .jsonl, .csv, or .evtx, or pass an explicit input_format.")


def load_events_from_path(path: str | Path, input_format: str | None = None) -> List[Dict[str, Any]]:
    events, _diagnostics = load_events_with_diagnostics(path, input_format=input_format)
    return events


def _dedupe_rule_paths(paths: List[str]) -> List[str]:
    seen = set()
    return [p for p in paths if not (p in seen or seen.add(p))]


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

    if result.cases_output_dir:
        export_cases_json(result.cases, result.cases_output_dir)
        artifacts["cases"] = result.cases_output_dir / "cases.json"

    if result.hunts_path:
        result.hunts_path.parent.mkdir(parents=True, exist_ok=True)
        result.hunts_path.write_text(json.dumps(result.hunt_findings, indent=2), encoding="utf-8")
        artifacts["hunts"] = result.hunts_path

    if result.reconstructions_path:
        result.reconstructions_path.parent.mkdir(parents=True, exist_ok=True)
        result.reconstructions_path.write_text(json.dumps(result.reconstructions, indent=2), encoding="utf-8")
        artifacts["reconstructions"] = result.reconstructions_path

    if result.events_path and result.input_path is not None:
        result.events_path.parent.mkdir(parents=True, exist_ok=True)
        result.events_path.write_text(json.dumps(result.events, indent=2), encoding="utf-8")
        artifacts["events"] = result.events_path


def run_analysis_for_events(options: AnalysisOptions) -> AnalysisResult:
    output_dir = Path(options.output_dir)
    alerts_path = Path(options.alerts_path) if options.alerts_path else output_dir / "alerts.json"
    report_path = Path(options.report_path) if options.report_path else output_dir / "report.html"
    cases_output_dir = Path(options.cases_output_dir) if options.cases_output_dir else output_dir
    hunts_path = Path(options.hunts_path) if options.hunts_path else output_dir / "hunts.json"
    reconstructions_path = Path(options.reconstructions_path) if options.reconstructions_path else output_dir / "reconstructions.json"
    events_path = Path(options.events_path) if options.events_path else None
    events = list(options.events or [])
    input_name = options.input_name or (Path(options.input_path).name if options.input_path else "")
    case_input_name = options.case_input_name or input_name

    cfg = load_config(str(options.config_path))
    rule_paths = _dedupe_rule_paths(options.rule_paths or ["soc_forge/rules"])
    rules = load_rules(rule_paths)
    yaml_alerts = run_rules(events, rules)

    legacy_alerts: List[Any] = []
    if not options.rules_only:
        legacy_alerts = detect_bruteforce(
            events,
            threshold=options.brute_force_threshold if options.brute_force_threshold is not None else cfg.bruteforce.threshold,
            window_minutes=options.brute_force_window_minutes if options.brute_force_window_minutes is not None else cfg.bruteforce.window_minutes,
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
    cases = attach_case_stories(build_cases(alert_dicts, case_input_name), hunt_findings)
    reconstructions = [_serialize_reconstruction(case) for case in cases]
    coverage_rows = mitre_coverage_by_tactic(rules, enabled_only=True)

    result = AnalysisResult(
        input_name=input_name,
        input_path=Path(options.input_path) if options.input_path else None,
        output_dir=output_dir,
        alerts_path=alerts_path if options.write_outputs else None,
        report_path=report_path if options.write_report else None,
        cases_output_dir=cases_output_dir if options.write_outputs else None,
        hunts_path=hunts_path if options.write_outputs else None,
        reconstructions_path=reconstructions_path if options.write_outputs else None,
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
        ingest_diagnostics=list(options.ingest_diagnostics),
    )

    if events_path and not (options.write_outputs and result.input_path is not None):
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


def run_analysis(options: AnalysisOptions) -> AnalysisResult:
    if options.events is not None:
        return run_analysis_for_events(options)
    if options.input_path is None:
        raise ValueError("AnalysisOptions requires events or input_path")

    input_path = Path(options.input_path)
    events, ingest_diagnostics = load_events_with_diagnostics(input_path, input_format=options.input_format)
    analysis_options = AnalysisOptions(
        events=events,
        input_name=options.input_name or input_path.name,
        input_path=input_path,
        output_dir=options.output_dir,
        config_path=options.config_path,
        rule_paths=options.rule_paths,
        rules_only=options.rules_only,
        write_outputs=options.write_outputs,
        write_report=options.write_report,
        events_path=options.events_path,
        input_format=options.input_format,
        alerts_path=options.alerts_path,
        report_path=options.report_path,
        cases_output_dir=options.cases_output_dir,
        hunts_path=options.hunts_path,
        reconstructions_path=options.reconstructions_path,
        case_input_name=options.case_input_name or str(input_path),
        brute_force_threshold=options.brute_force_threshold,
        brute_force_window_minutes=options.brute_force_window_minutes,
        ingest_diagnostics=ingest_diagnostics,
    )
    return run_analysis_for_events(analysis_options)


def run_analysis_for_file(input_path: str | Path, **kwargs: Any) -> AnalysisResult:
    return run_analysis(AnalysisOptions(input_path=Path(input_path), **kwargs))