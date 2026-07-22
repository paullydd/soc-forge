from __future__ import annotations

import argparse
import json
import mimetypes
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse

from soc_forge.rules.legacy import detect_bruteforce
from soc_forge.config import load_config
from soc_forge.correlate.rules import correlate_alerts
from soc_forge.export.cases_export import export_cases_json
from soc_forge.core.investigation_graph import build_investigation_graph, summarize_graph
from soc_forge.hunts import findings_to_dicts, run_hunts
from soc_forge.intelligence import attach_case_stories, build_risk_summary
from soc_forge.models import normalize_alerts
from soc_forge.reconstruct.engine import reconstruct_case
from soc_forge.report.html_report import build_cases, write_html_report
from soc_forge.rules.coverage import mitre_coverage_by_tactic
from soc_forge.rules.engine import load_rules, run_rules
from soc_forge.rules.quality import evaluate_rule_quality_from_paths
from soc_forge.simulator import generate_scenario, write_events_jsonl

DEFAULT_OUT_DIR = Path("out")
STATIC_DIR = Path(__file__).with_name("static")
WEB_SCENARIOS = {
    "attack_chain": "Attack Chain",
    "detection_lab": "Detection Lab",
}


def read_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def severity_rank(severity: Any) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(severity or "").lower(), 0)


def case_risk(case: Dict[str, Any]) -> int:
    try:
        return int(case.get("risk_score") or case.get("risk") or 0)
    except (TypeError, ValueError):
        return 0


def case_quality_score(case: Dict[str, Any]) -> int:
    quality = case.get("case_quality") if isinstance(case.get("case_quality"), dict) else {}
    try:
        return int(quality.get("quality_score") or 0)
    except (TypeError, ValueError):
        return 0


def collect_rule_counts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        rule_id = str(alert.get("rule_id") or "UNKNOWN")
        item = counts.setdefault(rule_id, {"rule_id": rule_id, "count": 0, "title": alert.get("title", "")})
        item["count"] += 1
    return sorted(counts.values(), key=lambda item: (-item["count"], item["rule_id"]))


def collect_tactic_counts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for alert in alerts:
        for mapping in alert.get("mitre", []) or []:
            if not isinstance(mapping, dict):
                continue
            tactic = str(mapping.get("tactic") or "").strip()
            if tactic:
                counts[tactic] = counts.get(tactic, 0) + 1
    return [{"tactic": tactic, "count": count} for tactic, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _score_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _category_score(name: str, score: int, detail: str) -> Dict[str, Any]:
    bounded = max(0, min(100, int(round(score))))
    return {"name": name, "score": bounded, "grade": _score_grade(bounded), "detail": detail}


def build_detection_scorecard(
    alerts: List[Dict[str, Any]],
    cases: List[Dict[str, Any]],
    hunts: List[Dict[str, Any]],
    out_dir: Path = DEFAULT_OUT_DIR,
    rule_paths: List[str] | None = None,
) -> Dict[str, Any]:
    paths = rule_paths or ["soc_forge/rules"]
    rules = load_rules(paths)
    enabled_rules = [rule for rule in rules if rule.enabled]
    quality = evaluate_rule_quality_from_paths(paths)

    mapped_rules = [rule for rule in enabled_rules if rule.mitre]
    techniques = sorted({str(mapping.get("id") or mapping.get("technique_id") or "") for rule in enabled_rules for mapping in rule.mitre if mapping})
    tactics = sorted({str(mapping.get("tactic") or "") for rule in enabled_rules for mapping in rule.mitre if str(mapping.get("tactic") or "").strip()})
    severities = Counter(rule.severity for rule in enabled_rules)
    correlation_alerts = [alert for alert in alerts if str(alert.get("rule_id") or "").startswith("SOCF-CORR")]
    context_rules = []
    for rule in enabled_rules:
        details = rule.emit.get("details") if isinstance(rule.emit, dict) else {}
        if not isinstance(details, dict):
            continue
        has_message = "message" in details
        has_context = any(field in details for field in {"host", "ip", "src_ip", "username", "actor", "target_user", "group", "group_name", "service_name", "task_name"})
        if has_message and has_context:
            context_rules.append(rule)

    metadata_score = 100 if quality.passed else max(0, 100 - len(quality.warnings) * 5 - len(quality.errors) * 20)
    mitre_score = 100 if not enabled_rules else len(mapped_rules) * 100 / len(enabled_rules)
    context_score = 100 if not enabled_rules else len(context_rules) * 100 / len(enabled_rules)
    correlation_score = min(100, len(correlation_alerts) * 25 + len([rule for rule in enabled_rules if "corr" in rule.id.lower()]) * 10)
    demo_score = 0
    demo_score += 30 if alerts else 0
    demo_score += 25 if cases else 0
    demo_score += 15 if hunts else 0
    demo_score += 15 if correlation_alerts else 0
    demo_score += 15 if (out_dir / "report.html").exists() else 0
    rule_depth_score = min(100, len(enabled_rules) * 5)

    categories = [
        _category_score("Rule Quality", metadata_score, f"{len(quality.errors)} errors, {len(quality.warnings)} warnings"),
        _category_score("MITRE Coverage", mitre_score, f"{len(tactics)} tactics, {len([t for t in techniques if t])} techniques"),
        _category_score("Evidence Context", context_score, f"{len(context_rules)} of {len(enabled_rules)} enabled rules emit analyst context"),
        _category_score("Correlation Depth", correlation_score, f"{len(correlation_alerts)} correlation alerts in current workspace"),
        _category_score("Demo Readiness", demo_score, f"{len(alerts)} alerts, {len(cases)} cases, {len(hunts)} hunts"),
        _category_score("Rule Inventory", rule_depth_score, f"{len(enabled_rules)} enabled rules"),
    ]
    overall = round(sum(item["score"] for item in categories) / len(categories)) if categories else 0

    return {
        "overall_score": overall,
        "grade": _score_grade(overall),
        "rule_count": len(rules),
        "enabled_rule_count": len(enabled_rules),
        "quality_gate": quality.passed,
        "finding_counts": {"errors": len(quality.errors), "warnings": len(quality.warnings)},
        "categories": categories,
        "coverage": {
            "tactic_count": len(tactics),
            "technique_count": len([t for t in techniques if t]),
            "tactics": tactics,
        },
        "severity_balance": [{"severity": severity, "count": count} for severity, count in sorted(severities.items())],
        "correlation_alert_count": len(correlation_alerts),
        "demo_signal_count": len(alerts) + len(cases) + len(hunts) + len(correlation_alerts),
    }


def attach_web_graphs(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            continue
        copy = dict(case)
        graph = build_investigation_graph(copy)
        copy["web_graph"] = {
            "nodes": graph.get("nodes", {}),
            "edges": graph.get("edges", []),
            "primary_path": graph.get("primary_path", []),
            "summary": summarize_graph(graph),
            "timeline_count": graph.get("timeline_count", 0),
            "alert_count": graph.get("alert_count", 0),
        }
        enriched.append(copy)
    return enriched


def load_workspace(out_dir: Path = DEFAULT_OUT_DIR) -> Dict[str, Any]:
    cases = read_json_file(out_dir / "cases.json", [])
    alerts = read_json_file(out_dir / "alerts.json", [])
    hunts = read_json_file(out_dir / "hunts.json", [])
    reconstructions = read_json_file(out_dir / "reconstructions.json", [])

    if not isinstance(cases, list):
        cases = []
    if not isinstance(alerts, list):
        alerts = []
    if not isinstance(hunts, list):
        hunts = []
    if not isinstance(reconstructions, list):
        reconstructions = []

    cases = attach_web_graphs(cases)
    cases = sorted(cases, key=lambda case: (-case_risk(case), str(case.get("case_id") or "")))
    alerts = sorted(alerts, key=lambda alert: (severity_rank(alert.get("severity")), str(alert.get("timestamp") or "")), reverse=True)

    return {
        "summary": build_summary(cases, alerts, hunts, reconstructions, out_dir),
        "detection_scorecard": build_detection_scorecard(alerts, cases, hunts, out_dir),
        "cases": cases,
        "alerts": alerts,
        "hunts": hunts,
        "reconstructions": reconstructions,
    }


def build_summary(
    cases: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    hunts: List[Dict[str, Any]],
    reconstructions: List[Dict[str, Any]],
    out_dir: Path = DEFAULT_OUT_DIR,
) -> Dict[str, Any]:
    correlated_alerts = [alert for alert in alerts if str(alert.get("rule_id") or "").startswith("SOCF-CORR")]
    top_case = max(cases, key=case_risk) if cases else None
    quality_scores = [case_quality_score(case) for case in cases if case_quality_score(case) > 0]

    return {
        "case_count": len(cases),
        "alert_count": len(alerts),
        "correlated_alert_count": len(correlated_alerts),
        "hunt_count": len(hunts),
        "reconstruction_count": len(reconstructions),
        "top_case_id": top_case.get("case_id") if top_case else None,
        "top_case_title": top_case.get("title") if top_case else None,
        "top_case_risk": case_risk(top_case) if top_case else 0,
        "average_case_quality": round(sum(quality_scores) / len(quality_scores), 1) if quality_scores else 0,
        "rule_counts": collect_rule_counts(alerts)[:8],
        "tactic_counts": collect_tactic_counts(alerts)[:8],
        "artifacts": {
            "report_html": (out_dir / "report.html").exists(),
            "cases_json": (out_dir / "cases.json").exists(),
            "alerts_json": (out_dir / "alerts.json").exists(),
        },
    }


def safe_artifact_path(out_dir: Path, requested: str) -> Path | None:
    allowed = {
        "report.html": out_dir / "report.html",
        "detection_lab_report.html": out_dir / "detection_lab_report.html",
        "cases.json": out_dir / "cases.json",
        "alerts.json": out_dir / "alerts.json",
        "hunts.json": out_dir / "hunts.json",
        "reconstructions.json": out_dir / "reconstructions.json",
    }
    return allowed.get(requested)


def run_demo_scenario(scenario: str, out_dir: Path = DEFAULT_OUT_DIR) -> Dict[str, Any]:
    if scenario not in WEB_SCENARIOS:
        raise ValueError(f"Unsupported scenario: {scenario}")

    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = load_config("config.yml")

    events = generate_scenario(scenario)
    events_path = write_events_jsonl(events, out_dir / f"{scenario}_events.jsonl")

    rules = load_rules(["soc_forge/rules"])
    yaml_alerts = run_rules(events, rules)
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

    corr_alerts = [a for a in alert_dicts if str(a.get("rule_id") or "").startswith("SOCF-CORR")]
    corr_summary = {
        "total": len(corr_alerts),
        "by_rule": sorted(Counter(a["rule_id"] for a in corr_alerts).items()),
    }

    hunt_findings = findings_to_dicts(run_hunts(events))
    risk_summary = build_risk_summary(alerts=alert_dicts, hunts=hunt_findings, correlations=corr_summary)
    cases = attach_case_stories(build_cases(alert_dicts, str(events_path)), hunt_findings)
    export_cases_json(cases, out_dir)

    reconstructions = []
    for case in cases:
        header = case.get("header", {}) or {}
        reconstruction = reconstruct_case(header, case.get("items", []) or [])
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

    (out_dir / "alerts.json").write_text(json.dumps(alert_dicts, indent=2), encoding="utf-8")
    (out_dir / "hunts.json").write_text(json.dumps(hunt_findings, indent=2), encoding="utf-8")
    (out_dir / "reconstructions.json").write_text(json.dumps(reconstructions, indent=2), encoding="utf-8")

    write_html_report(
        alerts=alert_dicts,
        output_path=out_dir / "report.html",
        input_name=events_path.name,
        mitre_coverage=mitre_coverage_by_tactic(rules, enabled_only=True),
        corr_summary=corr_summary,
        reconstructions=reconstructions,
        hunt_findings=hunt_findings,
        risk_summary=risk_summary,
        cases=cases,
    )

    workspace = load_workspace(out_dir)
    workspace["active_scenario"] = scenario
    workspace["scenario_label"] = WEB_SCENARIOS[scenario]
    workspace["generated_event_count"] = len(events)
    return workspace


class SocForgeWebHandler(BaseHTTPRequestHandler):
    out_dir = DEFAULT_OUT_DIR

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path: Path, content_type: str | None = None) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(404, "File not found")
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type or mimetypes.guess_type(str(path))[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        if STATIC_DIR in path.resolve().parents or path.resolve() == STATIC_DIR / "index.html":
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            return
        if parsed.path.startswith("/api/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/api/scenario":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
                payload = json.loads(raw_body or "{}")
                scenario = str(payload.get("scenario") or "")
                workspace = run_demo_scenario(scenario, self.out_dir)
            except ValueError as exc:
                self.send_json({"error": str(exc), "scenarios": WEB_SCENARIOS}, status=400)
                return
            except Exception as exc:
                self.send_json({"error": f"Unable to run scenario: {exc}"}, status=500)
                return

            self.send_json({"scenario": scenario, "workspace": workspace})
            return

        self.send_error(404, "Not found")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/" or path == "/index.html":
            self.send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return

        if path.startswith("/static/"):
            requested = path.removeprefix("/static/")
            if "/" in requested or ".." in requested:
                self.send_error(404, "File not found")
                return
            self.send_file(STATIC_DIR / requested)
            return

        workspace = load_workspace(self.out_dir)
        if path == "/api/summary":
            self.send_json(workspace["summary"])
            return
        if path == "/api/cases":
            self.send_json(workspace["cases"])
            return
        if path == "/api/alerts":
            self.send_json(workspace["alerts"])
            return
        if path == "/api/hunts":
            self.send_json(workspace["hunts"])
            return
        if path == "/api/detection-scorecard":
            self.send_json(workspace["detection_scorecard"])
            return
        if path == "/api/reconstructions":
            self.send_json(workspace["reconstructions"])
            return
        if path == "/api/workspace":
            self.send_json(workspace)
            return
        if path == "/api/scenarios":
            self.send_json([{"id": key, "label": value} for key, value in WEB_SCENARIOS.items()])
            return

        if path == "/artifact":
            name = parse_qs(parsed.query).get("file", [""])[0]
            artifact = safe_artifact_path(self.out_dir, name)
            if artifact is None:
                self.send_error(404, "Artifact not allowed")
                return
            self.send_file(artifact)
            return

        self.send_error(404, "Not found")


def make_server(host: str, port: int, out_dir: Path) -> ThreadingHTTPServer:
    class Handler(SocForgeWebHandler):
        pass

    Handler.out_dir = out_dir
    return ThreadingHTTPServer((host, port), Handler)


def main() -> int:
    parser = argparse.ArgumentParser(prog="soc-forge-web", description="Local SOC-Forge web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=8765, help="Port to bind")
    parser.add_argument("--out-dir", default="out", help="Directory containing SOC-Forge output artifacts")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    server = make_server(args.host, args.port, out_dir)
    print(f"SOC-Forge web UI running at http://{args.host}:{args.port}")
    print(f"Reading artifacts from: {out_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SOC-Forge web UI.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
