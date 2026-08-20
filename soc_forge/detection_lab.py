from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from soc_forge.pipeline import AnalysisOptions, AnalysisResult, run_analysis
from soc_forge.simulator.attack_simulator import (
    SCENARIO_GENERATORS,
    generate_scenario,
    write_events_jsonl,
)


@dataclass(frozen=True)
class DetectionLabResult:
    run_type: str
    source: str
    scenario: str
    rules_only: bool
    event_count: int
    rule_count: int
    triggered_rule_count: int
    triggered_rules: tuple[tuple[str, str], ...]
    alert_count: int
    case_count: int
    correlation_count: int
    hunt_count: int
    reconstruction_count: int
    attack_tactics: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    artifacts: tuple[tuple[str, str], ...]
    warnings: tuple[str, ...]


class DetectionLabService:
    """Controlled execution facade over the production analysis pipeline."""

    def __init__(
        self,
        *,
        output_dir: Path | str = Path("out"),
        analysis_runner: Callable[[AnalysisOptions], AnalysisResult] = run_analysis,
        scenario_generator: Callable[[str], list[dict]] = generate_scenario,
        event_writer: Callable[[list[dict], Path], Path] = write_events_jsonl,
    ):
        self.output_dir = Path(output_dir)
        self.analysis_runner = analysis_runner
        self.scenario_generator = scenario_generator
        self.event_writer = event_writer

    @property
    def scenarios(self) -> tuple[str, ...]:
        return tuple(SCENARIO_GENERATORS)

    def analyze_telemetry(
        self, input_path: str | Path, *, write_report: bool
    ) -> DetectionLabResult:
        path = Path(input_path)
        result = self.analysis_runner(
            AnalysisOptions(
                input_path=path,
                output_dir=self.output_dir,
                report_path=(
                    self.output_dir / "report.html" if write_report else None
                ),
                write_report=write_report,
            )
        )
        return self.project(
            result,
            run_type="Telemetry Analysis",
            source=str(path),
        )

    def run_simulation(self, scenario: str) -> DetectionLabResult:
        if scenario not in SCENARIO_GENERATORS:
            raise ValueError(f"Unsupported simulation scenario: {scenario}")
        events = self.scenario_generator(scenario)
        events_path = self.event_writer(
            events, self.output_dir / f"{scenario}_events.jsonl"
        )
        result = self.analysis_runner(
            AnalysisOptions(
                input_path=events_path,
                output_dir=self.output_dir,
                report_path=self.output_dir / f"{scenario}_report.html",
                write_report=True,
            )
        )
        return self.project(
            result,
            run_type="Attack Simulation",
            source=str(events_path),
            scenario=scenario,
        )

    def evaluate_rules_only(
        self, input_path: str | Path
    ) -> DetectionLabResult:
        path = Path(input_path)
        result = self.analysis_runner(
            AnalysisOptions(
                input_path=path,
                output_dir=self.output_dir,
                rules_only=True,
            )
        )
        return self.project(
            result,
            run_type="Rules Only",
            source=str(path),
            rules_only=True,
        )

    @staticmethod
    def project(
        result: AnalysisResult,
        *,
        run_type: str,
        source: str,
        scenario: str = "",
        rules_only: bool = False,
    ) -> DetectionLabResult:
        triggered = {
            (
                str(alert.get("rule_id", "") or ""),
                str(alert.get("title", "") or ""),
            )
            for alert in result.yaml_alerts
            if str(alert.get("rule_id", "") or "")
        }
        tactics = set()
        techniques = set()
        for alert in result.yaml_alerts:
            for mapping in alert.get("mitre", ()) or ():
                if not isinstance(mapping, dict):
                    continue
                tactic = str(mapping.get("tactic", "") or "").strip()
                technique_id = str(
                    mapping.get(
                        "technique_id", mapping.get("id", "")
                    )
                    or ""
                ).strip()
                technique = str(mapping.get("technique", "") or "").strip()
                if tactic:
                    tactics.add(tactic)
                rendered = " - ".join(
                    value for value in (technique_id, technique) if value
                )
                if rendered:
                    techniques.add(rendered)
        warnings = tuple(
            sorted(
                {
                    str(item.get("message", "") or "").strip()
                    for item in result.ingest_diagnostics
                    if str(item.get("message", "") or "").strip()
                }
            )
        )
        return DetectionLabResult(
            run_type=run_type,
            source=source,
            scenario=scenario,
            rules_only=rules_only,
            event_count=result.event_count,
            rule_count=result.rule_count,
            triggered_rule_count=len(triggered),
            triggered_rules=tuple(sorted(triggered)),
            alert_count=len(result.alerts),
            case_count=len(result.cases),
            correlation_count=int(result.correlations.get("total", 0) or 0),
            hunt_count=len(result.hunt_findings),
            reconstruction_count=len(result.reconstructions),
            attack_tactics=tuple(sorted(tactics)),
            attack_techniques=tuple(sorted(techniques)),
            artifacts=tuple(
                sorted(
                    (str(name), str(path))
                    for name, path in result.artifacts.items()
                )
            ),
            warnings=warnings,
        )
