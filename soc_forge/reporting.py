from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from soc_forge.attack_activity import AttackActivityService
from soc_forge.investigations.operational_summary import OperationalSummaryService
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.threat_activity import ThreatActivityOverviewService

KNOWN_REPORT_NAMES = (
    "brute_force_report.html", "password_spray_report.html",
    "privilege_escalation_report.html", "report.html",
)


@dataclass(frozen=True)
class ReportArtifact:
    filename: str
    path: str
    report_type: str
    available: bool
    modified_at: str | None


@dataclass(frozen=True)
class InvestigationReport:
    investigation_id: str
    title: str
    status: str
    owner: str | None
    revision: int
    created_at: str
    updated_at: str
    mode: str
    active_findings: tuple
    historical_findings: tuple
    evidence_count: int
    evidence_classifications: tuple[tuple[str, int], ...]
    hypotheses: tuple
    decisions: tuple
    annotations: tuple
    response_actions: tuple
    attack_tactics: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    source_analysis_available: bool


@dataclass(frozen=True)
class ExecutiveSummary:
    mode: str
    investigation_count: int
    investigations_with_activity: int
    active_findings: int
    historical_findings: int
    open_response_actions: int
    attention_items: int
    investigations_represented_in_queue: int
    critical_attention: int
    high_attention: int
    medium_attention: int
    low_attention: int
    top_attention: object | None
    observed_attack_tactics: tuple
    observed_attack_techniques: tuple
    recent_analyst_activity: tuple
    machine_context_available: bool


class ReportCenterService:
    def __init__(self, output_root=Path("out")):
        self.output_root = Path(output_root)

    def list_reports(self):
        rows = []
        for name in KNOWN_REPORT_NAMES:
            path = self.output_root / name
            if not path.is_file():
                continue
            rows.append(ReportArtifact(
                name, str(path.resolve()), "Analysis HTML Report", True,
                datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                .isoformat().replace("+00:00", "Z"),
            ))
        return tuple(rows)


class InvestigationReportService:
    def __init__(self, repository: InvestigationRepository,
                 analysis_provider: Callable[[], object | None] = lambda: None):
        self.repository = repository
        self.analysis_provider = analysis_provider

    def list_investigations(self):
        return tuple(self.repository.list_investigations())

    def build(self, investigation_id):
        record = self.repository.load_record(investigation_id)
        inv = record.investigation
        active = tuple(row for row in inv.findings
                       if row.lifecycle_state == "active")
        historical = tuple(row for row in inv.findings
                           if row.lifecycle_state != "active")
        analysis_available = self.analysis_provider() is not None
        counts = {}
        for row in inv.evidence_references:
            key = row.classification or row.origin
            counts[key] = counts.get(key, 0) + 1
        return InvestigationReport(
            inv.investigation_id, inv.metadata.title, inv.metadata.status,
            inv.metadata.owner, record.revision, inv.metadata.created_at,
            inv.metadata.updated_at,
            "full" if analysis_available else "offline",
            active, historical, len(inv.evidence_references),
            tuple(sorted(counts.items())), inv.hypotheses, inv.decisions,
            inv.annotations, inv.response_actions,
            tuple(sorted({value for row in inv.findings
                          for value in row.attack_tactics})),
            tuple(sorted({value for row in inv.findings
                          for value in row.attack_techniques})),
            analysis_available,
        )


class ExecutiveSummaryService:
    def __init__(self, operational: OperationalSummaryService,
                 threat: ThreatActivityOverviewService,
                 attack: AttackActivityService):
        self.operational, self.threat, self.attack = operational, threat, attack

    def summarize(self):
        operations = self.operational.summarize()
        threat = self.threat.summarize()
        attack = self.attack.summarize()
        recent = tuple(row for row in threat.recent_activity
                       if row.origin == "analyst")[:5]
        return ExecutiveSummary(
            threat.mode, threat.investigation_count,
            threat.investigations_with_activity, threat.active_finding_count,
            threat.historical_finding_count, threat.open_response_action_count,
            operations.total_attention_items,
            operations.investigations_represented,
            operations.critical_count, operations.high_count,
            operations.medium_count, operations.low_count,
            operations.top_item, attack.tactics[:5], attack.techniques[:5],
            recent, threat.mode == "full",
        )
