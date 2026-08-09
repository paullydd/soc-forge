from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.models import (
    Annotation,
    Decision,
    EvidenceReference,
    Hypothesis,
    Investigation,
    WorkspaceMetadata,
)
from soc_forge.pipeline import AnalysisResult


def build_query_analysis(tmp_path: Path) -> AnalysisResult:
    event_one = {
        "record_id": "EVENT-001",
        "event_id": 4688,
        "timestamp": "2026-08-10T10:00:00-04:00",
        "host": "WS-LAB-01",
        "username": "DOMAIN\\alice",
        "src_ip": "10.0.0.5",
        "process_name": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "service_name": "WinDefend",
        "action": "Process creation",
        "command_line": "powershell.exe -enc sensitive",
    }
    event_two = {
        "record_id": "EVENT-002",
        "event_id": 4688,
        "timestamp": "2026-08-10T14:01:00Z",
        "host": "WS-UNRELATED",
        "username": "OTHER\\alice",
        "src_ip": "10.0.0.99",
        "process_name": "cmd.exe",
        "action": "Unrelated process",
    }
    alert_one = {
        "alert_id": "ALERT-001",
        "rule_id": "SOCF-021",
        "severity": "high",
        "title": "Security control tampering",
        "timestamp": "2026-08-10T14:00:00Z",
        "source_event_id": "EVENT-001",
        "details": {
            "host": "WS-LAB-01",
            "username": "DOMAIN\\alice",
            "ip": "10.0.0.5",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc sensitive",
        },
        "mitre": [{"id": "T1562.001", "tactic": "Defense Evasion"}],
    }
    alert_two = {
        "alert_id": "ALERT-002",
        "rule_id": "SOCF-020",
        "severity": "medium",
        "title": "Unrelated archive collection",
        "timestamp": "2026-08-10T14:01:00Z",
        "source_event_id": "EVENT-002",
        "details": {"host": "WS-UNRELATED", "username": "OTHER\\alice"},
        "mitre": [{"id": "T1560.001", "tactic": "Collection"}],
    }
    case_one = {
        "case_id": "CASE-001",
        "title": "Defense evasion investigation",
        "timestamp": "2026-08-10T14:00:00Z",
        "items": [deepcopy(alert_one)],
    }
    case_two = {
        "case_id": "CASE-002",
        "title": "Unrelated collection investigation",
        "items": [deepcopy(alert_two)],
    }
    reconstructions = [{
        "case_id": "CASE-001",
        "attack_path": [{
            "step_no": 1,
            "stage": "Defense Evasion",
            "title": "Disable security controls",
            "tactic": "Defense Evasion",
            "technique": "T1562.001",
            "timestamp": "2026-08-10T14:00:00Z",
            "entities": {"host": "WS-LAB-01"},
        }],
    }]
    artifacts = {
        "events": tmp_path / "events.json",
        "alerts": tmp_path / "alerts.json",
        "cases": tmp_path / "cases.json",
        "reconstructions": tmp_path / "reconstructions.json",
    }
    for path in artifacts.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("immutable-analysis-artifact", encoding="utf-8")
    return AnalysisResult(
        input_name="query-fixture.jsonl",
        input_path=tmp_path / "query-fixture.jsonl",
        output_dir=tmp_path,
        alerts_path=artifacts["alerts"],
        report_path=None,
        cases_output_dir=tmp_path,
        hunts_path=None,
        reconstructions_path=artifacts["reconstructions"],
        events_path=artifacts["events"],
        event_count=2,
        events=[event_one, event_two],
        alerts=[alert_one, alert_two],
        legacy_alerts=[],
        yaml_alerts=[alert_one, alert_two],
        correlations={"total": 0, "by_rule": []},
        hunt_findings=[],
        risk_summary={"level": "high"},
        cases=[case_one, case_two],
        reconstructions=reconstructions,
        mitre_coverage=[],
        artifacts=artifacts,
        ingest_diagnostics=[],
    )


def build_query_investigation(analysis, case_ids=("CASE-001",)) -> Investigation:
    catalog = AnalysisEvidenceCatalog()
    analysis_id = catalog.source_analysis_id(analysis)
    candidates = catalog.list_candidates(analysis, case_ids=("CASE-001",))
    alert = next(item for item in candidates if item.evidence_type == "alert")
    event = next(item for item in candidates if item.evidence_type == "event")
    reconstruction = next(
        item for item in candidates if item.evidence_type == "reconstruction_step"
    )
    references = [
        EvidenceReference(
            reference_id=f"SCOPE-{case_id}",
            source_type="case",
            source_id=case_id,
            case_id=case_id,
            origin="scope",
        )
        for case_id in case_ids
    ]
    selected = (
        EvidenceReference(
            reference_id=alert.evidence_id,
            source_type="alert",
            source_id=alert.source_id,
            origin="analyst_selection",
            classification="supporting",
            rationale="Supports defense-evasion hypothesis",
            selected_by="Analyst",
            selected_at="2026-08-10T14:05:00Z",
            source_analysis_id=analysis_id,
            evidence_type="alert",
            scope_case_ids=("CASE-001",),
        ),
        EvidenceReference(
            reference_id=event.evidence_id,
            source_type="event",
            source_id=event.source_id,
            origin="analyst_selection",
            classification="contradicting",
            rationale="Requires contradictory review",
            selected_by="Analyst",
            selected_at="2026-08-10T14:06:00Z",
            source_analysis_id=analysis_id,
            evidence_type="event",
            scope_case_ids=("CASE-001",),
        ),
        EvidenceReference(
            reference_id=reconstruction.evidence_id,
            source_type="reconstruction",
            source_id=reconstruction.source_id,
            origin="analyst_selection",
            classification="context",
            rationale="Provides sequence context",
            selected_by="Analyst",
            selected_at="2026-08-10T14:07:00Z",
            source_analysis_id=analysis_id,
            evidence_type="reconstruction_step",
            scope_case_ids=("CASE-001",),
        ),
    )
    hypothesis = Hypothesis(
        hypothesis_id="HYP-001",
        statement="Security controls were intentionally impaired",
        state="open",
        supporting_evidence_reference_ids=(alert.evidence_id,),
        contradicting_evidence_reference_ids=(event.evidence_id,),
        created_at="2026-08-10T14:08:00Z",
        updated_at="2026-08-10T14:10:00Z",
        author="Analyst",
    )
    decisions = (
        Decision(
            decision_id="DEC-ASSESS",
            decision_type="hypothesis_assessment",
            outcome="supported",
            rationale="Evidence supported the working hypothesis",
            evidence_reference_ids=(alert.evidence_id,),
            hypothesis_ids=("HYP-001",),
            decided_at="2026-08-10T14:09:00Z",
            decided_by="Analyst",
        ),
        Decision(
            decision_id="DEC-REOPEN",
            decision_type="hypothesis_assessment",
            outcome="reopened",
            rationale="Contradictory evidence requires review",
            evidence_reference_ids=(event.evidence_id,),
            hypothesis_ids=("HYP-001",),
            decided_at="2026-08-10T14:10:00Z",
            decided_by="Analyst",
        ),
        Decision(
            decision_id="DEC-GENERAL",
            decision_type="escalation",
            outcome="review",
            rationale="Senior review required",
            hypothesis_ids=("HYP-001",),
            decided_by="Analyst",
        ),
    )
    return Investigation(
        investigation_id="INV-QUERY",
        analysis_id=analysis_id,
        metadata=WorkspaceMetadata(
            title="Query investigation",
            created_at="2026-08-10T14:04:00Z",
            updated_at="2026-08-10T14:10:00Z",
            owner="Analyst",
            status="in_progress",
        ),
        analysis_artifact_keys=tuple(sorted(analysis.artifacts)),
        evidence_references=tuple(references) + selected,
        hypotheses=(hypothesis,),
        decisions=decisions,
        annotations=(
            Annotation(
                annotation_id="NOTE-001",
                target_type="investigation",
                target_id="INV-QUERY",
                body="Sensitive annotation body",
                created_at="2026-08-10T14:11:00Z",
                created_by="Analyst",
            ),
        ),
    )
