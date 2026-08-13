from __future__ import annotations

from typing import Callable

from soc_forge.investigations.summary import (
    InvestigationSummary,
    InvestigationSummaryService,
)
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.screen import begin_screen


class InvestigationSummaryConsoleController:
    """Terminal presentation for the shared read-only investigation summary."""

    def __init__(
        self,
        *,
        summary_service: InvestigationSummaryService,
        analysis_provider: Callable[[], object | None],
        evidence_controller: object,
        reasoning_controller: object,
        query_controller: object,
        handoff_controller: object,
        finding_controller: object | None = None,
        snapshot_loader: Callable[[WorkspaceResult], object | None],
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ) -> None:
        self.summary_service = summary_service
        self.analysis_provider = analysis_provider
        self.evidence_controller = evidence_controller
        self.reasoning_controller = reasoning_controller
        self.query_controller = query_controller
        self.handoff_controller = handoff_controller
        self.finding_controller = finding_controller
        self.snapshot_loader = snapshot_loader
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to continue..."))

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            summary = self.summary_service.summarize(
                current.investigation.investigation_id,
                self.analysis_provider(),
            )
            self.render(summary)
            self.output("")
            self.output("[1] Evidence Workspace")
            self.output("[2] Hypotheses and Decisions")
            self.output("[3] Timeline and Pivot Workbench")
            self.output("[4] Investigation Handoff")
            self.output("[5] Investigation Findings")
            self.output("[6] Load Source Analysis Snapshot")
            self.output("[0] Back")

            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self.evidence_controller.run(current)
            elif choice == "2":
                current = self.reasoning_controller.run(current)
            elif choice == "3":
                current = self.query_controller.run(current)
            elif choice == "4":
                current = self.handoff_controller.run(current)
            elif choice == "5" and self.finding_controller is not None:
                current = self.finding_controller.run(current)
            elif choice == "6":
                self.snapshot_loader(current)
                self.pause()
            else:
                self.output("Invalid option.")
                self.pause()

    def render(self, summary: InvestigationSummary) -> None:
        self.screen("INVESTIGATION SUMMARY")
        self.output(
            "Warning: terminal scrollback may retain investigation and "
            "analyst-authored content."
        )
        self.output("")
        self.output("INVESTIGATION")
        self.output(f"  Investigation ID : {summary.investigation_id}")
        self.output(f"  Title            : {summary.title}")
        self.output(f"  Owner            : {summary.owner or 'Unassigned'}")
        self.output(f"  Status           : {summary.status}")
        self.output(f"  Revision         : {summary.revision}")
        self.output(f"  Source analysis  : {summary.source_analysis_id}")
        self.output(f"  Summary mode     : {summary.mode.upper()}")
        self.output(
            "  Selected cases   : "
            + (", ".join(summary.selected_case_ids) or "None")
        )

        self.output("")
        self.output("ANALYST SUMMARY")
        self.output(summary.narrative)

        states = dict(summary.state.hypothesis_counts_by_state)
        self.output("")
        self.output("INVESTIGATION STATE")
        self.output(
            f"  Annotations: {summary.state.annotation_count} | "
            f"Evidence: {summary.state.selected_evidence_count} | "
            f"Decisions: {summary.state.decision_count}"
        )
        self.output(
            f"  Supporting: {summary.state.supporting_evidence_count} | "
            f"Contradicting: {summary.state.contradicting_evidence_count} | "
            f"Context: {summary.state.context_evidence_count}"
        )
        self.output(
            f"  Findings: {summary.finding_counts.total} | "
            f"Draft: {summary.finding_counts.draft} | "
            f"Substantiated: {summary.finding_counts.substantiated} | "
            f"Unsubstantiated: {summary.finding_counts.unsubstantiated} | "
            f"Inconclusive: {summary.finding_counts.inconclusive}"
        )
        self.output(
            f"  Hypotheses: {sum(states.values())} | "
            f"Open: {states.get('open', 0)} | "
            f"Supported: {states.get('supported', 0)} | "
            f"Rejected: {states.get('rejected', 0)} | "
            f"Inconclusive: {states.get('inconclusive', 0)}"
        )
        if summary.timeline is None:
            self.output("  Timed entries: Unavailable | Untimed entries: Unavailable")
        else:
            self.output(
                f"  Timed entries: {summary.timeline.timed_entry_count} | "
                f"Untimed entries: {summary.timeline.untimed_entry_count}"
            )

        self.output("")
        self.output("MACHINE-GENERATED DETECTION CONTEXT")
        if summary.mode == "offline":
            self.output(
                "Source analysis is not active. Detection and chronology details "
                "requiring the matching analysis are unavailable."
            )
        elif not summary.findings:
            self.output("No selected-case detection context is available.")
        else:
            for finding in summary.findings:
                self.output(f"  {finding.case_id} | {finding.title}")
                self.output(
                    "    Severity: "
                    + (", ".join(finding.severities) or "Unknown")
                )
                self.output(
                    "    Rule IDs: " + (", ".join(finding.rule_ids) or "None")
                )
                self.output(
                    "    ATT&CK tactics: "
                    + (", ".join(finding.attack_tactics) or "None")
                )
                self.output(
                    "    ATT&CK techniques: "
                    + (", ".join(finding.attack_techniques) or "None")
                )

        self.output("")
        self.output("ANALYST-SELECTED EVIDENCE")
        if not summary.evidence:
            self.output("No analyst-selected evidence.")
        for evidence in summary.evidence:
            sensitive = (
                "YES" if evidence.sensitive_content is True
                else "NO" if evidence.sensitive_content is False
                else "UNKNOWN"
            )
            self.output(
                f"  {evidence.evidence_id} | {evidence.evidence_type} | "
                f"{evidence.classification.upper()} | Sensitive: {sensitive}"
            )
            self.output(
                "    Related cases: "
                + (", ".join(evidence.related_case_ids) or "None")
            )
            self.output(f"    Rationale: {evidence.rationale_summary or 'None'}")

        self.output("")
        self.output("ANALYST HYPOTHESES")
        if not summary.hypotheses:
            self.output("No analyst hypotheses.")
        for hypothesis in summary.hypotheses:
            self.output(f"  {hypothesis.hypothesis_id} | {hypothesis.statement_summary}")
            self.output(f"    Analyst assessment: {hypothesis.state}")
            self.output(
                f"    Supporting evidence: {hypothesis.supporting_evidence_count} | "
                f"Contradicting evidence: {hypothesis.contradicting_evidence_count}"
            )
            if hypothesis.latest_assessment_outcome:
                self.output(
                    f"    Latest assessment: {hypothesis.latest_assessment_outcome} "
                    f"({hypothesis.latest_assessment_decision_id})"
                )

        self.output("")
        self.output("ANALYST DECISIONS")
        if not summary.decisions:
            self.output("No analyst decisions.")
        for decision in summary.decisions:
            self.output(
                f"  {decision.decision_id} | {decision.decision_type} | "
                f"{decision.outcome}"
            )
            self.output(
                f"    Author: {decision.author or 'Unknown'} | "
                f"Timestamp: {decision.timestamp or 'Unknown'}"
            )
            self.output(f"    Rationale: {decision.rationale_summary or 'None'}")
            self.output(
                f"    Hypotheses: {len(decision.hypothesis_ids)} | "
                f"Evidence: {len(decision.evidence_reference_ids)}"
            )

        self.output("")
        self.output("ANALYST FINDINGS")
        self.output("Findings are analyst-authored conclusions.")
        self.output("Confidence reflects analyst assessment, not machine certainty.")
        if not summary.analyst_findings:
            self.output("No analyst-authored findings.")
        for finding in summary.analyst_findings:
            self.output(
                f"  {finding.finding_id} | {finding.title} | "
                f"{finding.status.upper()} | {finding.confidence.upper()}"
            )
            self.output(f"    Analyst: {finding.author}")
            self.output(f"    Conclusion: {finding.conclusion}")
            self.output(
                f"    Basis: {finding.evidence_count} evidence | "
                f"{finding.hypothesis_count} hypotheses | "
                f"{finding.decision_count} decisions"
            )
            if finding.attack_tactics or finding.attack_techniques:
                self.output(
                    "    ATT&CK: "
                    + ", ".join(
                        finding.attack_tactics + finding.attack_techniques
                    )
                )
            for limitation in finding.limitations:
                self.output(f"    Limitation: {limitation}")

        self.output("")
        self.output("TIMELINE SUMMARY")
        if summary.timeline is None:
            self.output("Chronology requires the matching source analysis.")
        else:
            self.output(
                f"  First timed activity: "
                f"{summary.timeline.first_timed_activity or 'None'}"
            )
            self.output(
                f"  Last timed activity : "
                f"{summary.timeline.last_timed_activity or 'None'}"
            )
            for milestone in summary.timeline.milestones:
                self.output(
                    f"  {milestone.timestamp} | {milestone.entry_type} | "
                    f"{milestone.title}"
                )

        if summary.limitations:
            self.output("")
            self.output("LIMITATIONS")
            for limitation in summary.limitations:
                self.output(f"  - {limitation}")
