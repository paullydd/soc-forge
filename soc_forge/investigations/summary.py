"""Deterministic read-only summaries of durable investigations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Tuple

from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.models import Investigation
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.query_models import InvestigationQueryError
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import InvestigationWorkspaceService



SUMMARY_SCHEMA_VERSION = "1.0"
SUMMARY_TEXT_LIMIT = 160
SUMMARY_NARRATIVE_LIMIT = 640
SUMMARY_MILESTONE_LIMIT = 6
ATTRIBUTION_MACHINE = "machine"
ATTRIBUTION_ANALYST = "analyst"


def _bounded(value: object, limit: int = SUMMARY_TEXT_LIMIT) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


@dataclass(frozen=True)
class InvestigationFindingSummary:
    case_id: str
    title: str
    rule_ids: Tuple[str, ...] = ()
    severities: Tuple[str, ...] = ()
    attack_tactics: Tuple[str, ...] = ()
    attack_techniques: Tuple[str, ...] = ()
    attribution: str = ATTRIBUTION_MACHINE


@dataclass(frozen=True)
class InvestigationEvidenceSummary:
    evidence_id: str
    evidence_type: str
    classification: str
    rationale_summary: str
    related_case_ids: Tuple[str, ...]
    source_id: str
    sensitive_content: bool | None
    attribution: str = ATTRIBUTION_ANALYST


@dataclass(frozen=True)
class InvestigationReasoningSummary:
    hypothesis_id: str
    statement_summary: str
    state: str
    supporting_evidence_count: int
    contradicting_evidence_count: int
    latest_assessment_decision_id: str | None = None
    latest_assessment_outcome: str | None = None
    attribution: str = ATTRIBUTION_ANALYST


@dataclass(frozen=True)
class InvestigationDecisionSummary:
    decision_id: str
    decision_type: str
    outcome: str
    rationale_summary: str
    author: str | None
    timestamp: str | None
    hypothesis_ids: Tuple[str, ...]
    evidence_reference_ids: Tuple[str, ...]
    attribution: str = ATTRIBUTION_ANALYST


@dataclass(frozen=True)
class InvestigationTimelineMilestone:
    entry_id: str
    timestamp: str
    entry_type: str
    title: str
    context_kind: str


@dataclass(frozen=True)
class InvestigationTimelineSummary:
    first_timed_activity: str | None
    last_timed_activity: str | None
    timed_entry_count: int
    untimed_entry_count: int
    milestones: Tuple[InvestigationTimelineMilestone, ...] = ()


@dataclass(frozen=True)
class InvestigationStateSummary:
    annotation_count: int
    selected_evidence_count: int
    supporting_evidence_count: int
    contradicting_evidence_count: int
    context_evidence_count: int
    hypothesis_counts_by_state: Tuple[Tuple[str, int], ...]
    decision_count: int


@dataclass(frozen=True)
class InvestigationSummary:
    investigation_id: str
    title: str
    owner: str | None
    status: str
    revision: int
    source_analysis_id: str
    selected_case_ids: Tuple[str, ...]
    mode: str
    narrative: str
    state: InvestigationStateSummary
    findings: Tuple[InvestigationFindingSummary, ...] = ()
    evidence: Tuple[InvestigationEvidenceSummary, ...] = ()
    hypotheses: Tuple[InvestigationReasoningSummary, ...] = ()
    decisions: Tuple[InvestigationDecisionSummary, ...] = ()
    timeline: InvestigationTimelineSummary | None = None
    limitations: Tuple[str, ...] = ()
    contains_sensitive_content: bool = True
    schema_version: str = SUMMARY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.mode not in {"full", "offline"}:
            raise ValueError("InvestigationSummary.mode must be 'full' or 'offline'")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InvestigationSummaryService:
    """Build an immutable summary without changing analysis or workspace state."""

    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        evidence_catalog: AnalysisEvidenceCatalog | None = None,
        timeline_service: InvestigationTimelineService | None = None,
    ) -> None:
        self.workspace_service = workspace_service
        self.evidence_catalog = evidence_catalog or AnalysisEvidenceCatalog()
        self.timeline_service = timeline_service or InvestigationTimelineService()

    def summarize(
        self,
        investigation_id: str,
        analysis: object | None = None,
    ) -> InvestigationSummary:
        current = self.workspace_service.get_investigation(investigation_id)
        investigation = current.investigation
        context = None
        limitations = []
        if analysis is None:
            limitations.append(
                "Source analysis is unavailable; machine context is omitted."
            )
        else:
            try:
                context = InvestigationQueryContext(
                    analysis,
                    investigation,
                    evidence_catalog=self.evidence_catalog,
                )
            except InvestigationQueryError:
                limitations.append(
                    "The supplied source analysis could not be validated for this "
                    "investigation; machine context is omitted."
                )

        selected_case_ids = self._selected_case_ids(investigation)
        evidence = self._evidence_summaries(
            investigation, analysis if context is not None else None
        )
        hypotheses = self._hypothesis_summaries(investigation)
        decisions = self._decision_summaries(investigation)
        findings = (
            self._findings(analysis, selected_case_ids, context)
            if context is not None and analysis is not None
            else ()
        )
        timeline = None
        if context is not None:
            projected = self.timeline_service.timeline(context)
            timeline = self._timeline_summary(projected)
            limitations.extend(projected.limitations)
        else:
            limitations.append(
                "Timeline, case, rule, ATT&CK, and source-evidence details require "
                "the matching completed analysis."
            )
        mode = "full" if context is not None else "offline"
        state = self._state_summary(investigation, evidence)
        return InvestigationSummary(
            investigation_id=investigation.investigation_id,
            title=investigation.metadata.title,
            owner=investigation.metadata.owner,
            status=investigation.metadata.status,
            revision=current.revision,
            source_analysis_id=investigation.analysis_id,
            selected_case_ids=selected_case_ids,
            mode=mode,
            narrative=self._narrative(
                investigation, mode, selected_case_ids, findings, evidence,
                hypotheses, decisions, timeline,
            ),
            state=state,
            findings=findings,
            evidence=evidence,
            hypotheses=hypotheses,
            decisions=decisions,
            timeline=timeline,
            limitations=tuple(dict.fromkeys(limitations)),
        )

    @staticmethod
    def _selected_case_ids(investigation: Investigation) -> Tuple[str, ...]:
        return tuple(sorted({
            item.source_id
            for item in investigation.evidence_references
            if item.origin == "scope" and item.source_type == "case"
        }))

    def _evidence_summaries(
        self,
        investigation: Investigation,
        analysis: object | None,
    ) -> Tuple[InvestigationEvidenceSummary, ...]:
        summaries = []
        for reference in investigation.evidence_references:
            if reference.origin != "analyst_selection":
                continue
            sensitive = None
            if analysis is not None:
                candidate = self.evidence_catalog.get_candidate(
                    analysis, reference.reference_id
                )
                sensitive = bool(candidate.sensitive_fields)
            summaries.append(InvestigationEvidenceSummary(
                evidence_id=reference.reference_id,
                evidence_type=reference.evidence_type or reference.source_type,
                classification=reference.classification or "context",
                rationale_summary=_bounded(reference.rationale),
                related_case_ids=tuple(sorted(reference.scope_case_ids)),
                source_id=reference.source_id,
                sensitive_content=sensitive,
            ))
        return tuple(sorted(summaries, key=lambda item: item.evidence_id))

    @staticmethod
    def _hypothesis_summaries(
        investigation: Investigation,
    ) -> Tuple[InvestigationReasoningSummary, ...]:
        summaries = []
        for hypothesis in investigation.hypotheses:
            assessments = sorted(
                (
                    decision for decision in investigation.decisions
                    if decision.decision_type == "hypothesis_assessment"
                    and hypothesis.hypothesis_id in decision.hypothesis_ids
                ),
                key=lambda item: (item.decided_at or "", item.decision_id),
            )
            latest = assessments[-1] if assessments else None
            summaries.append(InvestigationReasoningSummary(
                hypothesis_id=hypothesis.hypothesis_id,
                statement_summary=_bounded(hypothesis.statement),
                state=hypothesis.state,
                supporting_evidence_count=len(
                    hypothesis.supporting_evidence_reference_ids
                ),
                contradicting_evidence_count=len(
                    hypothesis.contradicting_evidence_reference_ids
                ),
                latest_assessment_decision_id=(
                    latest.decision_id if latest is not None else None
                ),
                latest_assessment_outcome=(
                    latest.outcome if latest is not None else None
                ),
            ))
        return tuple(sorted(summaries, key=lambda item: item.hypothesis_id))

    @staticmethod
    def _decision_summaries(
        investigation: Investigation,
    ) -> Tuple[InvestigationDecisionSummary, ...]:
        return tuple(sorted(
            (
                InvestigationDecisionSummary(
                    decision_id=item.decision_id,
                    decision_type=item.decision_type,
                    outcome=item.outcome,
                    rationale_summary=_bounded(item.rationale),
                    author=item.decided_by,
                    timestamp=item.decided_at,
                    hypothesis_ids=tuple(sorted(item.hypothesis_ids)),
                    evidence_reference_ids=tuple(
                        sorted(item.evidence_reference_ids)
                    ),
                )
                for item in investigation.decisions
            ),
            key=lambda item: (item.timestamp or "", item.decision_id),
        ))

    @staticmethod
    def _state_summary(
        investigation: Investigation,
        evidence: Tuple[InvestigationEvidenceSummary, ...],
    ) -> InvestigationStateSummary:
        counts = {
            name: sum(item.classification == name for item in evidence)
            for name in ("supporting", "contradicting", "context")
        }
        states = sorted({item.state for item in investigation.hypotheses})
        return InvestigationStateSummary(
            annotation_count=len(investigation.annotations),
            selected_evidence_count=len(evidence),
            supporting_evidence_count=counts["supporting"],
            contradicting_evidence_count=counts["contradicting"],
            context_evidence_count=counts["context"],
            hypothesis_counts_by_state=tuple(
                (state, sum(item.state == state for item in investigation.hypotheses))
                for state in states
            ),
            decision_count=len(investigation.decisions),
        )

    @staticmethod
    def _case_id(case: Mapping[str, Any]) -> str:
        header = case.get("header")
        return str(
            case.get("case_id")
            or (header.get("case_id") if isinstance(header, Mapping) else "")
            or ""
        ).strip()

    @classmethod
    def _findings(
        cls,
        analysis: object,
        selected_case_ids: Tuple[str, ...],
        context: InvestigationQueryContext,
    ) -> Tuple[InvestigationFindingSummary, ...]:
        case_by_id = {
            cls._case_id(case): case
            for case in analysis.cases
            if isinstance(case, Mapping) and cls._case_id(case)
        }
        findings = []
        for case_id in selected_case_ids:
            case = case_by_id.get(case_id, {})
            sources = tuple(
                source for source in context.scoped_sources
                if case_id in source.candidate.case_ids
            )
            findings.append(InvestigationFindingSummary(
                case_id=case_id,
                title=_bounded(case.get("title") or case_id),
                rule_ids=tuple(sorted({
                    source.candidate.rule_id for source in sources
                    if source.candidate.rule_id
                })),
                severities=tuple(sorted({
                    source.field_values["severity"] for source in sources
                    if source.field_values.get("severity")
                })),
                attack_tactics=tuple(sorted({
                    source.candidate.tactic for source in sources
                    if source.candidate.tactic
                })),
                attack_techniques=tuple(sorted({
                    source.candidate.technique for source in sources
                    if source.candidate.technique
                })),
            ))
        return tuple(findings)

    @staticmethod
    def _timeline_summary(timeline) -> InvestigationTimelineSummary:
        entries = timeline.entries
        return InvestigationTimelineSummary(
            first_timed_activity=entries[0].timestamp if entries else None,
            last_timed_activity=entries[-1].timestamp if entries else None,
            timed_entry_count=len(entries),
            untimed_entry_count=len(timeline.untimed_entries),
            milestones=tuple(
                InvestigationTimelineMilestone(
                    entry_id=item.entry_id,
                    timestamp=item.timestamp or "",
                    entry_type=item.entry_type,
                    title=_bounded(item.title),
                    context_kind=item.context_kind,
                )
                for item in entries[:SUMMARY_MILESTONE_LIMIT]
            ),
        )

    @staticmethod
    def _narrative(
        investigation: Investigation,
        mode: str,
        selected_case_ids: Tuple[str, ...],
        findings: Tuple[InvestigationFindingSummary, ...],
        evidence: Tuple[InvestigationEvidenceSummary, ...],
        hypotheses: Tuple[InvestigationReasoningSummary, ...],
        decisions: Tuple[InvestigationDecisionSummary, ...],
        timeline: InvestigationTimelineSummary | None,
    ) -> str:
        if mode == "offline":
            return _bounded(
                f"Source analysis is not active. This summary reflects persisted "
                f"analyst state only for investigation {investigation.investigation_id}: "
                f"{len(evidence)} selected evidence item(s), {len(hypotheses)} "
                f"hypothesis item(s), and {len(decisions)} decision(s).",
                SUMMARY_NARRATIVE_LIMIT,
            )
        case_text = ", ".join(
            f"{item.case_id} ({item.title})" for item in findings
        ) or ", ".join(selected_case_ids)
        assessments = ", ".join(
            f"{item.hypothesis_id} as {item.state}" for item in hypotheses
        )
        assessment_text = (
            f" Analyst assessment: {assessments}." if assessments else ""
        )
        timed = timeline.timed_entry_count if timeline is not None else 0
        return _bounded(
            f"Investigation {investigation.investigation_id} covers {case_text}. "
            f"It contains {len(evidence)} analyst-selected evidence item(s) and "
            f"{len(decisions)} analyst decision(s).{assessment_text} "
            f"{timed} timed investigation entry or entries are available.",
            SUMMARY_NARRATIVE_LIMIT,
        )
