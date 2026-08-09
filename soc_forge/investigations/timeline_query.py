from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timezone
from typing import Mapping, Tuple

from soc_forge.investigations.query_context import (
    InvestigationQueryContext,
    normalize_entity,
)
from soc_forge.investigations.query_models import (
    DecisionOverlay,
    HypothesisOverlay,
    InvalidTimelineRangeError,
    InvestigationTimeline,
    InvestigationTimelineEntry,
    InvestigationTimelineFilters,
    TIMELINE_ENTRY_TYPES,
    TIMELINE_FILTER_FIELDS,
    UnsupportedTimelineFilterError,
)


ENTRY_TYPE_PRECEDENCE = {
    entry_type: index
    for index, entry_type in enumerate(
        (
            "event",
            "alert",
            "case",
            "reconstruction_step",
            "analyst_evidence_selection",
            "hypothesis_created",
            "hypothesis_assessed",
            "hypothesis_reopened",
            "analyst_decision",
            "annotation",
        )
    )
}
MAX_TIMELINE_SUMMARY_LENGTH = 240


def normalize_timestamp(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    rendered = str(value).strip()
    if rendered.endswith("Z"):
        rendered = rendered[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(rendered)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z")


class InvestigationTimelineService:
    def timeline(
        self,
        context: InvestigationQueryContext,
        *,
        filters: InvestigationTimelineFilters | Mapping[str, object] | None = None,
    ) -> InvestigationTimeline:
        normalized_filters = self._filters(filters)
        entries = list(self._machine_entries(context))
        entries.extend(self._analyst_entries(context))
        entries = [entry for entry in entries if self._matches(entry, normalized_filters)]
        timed = tuple(sorted((item for item in entries if item.timestamp), key=self._sort_key))
        untimed = tuple(
            sorted(
                (item for item in entries if item.timestamp is None),
                key=lambda item: (
                    ENTRY_TYPE_PRECEDENCE[item.entry_type],
                    item.entry_id,
                ),
            )
        )
        limitations = ()
        if untimed:
            limitations = ("Entries without reliable timestamps are returned as untimed.",)
        return InvestigationTimeline(
            investigation_id=context.investigation.investigation_id,
            source_analysis_id=context.source_analysis_id,
            entries=timed,
            untimed_entries=untimed,
            applied_filters=normalized_filters,
            limitations=limitations,
        )

    def _machine_entries(
        self,
        context: InvestigationQueryContext,
    ) -> Tuple[InvestigationTimelineEntry, ...]:
        entries = []
        for source in context.scoped_sources:
            candidate = source.candidate
            selected = context.selected_reference(candidate.evidence_id)
            hypothesis_ids, decision_ids, hypothesis_overlays, decision_overlays = (
                self._reasoning_links(context, selected)
            )
            values = source.field_values
            entries.append(
                InvestigationTimelineEntry(
                    entry_id=f"{candidate.evidence_type}:{candidate.evidence_id}",
                    timestamp=normalize_timestamp(candidate.timestamp),
                    entry_type=candidate.evidence_type,
                    source_id=candidate.source_id,
                    source_analysis_id=context.source_analysis_id,
                    case_ids=candidate.case_ids,
                    title=candidate.title,
                    summary=self._bounded(candidate.summary),
                    context_kind="machine",
                    relationship_reason=candidate.relationship,
                    host=values.get("host"),
                    user=values.get("user"),
                    ip=values.get("source_ip"),
                    process=values.get("process"),
                    service=values.get("service"),
                    rule_id=candidate.rule_id,
                    severity=values.get("severity"),
                    attack_tactic=candidate.tactic,
                    attack_technique=candidate.technique,
                    evidence_id=candidate.evidence_id,
                    analyst_selected=selected is not None,
                    evidence_classification=(
                        selected.classification if selected is not None else None
                    ),
                    related_hypothesis_ids=hypothesis_ids,
                    related_decision_ids=decision_ids,
                    hypothesis_overlays=hypothesis_overlays,
                    decision_overlays=decision_overlays,
                    sensitive_fields=candidate.sensitive_fields,
                    provenance_fields=tuple(
                        sorted({item.field_name for item in candidate.field_provenance})
                    ),
                    limitations=(
                        (candidate.limitation_reason,)
                        if candidate.limitation_reason
                        else ()
                    ),
                )
            )
            if selected is not None:
                entries.append(
                    InvestigationTimelineEntry(
                        entry_id=f"selection:{selected.reference_id}",
                        timestamp=normalize_timestamp(selected.selected_at),
                        entry_type="analyst_evidence_selection",
                        source_id=selected.reference_id,
                        source_analysis_id=context.source_analysis_id,
                        case_ids=selected.scope_case_ids or candidate.case_ids,
                        title="Analyst evidence selection",
                        summary=(
                            f"{selected.classification} evidence; rationale available"
                        ),
                        context_kind="analyst",
                        relationship_reason="analyst evidence selection",
                        evidence_id=selected.reference_id,
                        analyst_selected=True,
                        evidence_classification=selected.classification,
                        related_hypothesis_ids=hypothesis_ids,
                        related_decision_ids=decision_ids,
                        hypothesis_overlays=hypothesis_overlays,
                        decision_overlays=decision_overlays,
                    )
                )
        return tuple(entries)

    def _analyst_entries(
        self,
        context: InvestigationQueryContext,
    ) -> Tuple[InvestigationTimelineEntry, ...]:
        entries = []
        for hypothesis in context.hypotheses:
            entries.append(
                InvestigationTimelineEntry(
                    entry_id=f"hypothesis-created:{hypothesis.hypothesis_id}",
                    timestamp=normalize_timestamp(hypothesis.created_at),
                    entry_type="hypothesis_created",
                    source_id=hypothesis.hypothesis_id,
                    source_analysis_id=context.source_analysis_id,
                    case_ids=context.selected_case_ids,
                    title="Analyst hypothesis created",
                    summary=self._bounded(hypothesis.statement),
                    context_kind="analyst",
                    relationship_reason="investigation hypothesis",
                    related_hypothesis_ids=(hypothesis.hypothesis_id,),
                    hypothesis_overlays=(
                        HypothesisOverlay(
                            hypothesis.hypothesis_id,
                            "investigation hypothesis",
                            hypothesis.state,
                        ),
                    ),
                )
            )
        for decision in context.decisions:
            if decision.decision_type == "hypothesis_assessment":
                entry_type = (
                    "hypothesis_reopened"
                    if decision.outcome == "reopened"
                    else "hypothesis_assessed"
                )
                title = (
                    "Hypothesis reopened"
                    if decision.outcome == "reopened"
                    else "Hypothesis assessed"
                )
            else:
                entry_type = "analyst_decision"
                title = "Analyst decision recorded"
            entries.append(
                InvestigationTimelineEntry(
                    entry_id=f"decision:{decision.decision_id}",
                    timestamp=normalize_timestamp(decision.decided_at),
                    entry_type=entry_type,
                    source_id=decision.decision_id,
                    source_analysis_id=context.source_analysis_id,
                    case_ids=context.selected_case_ids,
                    title=title,
                    summary=f"{decision.decision_type}: {decision.outcome}",
                    context_kind="analyst",
                    relationship_reason="investigation decision",
                    evidence_id=(
                        decision.evidence_reference_ids[0]
                        if len(decision.evidence_reference_ids) == 1
                        else None
                    ),
                    related_hypothesis_ids=decision.hypothesis_ids,
                    related_decision_ids=(decision.decision_id,),
                    decision_overlays=(
                        DecisionOverlay(decision.decision_id, decision.decision_type),
                    ),
                )
            )
        for annotation in context.investigation.annotations:
            entries.append(
                InvestigationTimelineEntry(
                    entry_id=f"annotation:{annotation.annotation_id}",
                    timestamp=normalize_timestamp(annotation.created_at),
                    entry_type="annotation",
                    source_id=annotation.annotation_id,
                    source_analysis_id=context.source_analysis_id,
                    case_ids=context.selected_case_ids,
                    title="Analyst annotation",
                    summary="Annotation content available through workspace detail",
                    context_kind="analyst",
                    relationship_reason=f"annotation target: {annotation.target_type}",
                )
            )
        return tuple(entries)

    @staticmethod
    def _reasoning_links(context, selected):
        if selected is None:
            return (), (), (), ()
        reference_id = selected.reference_id
        hypothesis_overlays = tuple(
            sorted(
                (
                    HypothesisOverlay(
                        hypothesis.hypothesis_id,
                        (
                            "supporting"
                            if reference_id
                            in hypothesis.supporting_evidence_reference_ids
                            else "contradicting"
                        ),
                        hypothesis.state,
                    )
                    for hypothesis in context.hypotheses
                    if reference_id in hypothesis.supporting_evidence_reference_ids
                    or reference_id in hypothesis.contradicting_evidence_reference_ids
                ),
                key=lambda item: item.hypothesis_id,
            )
        )
        hypotheses = tuple(item.hypothesis_id for item in hypothesis_overlays)
        decision_overlays = tuple(
            sorted(
                (
                    DecisionOverlay(decision.decision_id, decision.decision_type)
                    for decision in context.decisions
                    if reference_id in decision.evidence_reference_ids
                    or set(decision.hypothesis_ids).intersection(hypotheses)
                ),
                key=lambda item: item.decision_id,
            )
        )
        decisions = tuple(item.decision_id for item in decision_overlays)
        return hypotheses, decisions, hypothesis_overlays, decision_overlays

    @staticmethod
    def _bounded(value: str) -> str:
        rendered = " ".join(str(value).split())
        if len(rendered) <= MAX_TIMELINE_SUMMARY_LENGTH:
            return rendered
        return rendered[: MAX_TIMELINE_SUMMARY_LENGTH - 3] + "..."

    @staticmethod
    def _sort_key(entry: InvestigationTimelineEntry):
        return (
            entry.timestamp or "",
            ENTRY_TYPE_PRECEDENCE[entry.entry_type],
            entry.entry_id,
        )

    def _filters(self, value):
        if value is None:
            result = InvestigationTimelineFilters()
        elif isinstance(value, InvestigationTimelineFilters):
            result = value
        elif isinstance(value, Mapping):
            unknown = set(value).difference(TIMELINE_FILTER_FIELDS)
            if unknown:
                raise UnsupportedTimelineFilterError(
                    f"Unsupported timeline filter: {sorted(unknown)[0]}"
                )
            result = InvestigationTimelineFilters(**value)
        else:
            raise UnsupportedTimelineFilterError("filters must be typed filters or a mapping")
        unknown_types = set(result.entry_types).difference(TIMELINE_ENTRY_TYPES)
        if unknown_types:
            raise UnsupportedTimelineFilterError(
                f"Unsupported entry type filter: {sorted(unknown_types)[0]}"
            )
        start = normalize_timestamp(result.start_time)
        end = normalize_timestamp(result.end_time)
        if result.start_time and start is None:
            raise InvalidTimelineRangeError("Invalid start timestamp")
        if result.end_time and end is None:
            raise InvalidTimelineRangeError("Invalid end timestamp")
        if start and end and start > end:
            raise InvalidTimelineRangeError("Timeline start must not follow end")
        return replace(result, start_time=start, end_time=end)

    def _matches(self, entry, filters):
        if filters.start_time and (entry.timestamp is None or entry.timestamp < filters.start_time):
            return False
        if filters.end_time and (entry.timestamp is None or entry.timestamp > filters.end_time):
            return False
        if filters.entry_types and entry.entry_type not in filters.entry_types:
            return False
        comparisons = (
            ("host", filters.host),
            ("user", filters.user),
            ("ip", filters.ip),
            ("process", filters.process),
        )
        for field_name, expected in comparisons:
            if expected is None:
                continue
            actual = getattr(entry, field_name)
            if actual is None or not self._entity_matches(field_name, expected, actual):
                return False
        exact = (
            (entry.rule_id, filters.rule_id),
            (entry.attack_tactic, filters.attack_tactic),
            (entry.attack_technique, filters.attack_technique),
            (entry.severity, filters.severity),
            (entry.evidence_classification, filters.evidence_classification),
        )
        if any(
            expected is not None
            and (actual is None or str(actual).casefold() != str(expected).casefold())
            for actual, expected in exact
        ):
            return False
        if filters.hypothesis_id and filters.hypothesis_id not in entry.related_hypothesis_ids:
            return False
        if filters.case_id and filters.case_id not in entry.case_ids:
            return False
        return True

    @staticmethod
    def _entity_matches(kind: str, expected: str, actual: str) -> bool:
        left = normalize_entity(kind, expected)
        right = normalize_entity(kind, actual)
        if kind == "process":
            return bool(
                {left.normalized_value, left.secondary_key}
                .intersection({right.normalized_value, right.secondary_key})
            )
        return left.normalized_value == right.normalized_value
