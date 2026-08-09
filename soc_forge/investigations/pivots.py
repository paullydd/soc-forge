from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Iterable, Tuple

from soc_forge.investigations.query_context import (
    InvestigationQueryContext,
    QuerySource,
    normalize_entity,
)
from soc_forge.investigations.query_models import (
    DecisionOverlay,
    HypothesisOverlay,
    InvestigationEntity,
    PivotMatch,
    PivotResult,
    RelatedEntitiesResult,
    RelatedEntity,
)
from soc_forge.investigations.timeline_query import InvestigationTimelineService


MAX_PIVOT_RESULTS = 200
MAX_RELATED_ENTITIES = 100


class InvestigationPivotService:
    def events_for_entity(self, context, entity_type, value) -> PivotResult:
        return self._source_result(context, entity_type, value, {"event"})

    def alerts_for_entity(self, context, entity_type, value) -> PivotResult:
        return self._source_result(context, entity_type, value, {"alert"})

    def evidence_for_entity(self, context, entity_type, value) -> PivotResult:
        return self._source_result(
            context,
            entity_type,
            value,
            {"event", "alert", "case", "reconstruction_step"},
        )

    def cases_for_entity(self, context, entity_type, value) -> PivotResult:
        entity = normalize_entity(entity_type, value)
        case_reasons = defaultdict(set)
        timestamps = defaultdict(list)
        for source in self._matching_sources(context, entity):
            for case_id in source.candidate.case_ids:
                case_reasons[case_id].add(source.candidate.source_id)
                if source.candidate.timestamp:
                    timestamps[case_id].append(source.candidate.timestamp)
        if entity.entity_type == "case":
            case_reasons[entity.value].add(entity.value)
        matches = []
        for case_id in sorted(case_reasons):
            observed = sorted(timestamps[case_id])
            matches.append(
                PivotMatch(
                    source_type="case",
                    source_id=case_id,
                    relationship_type="case_membership",
                    relationship_reason=(
                        "Matched source records are explicit members of this case"
                    ),
                    source_analysis_id=context.source_analysis_id,
                    case_ids=(case_id,),
                    first_seen=observed[0] if observed else None,
                    last_seen=observed[-1] if observed else None,
                    count=len(case_reasons[case_id]),
                )
            )
        return self._result(context, entity, matches)

    def hypotheses_for_entity(self, context, entity_type, value) -> PivotResult:
        entity = normalize_entity(entity_type, value)
        matched_reference_ids = set()
        if entity.entity_type == "evidence":
            matched_reference_ids.add(entity.value)
            source = context.sources.get(entity.value)
            if source:
                selected = context.selected_reference(source.candidate.evidence_id)
                if selected:
                    matched_reference_ids.add(selected.reference_id)
        else:
            for source in self._matching_sources(context, entity):
                selected = context.selected_reference(source.candidate.evidence_id)
                if selected:
                    matched_reference_ids.add(selected.reference_id)

        matches = []
        for hypothesis in context.hypotheses:
            if entity.entity_type == "hypothesis":
                linked = hypothesis.hypothesis_id == entity.value
                reason = "Entity names this investigation hypothesis"
            else:
                supporting = set(hypothesis.supporting_evidence_reference_ids)
                contradicting = set(hypothesis.contradicting_evidence_reference_ids)
                linked = bool(matched_reference_ids.intersection(supporting | contradicting))
                relationship = (
                    "supporting"
                    if matched_reference_ids.intersection(supporting)
                    else "contradicting"
                )
                reason = f"Hypothesis explicitly references {relationship} evidence"
            if linked:
                matches.append(
                    PivotMatch(
                        source_type="hypothesis",
                        source_id=hypothesis.hypothesis_id,
                        relationship_type="hypothesis_relationship",
                        relationship_reason=reason,
                        source_analysis_id=context.source_analysis_id,
                        case_ids=context.selected_case_ids,
                        first_seen=hypothesis.created_at,
                        last_seen=hypothesis.updated_at,
                        hypothesis_overlays=(
                            HypothesisOverlay(
                                hypothesis.hypothesis_id,
                                "direct hypothesis reference",
                                hypothesis.state,
                            ),
                        ),
                    )
                )
        return self._result(context, entity, matches)

    def evidence_for_hypothesis(self, context, hypothesis_id) -> PivotResult:
        entity = normalize_entity("hypothesis", hypothesis_id)
        hypothesis = next(
            (
                item
                for item in context.hypotheses
                if item.hypothesis_id == hypothesis_id
            ),
            None,
        )
        matches = []
        if hypothesis is not None:
            relationships = (
                ("supporting", hypothesis.supporting_evidence_reference_ids),
                ("contradicting", hypothesis.contradicting_evidence_reference_ids),
            )
            for relationship, evidence_ids in relationships:
                for evidence_id in evidence_ids:
                    reference = context.evidence_references_by_id.get(evidence_id)
                    matches.append(
                        PivotMatch(
                            source_type="evidence",
                            source_id=evidence_id,
                            relationship_type="hypothesis_relationship",
                            relationship_reason=(
                                f"Hypothesis explicitly references {relationship} evidence"
                            ),
                            source_analysis_id=context.source_analysis_id,
                            case_ids=context.selected_case_ids,
                            evidence_id=evidence_id,
                            analyst_selected=(
                                reference is not None
                                and reference.origin == "analyst_selection"
                            ),
                            evidence_classification=(
                                reference.classification if reference is not None else None
                            ),
                            hypothesis_overlays=(
                                HypothesisOverlay(
                                    hypothesis.hypothesis_id,
                                    relationship,
                                    hypothesis.state,
                                ),
                            ),
                        )
                    )
        return self._result(context, entity, matches)

    def timeline_for_entity(self, context, entity_type, value):
        entity = normalize_entity(entity_type, value)
        direct_filters = {
            "host": "host",
            "user": "user",
            "ip": "ip",
            "process": "process",
            "rule": "rule_id",
            "attack_technique": "attack_technique",
            "case": "case_id",
            "hypothesis": "hypothesis_id",
        }
        field = direct_filters.get(entity.entity_type)
        if field:
            return InvestigationTimelineService().timeline(
                context,
                filters={field: entity.value},
            )
        timeline = InvestigationTimelineService().timeline(context)
        matched_ids = {
            source.candidate.source_id
            for source in self._matching_sources(context, entity)
        }
        return replace(
            timeline,
            entries=tuple(
                entry for entry in timeline.entries if entry.source_id in matched_ids
            ),
            untimed_entries=tuple(
                entry
                for entry in timeline.untimed_entries
                if entry.source_id in matched_ids
            ),
        )

    def related_entities(
        self,
        context: InvestigationQueryContext,
        entity_type: str,
        value: object,
    ) -> RelatedEntitiesResult:
        entity = normalize_entity(entity_type, value)
        grouped = defaultdict(lambda: {"sources": set(), "times": []})
        for source in self._matching_sources(context, entity):
            for related in source.entities:
                if self._entity_equal(entity, related):
                    continue
                key = (
                    related.entity_type,
                    related.normalized_value,
                    related.secondary_key,
                )
                grouped[key]["entity"] = related
                grouped[key]["sources"].add(source.candidate.source_id)
                if source.candidate.timestamp:
                    grouped[key]["times"].append(source.candidate.timestamp)
        relationships = []
        for key in sorted(grouped):
            item = grouped[key]
            times = sorted(item["times"])
            relationships.append(
                RelatedEntity(
                    entity=item["entity"],
                    source_ids=tuple(sorted(item["sources"])),
                    relationship_reason="Directly observed on the same source record",
                    count=len(item["sources"]),
                    first_seen=times[0] if times else None,
                    last_seen=times[-1] if times else None,
                )
            )
        return RelatedEntitiesResult(
            investigation_id=context.investigation.investigation_id,
            source_analysis_id=context.source_analysis_id,
            entity=entity,
            relationships=tuple(relationships[:MAX_RELATED_ENTITIES]),
            limitations=(
                ("Related entities are bounded to directly observed records.",)
                if len(relationships) > MAX_RELATED_ENTITIES
                else ()
            ),
        )

    def _source_result(self, context, entity_type, value, source_types):
        entity = normalize_entity(entity_type, value)
        matches = []
        for source in self._matching_sources(context, entity):
            candidate = source.candidate
            if candidate.evidence_type not in source_types:
                continue
            selected = context.selected_reference(candidate.evidence_id)
            hypothesis_overlays, decision_overlays = self._reasoning_overlays(
                context, selected
            )
            matches.append(
                PivotMatch(
                    source_type=candidate.evidence_type,
                    source_id=candidate.source_id,
                    relationship_type="source_field",
                    relationship_reason=self._relationship_reason(entity),
                    source_analysis_id=context.source_analysis_id,
                    case_ids=candidate.case_ids,
                    evidence_id=candidate.evidence_id,
                    analyst_selected=selected is not None,
                    evidence_classification=(
                        selected.classification if selected is not None else None
                    ),
                    hypothesis_overlays=hypothesis_overlays,
                    decision_overlays=decision_overlays,
                    first_seen=candidate.timestamp,
                    last_seen=candidate.timestamp,
                    limitations=(
                        (candidate.limitation_reason,)
                        if candidate.limitation_reason
                        else ()
                    ),
                )
            )
        return self._result(context, entity, matches)

    @staticmethod
    def _reasoning_overlays(context, selected):
        if selected is None:
            return (), ()
        reference_id = selected.reference_id
        hypotheses = tuple(
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
        hypothesis_ids = {item.hypothesis_id for item in hypotheses}
        decisions = tuple(
            sorted(
                (
                    DecisionOverlay(decision.decision_id, decision.decision_type)
                    for decision in context.decisions
                    if reference_id in decision.evidence_reference_ids
                    or set(decision.hypothesis_ids).intersection(hypothesis_ids)
                ),
                key=lambda item: item.decision_id,
            )
        )
        return hypotheses, decisions

    @staticmethod
    def _result(context, entity, matches: Iterable[PivotMatch]):
        deduped = {
            (
                match.source_type,
                match.source_id,
                match.relationship_type,
                match.relationship_reason,
            ): match
            for match in matches
        }
        ordered = tuple(deduped[key] for key in sorted(deduped))
        return PivotResult(
            investigation_id=context.investigation.investigation_id,
            source_analysis_id=context.source_analysis_id,
            entity=entity,
            matches=ordered[:MAX_PIVOT_RESULTS],
            limitations=(
                ("Pivot results were deterministically bounded.",)
                if len(ordered) > MAX_PIVOT_RESULTS
                else ()
            ),
        )

    @staticmethod
    def _matching_sources(context, entity) -> Tuple[QuerySource, ...]:
        return tuple(
            source
            for source in context.sources.values()
            if any(
                InvestigationPivotService._entity_equal(entity, candidate)
                for candidate in source.entities
            )
        )

    @staticmethod
    def _entity_equal(left: InvestigationEntity, right: InvestigationEntity) -> bool:
        if left.entity_type != right.entity_type:
            return False
        if left.entity_type == "process":
            return bool(
                {left.normalized_value, left.secondary_key}
                .intersection({right.normalized_value, right.secondary_key})
            )
        return left.normalized_value == right.normalized_value

    @staticmethod
    def _relationship_reason(entity: InvestigationEntity) -> str:
        if entity.entity_type == "rule":
            return "Alert rule_id equals the normalized rule entity"
        if entity.entity_type == "attack_technique":
            return "Source ATT&CK technique equals the normalized technique entity"
        if entity.entity_type == "case":
            return "Source is an explicit member of the selected case"
        if entity.entity_type == "evidence":
            return "Source owns the requested evidence identity"
        return f"Source {entity.entity_type} field equals the normalized entity"
