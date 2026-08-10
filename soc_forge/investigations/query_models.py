from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


TIMELINE_ENTRY_TYPES = frozenset(
    {
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
    }
)
ENTITY_TYPES = frozenset(
    {
        "host",
        "user",
        "ip",
        "process",
        "service",
        "rule",
        "attack_technique",
        "case",
        "evidence",
        "hypothesis",
    }
)
TIMELINE_FILTER_FIELDS = frozenset(
    {
        "start_time",
        "end_time",
        "entry_types",
        "host",
        "user",
        "ip",
        "process",
        "rule_id",
        "attack_tactic",
        "attack_technique",
        "severity",
        "evidence_classification",
        "hypothesis_id",
        "case_id",
    }
)


class InvestigationQueryError(ValueError):
    pass


class AnalysisProvenanceMismatchError(InvestigationQueryError):
    pass


class UnsupportedEntityTypeError(InvestigationQueryError):
    pass


class InvalidEntityValueError(InvestigationQueryError):
    pass


class InvestigationEntityNotFoundError(InvestigationQueryError):
    pass


class UnsupportedTimelineFilterError(InvestigationQueryError):
    pass


class InvalidTimelineRangeError(InvestigationQueryError):
    pass


class QuerySourceReferenceNotFoundError(InvestigationQueryError):
    pass


@dataclass(frozen=True)
class HypothesisOverlay:
    hypothesis_id: str
    relationship: str
    state: str


@dataclass(frozen=True)
class DecisionOverlay:
    decision_id: str
    decision_type: str


@dataclass(frozen=True)
class InvestigationTimelineEntry:
    entry_id: str
    timestamp: str | None
    entry_type: str
    source_id: str
    source_analysis_id: str
    case_ids: Tuple[str, ...]
    title: str
    summary: str
    context_kind: str
    relationship_reason: str
    host: str | None = None
    user: str | None = None
    ip: str | None = None
    process: str | None = None
    service: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    attack_tactic: str | None = None
    attack_technique: str | None = None
    evidence_id: str | None = None
    analyst_selected: bool = False
    evidence_classification: str | None = None
    related_hypothesis_ids: Tuple[str, ...] = ()
    related_decision_ids: Tuple[str, ...] = ()
    hypothesis_overlays: Tuple[HypothesisOverlay, ...] = ()
    decision_overlays: Tuple[DecisionOverlay, ...] = ()
    sensitive_fields: Tuple[str, ...] = ()
    provenance_fields: Tuple[str, ...] = ()
    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.entry_type not in TIMELINE_ENTRY_TYPES:
            raise ValueError(f"Unsupported timeline entry type: {self.entry_type}")
        if self.context_kind not in {"machine", "analyst"}:
            raise ValueError("context_kind must be 'machine' or 'analyst'")


@dataclass(frozen=True)
class InvestigationTimelineFilters:
    start_time: str | None = None
    end_time: str | None = None
    entry_types: Tuple[str, ...] = ()
    host: str | None = None
    user: str | None = None
    ip: str | None = None
    process: str | None = None
    rule_id: str | None = None
    attack_tactic: str | None = None
    attack_technique: str | None = None
    severity: str | None = None
    evidence_classification: str | None = None
    hypothesis_id: str | None = None
    case_id: str | None = None


@dataclass(frozen=True)
class InvestigationTimeline:
    investigation_id: str
    source_analysis_id: str
    entries: Tuple[InvestigationTimelineEntry, ...]
    untimed_entries: Tuple[InvestigationTimelineEntry, ...]
    applied_filters: InvestigationTimelineFilters
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class InvestigationEntity:
    entity_type: str
    value: str
    normalized_value: str
    display_value: str
    secondary_key: str | None = None

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise UnsupportedEntityTypeError(
                f"Unsupported entity type: {self.entity_type}"
            )
        if not self.normalized_value:
            raise InvalidEntityValueError("Entity value must be nonblank")


@dataclass(frozen=True)
class PivotMatch:
    source_type: str
    source_id: str
    relationship_type: str
    relationship_reason: str
    source_analysis_id: str
    case_ids: Tuple[str, ...] = ()
    evidence_id: str | None = None
    analyst_selected: bool = False
    evidence_classification: str | None = None
    hypothesis_overlays: Tuple[HypothesisOverlay, ...] = ()
    decision_overlays: Tuple[DecisionOverlay, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None
    count: int = 1
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class PivotResult:
    investigation_id: str
    source_analysis_id: str
    entity: InvestigationEntity
    matches: Tuple[PivotMatch, ...]
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RelatedEntity:
    entity: InvestigationEntity
    source_ids: Tuple[str, ...]
    relationship_reason: str
    count: int
    first_seen: str | None = None
    last_seen: str | None = None


@dataclass(frozen=True)
class RelatedEntitiesResult:
    investigation_id: str
    source_analysis_id: str
    entity: InvestigationEntity
    relationships: Tuple[RelatedEntity, ...]
    limitations: Tuple[str, ...] = ()
