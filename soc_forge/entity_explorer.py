from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Callable

from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.query_context import normalize_entity
from soc_forge.investigations.query_models import (
    InvalidEntityValueError, UnsupportedEntityTypeError,
)
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.pipeline import AnalysisResult

ENTITY_TYPES = ("host", "user", "ip", "process")
FIELD_ENTITY_TYPES = {
    "host": "host", "user": "user", "source_ip": "ip", "process": "process",
}


@dataclass(frozen=True)
class ObservedEntity:
    entity_type: str
    display_value: str
    normalized_value: str
    secondary_key: str | None = None


@dataclass(frozen=True)
class EntityObservation:
    entity_type: str
    entity_value: str
    normalized_value: str
    source_type: str
    source_id: str
    investigation_id: str | None
    timestamp: str | None
    title: str
    attack_tactics: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    entities: tuple[ObservedEntity, ...]
    origin: str


@dataclass(frozen=True)
class RelatedEntity:
    entity_type: str
    entity_value: str
    normalized_value: str
    observation_count: int


@dataclass(frozen=True)
class AttackObservation:
    value: str
    observation_count: int


@dataclass(frozen=True)
class DiscoverableEntity:
    entity_type: str
    display_value: str
    normalized_value: str
    observation_count: int
    machine_observation_count: int
    analyst_observation_count: int
    investigation_ids: tuple[str, ...]


@dataclass(frozen=True)
class EntityDiscoveryResult:
    mode: str
    machine_context_available: bool
    entities: tuple[DiscoverableEntity, ...]


@dataclass(frozen=True)
class EntityExplorerResult:
    entity_type: str
    query: str
    normalized_query: str
    mode: str
    observation_count: int
    alert_count: int
    investigation_count: int
    finding_count: int
    response_action_count: int
    case_count: int
    observations: tuple[EntityObservation, ...]
    related_entities: tuple[RelatedEntity, ...]
    attack_tactics: tuple[AttackObservation, ...]
    attack_techniques: tuple[AttackObservation, ...]
    investigation_ids: tuple[str, ...]


class EntityObservationService:
    """Projects structured entity observations without persisting an index."""

    def __init__(self, repository: InvestigationRepository,
                 analysis_provider: Callable[[], object | None] = lambda: None,
                 *, catalog: AnalysisEvidenceCatalog | None = None) -> None:
        self.repository = repository
        self.analysis_provider = analysis_provider
        self.catalog = catalog or AnalysisEvidenceCatalog()

    def list_observations(self) -> tuple[str, tuple[EntityObservation, ...]]:
        candidate = self.analysis_provider()
        analysis = candidate if isinstance(candidate, AnalysisResult) else None
        if analysis is None:
            return "offline", ()
        observations = list(self._machine_observations(analysis))
        by_evidence = {row.source_id: row for row in observations}
        for summary in self.repository.list_investigations():
            investigation = self.repository.load(summary.investigation_id)
            selected = {
                reference.reference_id: by_evidence.get(reference.reference_id)
                for reference in investigation.evidence_references
                if reference.origin == "analyst_selection"
            }
            selected = {key: value for key, value in selected.items() if value}
            for reference_id, machine in selected.items():
                observations.append(self._analyst_copy(
                    machine, "evidence", reference_id,
                    investigation.investigation_id,
                    next(reference.label for reference in investigation.evidence_references
                         if reference.reference_id == reference_id) or machine.title,
                    next(reference.selected_at for reference in investigation.evidence_references
                         if reference.reference_id == reference_id),
                ))
            findings_by_id = {}
            for finding in investigation.findings:
                linked = tuple(selected[item] for item in finding.evidence_ids
                               if item in selected)
                entities = self._union_entities(linked)
                if not entities:
                    continue
                findings_by_id[finding.finding_id] = entities
                observations.append(EntityObservation(
                    entities[0].entity_type, entities[0].display_value,
                    entities[0].normalized_value, "finding", finding.finding_id,
                    investigation.investigation_id, finding.updated_at, finding.title,
                    tuple(sorted(set(finding.attack_tactics))),
                    tuple(sorted(set(finding.attack_techniques))), entities, "analyst",
                ))
            for action in investigation.response_actions:
                entities = self._union_entity_tuples(
                    findings_by_id[item] for item in action.finding_ids
                    if item in findings_by_id
                )
                if entities:
                    observations.append(EntityObservation(
                        entities[0].entity_type, entities[0].display_value,
                        entities[0].normalized_value, "response_action",
                        action.action_id, investigation.investigation_id,
                        action.updated_at, action.title, (), (), entities, "analyst",
                    ))
        return "full", tuple(observations)

    def _machine_observations(self, analysis: AnalysisResult):
        alert_attack = self._alert_attack_map(analysis)
        for candidate in self.catalog.list_candidates(analysis):
            details = self.catalog.resolve_details(analysis, candidate.evidence_id)
            entities = []
            for reference in candidate.entity_references:
                entity_type, separator, value = reference.partition(":")
                if not separator or entity_type not in ENTITY_TYPES:
                    continue
                try:
                    entity = normalize_entity(entity_type, value)
                except (InvalidEntityValueError, UnsupportedEntityTypeError):
                    continue
                entities.append(ObservedEntity(
                    entity.entity_type, entity.display_value,
                    entity.normalized_value, entity.secondary_key,
                ))
            for field in details.fields:
                entity_type = FIELD_ENTITY_TYPES.get(field.field_name)
                if entity_type is None or field.sensitive or not field.value.strip():
                    continue
                try:
                    entity = normalize_entity(entity_type, field.value)
                except (InvalidEntityValueError, UnsupportedEntityTypeError):
                    continue
                entities.append(ObservedEntity(
                    entity.entity_type, entity.display_value,
                    entity.normalized_value, entity.secondary_key,
                ))
            entities = self._dedupe_entities(entities)
            if not entities:
                continue
            tactics = (candidate.tactic,) if candidate.tactic else ()
            techniques = (candidate.technique,) if candidate.technique else ()
            if candidate.evidence_type == "alert":
                extra_tactics, extra_techniques = alert_attack.get(
                    (candidate.rule_id or "", candidate.timestamp or "", candidate.title), ((), ())
                )
                tactics = tuple(sorted(set(tactics).union(extra_tactics)))
                techniques = tuple(sorted(set(techniques).union(extra_techniques)))
            yield EntityObservation(
                entities[0].entity_type, entities[0].display_value,
                entities[0].normalized_value, candidate.evidence_type,
                candidate.evidence_id, None, candidate.timestamp, candidate.title,
                tactics, techniques, entities, "machine",
            )

    @staticmethod
    def _alert_attack_map(analysis: AnalysisResult):
        result = {}
        for alert in analysis.alerts:
            if not isinstance(alert, dict):
                continue
            tactics, techniques = set(), set()
            rows = alert.get("mitre")
            rows = rows if isinstance(rows, (list, tuple)) else (rows,)
            for row in rows:
                if not isinstance(row, dict):
                    continue
                tactic = str(row.get("tactic") or "").strip()
                technique = " - ".join(part for part in (
                    str(row.get("technique_id") or "").strip(),
                    str(row.get("technique") or "").strip(),
                ) if part)
                if tactic:
                    tactics.add(tactic)
                if technique:
                    techniques.add(technique)
            key = (
                str(alert.get("rule_id") or "").strip(),
                str(alert.get("timestamp") or "").strip(),
                str(alert.get("title") or "Detection alert").strip(),
            )
            result[key] = (tuple(sorted(tactics)), tuple(sorted(techniques)))
        return result

    @staticmethod
    def _analyst_copy(machine, source_type, source_id, investigation_id,
                      title, timestamp):
        return EntityObservation(
            machine.entity_type, machine.entity_value, machine.normalized_value,
            source_type, source_id, investigation_id, timestamp, title,
            machine.attack_tactics, machine.attack_techniques,
            machine.entities, "analyst",
        )

    @classmethod
    def _union_entities(cls, observations):
        return cls._union_entity_tuples(row.entities for row in observations)

    @classmethod
    def _union_entity_tuples(cls, tuples):
        return cls._dedupe_entities(entity for values in tuples for entity in values)

    @staticmethod
    def _dedupe_entities(entities):
        values = {}
        for entity in entities:
            key = (entity.entity_type, entity.normalized_value,
                   entity.secondary_key or "")
            values.setdefault(key, entity)
        return tuple(values[key] for key in sorted(values))


class EntityExplorerService:
    def __init__(self, observation_service: EntityObservationService,
                 *, observation_limit: int = 10) -> None:
        self.observation_service = observation_service
        self.observation_limit = max(0, observation_limit)

    def discover(self) -> EntityDiscoveryResult:
        mode, observations = self.observation_service.list_observations()
        grouped = {}
        for observation in observations:
            seen = set()
            for entity in observation.entities:
                key = (entity.entity_type, entity.normalized_value)
                if key in seen:
                    continue
                seen.add(key)
                value = grouped.setdefault(key, {
                    "display_value": entity.display_value,
                    "machine": 0,
                    "analyst": 0,
                    "investigations": set(),
                })
                value[observation.origin] += 1
                if observation.investigation_id:
                    value["investigations"].add(observation.investigation_id)
        entities = tuple(sorted((
            DiscoverableEntity(
                entity_type, values["display_value"], normalized_value,
                values["machine"] + values["analyst"], values["machine"],
                values["analyst"], tuple(sorted(values["investigations"])),
            )
            for (entity_type, normalized_value), values in grouped.items()
        ), key=lambda row: (
            row.entity_type, -row.observation_count, row.normalized_value
        )))
        return EntityDiscoveryResult(mode, mode == "full", entities)

    def search(self, entity_type: str, query: object) -> EntityExplorerResult:
        entity = normalize_entity(entity_type, query)
        if entity.entity_type not in ENTITY_TYPES:
            raise UnsupportedEntityTypeError(f"Unsupported entity type: {entity_type}")
        mode, all_observations = self.observation_service.list_observations()
        matches = tuple(row for row in all_observations
                        if self._matches(row, entity.entity_type,
                                         entity.normalized_value))
        ordered = tuple(sorted(matches, key=lambda row: (
            row.timestamp or "", row.source_type, row.investigation_id or "",
            row.source_id,
        ), reverse=True))
        investigations = tuple(sorted({
            row.investigation_id for row in matches if row.investigation_id
        }))
        related = Counter()
        display = {}
        for row in matches:
            seen = set()
            for related_entity in row.entities:
                key = (related_entity.entity_type, related_entity.normalized_value)
                if key == (entity.entity_type, entity.normalized_value) or key in seen:
                    continue
                seen.add(key)
                related[key] += 1
                display.setdefault(key, related_entity.display_value)
        related_rows = tuple(sorted((
            RelatedEntity(kind, display[(kind, value)], value, count)
            for (kind, value), count in related.items()
        ), key=lambda row: (-row.observation_count, row.entity_type,
                            row.normalized_value)))
        return EntityExplorerResult(
            entity.entity_type, str(query).strip(), entity.normalized_value, mode,
            len(matches), sum(row.source_type == "alert" for row in matches),
            len(investigations), sum(row.source_type == "finding" for row in matches),
            sum(row.source_type == "response_action" for row in matches),
            sum(row.source_type == "case" for row in matches),
            ordered[:self.observation_limit], related_rows,
            self._attack(matches, "attack_tactics"),
            self._attack(matches, "attack_techniques"), investigations,
        )

    @staticmethod
    def _matches(row, entity_type, normalized):
        return any(
            item.entity_type == entity_type
            and item.normalized_value == normalized
            for item in row.entities
        )

    @staticmethod
    def _attack(observations, field):
        counts = Counter(value for row in observations for value in getattr(row, field))
        return tuple(AttackObservation(value, count)
                     for value, count in sorted(counts.items(),
                                                key=lambda item: (-item[1], item[0])))
