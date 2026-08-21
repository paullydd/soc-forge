from __future__ import annotations

from dataclasses import dataclass
import re

from soc_forge.attack_activity import AttackActivityService
from soc_forge.entity_explorer import EntityObservationService

CAUTION = (
    "Shared observations do not establish that these Investigations represent "
    "the same attack, attacker, campaign, or cause."
)


@dataclass(frozen=True)
class CrossInvestigationObservation:
    timestamp: str | None
    attribution: str
    source_type: str
    source_id: str
    investigation_id: str
    title: str


@dataclass(frozen=True)
class CrossInvestigationRelationship:
    relationship_id: str
    relationship_type: str
    key: str
    display_value: str
    entity_type: str | None
    tactic: str | None
    technique_id: str | None
    investigation_ids: tuple[str, ...]
    observation_count: int
    machine_observation_count: int
    analyst_observation_count: int
    source_ids: tuple[str, ...]
    recent_observations: tuple[CrossInvestigationObservation, ...]
    explanation: str
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class CrossInvestigationSummary:
    relationship_count: int
    investigation_count: int
    shared_entity_count: int
    shared_tactic_count: int
    shared_technique_count: int
    relationships: tuple[CrossInvestigationRelationship, ...]
    mode: str


class CrossInvestigationAnalysisService:
    """Projects explicit overlap across distinct durable Investigations."""

    def __init__(
        self,
        entity_observations: EntityObservationService,
        attack_activity: AttackActivityService,
        *,
        recent_limit: int = 10,
    ) -> None:
        self.entity_observations = entity_observations
        self.attack_activity = attack_activity
        self.recent_limit = max(0, recent_limit)

    def summarize(self) -> CrossInvestigationSummary:
        entity_mode, entity_rows = self.entity_observations.list_observations()
        attack = self.attack_activity.summarize()
        groups: dict[tuple[str, str, str], dict[tuple[str, ...], object]] = {}

        for row in entity_rows:
            if not row.investigation_id:
                continue
            for entity in row.entities:
                group = groups.setdefault(
                    ("shared_entity", entity.entity_type, entity.normalized_value), {}
                )
                identity = (
                    row.investigation_id, row.origin, row.source_type, row.source_id,
                    entity.entity_type, entity.normalized_value,
                )
                group.setdefault(identity, (entity.display_value, row))

        for row in attack.observations:
            if not row.investigation_id:
                continue
            if row.tactic:
                group = groups.setdefault(
                    ("shared_attack_tactic", "", row.tactic.casefold()), {}
                )
                identity = (
                    row.investigation_id, row.attribution, row.source_type,
                    row.source_id, "tactic", row.tactic.casefold(),
                )
                group.setdefault(identity, (row.tactic, row))
            if row.technique_key:
                normalized = (row.technique_id or row.technique_key).casefold()
                group = groups.setdefault(
                    ("shared_attack_technique", "", normalized), {}
                )
                identity = (
                    row.investigation_id, row.attribution, row.source_type,
                    row.source_id, "technique", normalized,
                )
                group.setdefault(identity, (row.technique_key, row))

        relationships = []
        for (kind, subtype, key), entries in groups.items():
            investigation_ids = tuple(sorted({identity[0] for identity in entries}))
            if len(investigation_ids) < 2:
                continue
            relationships.append(self._relationship(
                kind, subtype, key, tuple(entries.values()), investigation_ids
            ))
        relationships.sort(key=lambda row: (
            -len(row.investigation_ids), -row.observation_count,
            row.relationship_type, row.key,
        ))
        represented = {
            investigation_id
            for row in relationships for investigation_id in row.investigation_ids
        }
        return CrossInvestigationSummary(
            relationship_count=len(relationships),
            investigation_count=len(represented),
            shared_entity_count=sum(
                row.relationship_type == "shared_entity" for row in relationships
            ),
            shared_tactic_count=sum(
                row.relationship_type == "shared_attack_tactic"
                for row in relationships
            ),
            shared_technique_count=sum(
                row.relationship_type == "shared_attack_technique"
                for row in relationships
            ),
            relationships=tuple(relationships),
            mode="full" if "full" in (entity_mode, attack.mode) else "offline",
        )

    def _relationship(self, kind, subtype, key, entries, investigation_ids):
        display = sorted({value for value, _row in entries}, key=str.casefold)[0]
        observations = tuple(sorted(
            (self._supporting(row) for _value, row in entries),
            key=lambda row: (
                row.timestamp or "", row.attribution, row.source_type,
                row.investigation_id, row.source_id,
            ),
            reverse=True,
        ))
        machine = sum(row.attribution == "machine" for row in observations)
        analyst = sum(row.attribution == "analyst" for row in observations)
        if kind == "shared_entity":
            relationship_id = f"XINV:ENTITY:{subtype}:{key}"
            explanation = (
                f"{subtype.title()} {display} was explicitly observed in "
                f"{len(investigation_ids)} Investigations."
            )
            tactic = technique_id = None
            entity_type = subtype
        elif kind == "shared_attack_tactic":
            relationship_id = f"XINV:ATTACK:TACTIC:{self._id_key(key)}"
            explanation = (
                f"Tactic {display} was explicitly observed or recorded in "
                f"{len(investigation_ids)} Investigations."
            )
            tactic, technique_id, entity_type = display, None, None
        else:
            technique_id = next((
                getattr(row, "technique_id", None) for _value, row in entries
                if getattr(row, "technique_id", None)
            ), None)
            relationship_id = (
                f"XINV:ATTACK:TECHNIQUE:{technique_id or self._id_key(key)}"
            )
            explanation = (
                f"Technique {display} was explicitly observed or recorded in "
                f"{len(investigation_ids)} Investigations."
            )
            tactic, entity_type = None, None
        return CrossInvestigationRelationship(
            relationship_id, kind, key, display, entity_type, tactic,
            technique_id, investigation_ids, len(observations), machine, analyst,
            tuple(sorted({row.source_id for row in observations})),
            observations[:self.recent_limit], explanation, (CAUTION,),
        )

    @staticmethod
    def _supporting(row):
        attribution = getattr(row, "origin", None) or getattr(
            row, "attribution", "analyst"
        )
        return CrossInvestigationObservation(
            row.timestamp, attribution, row.source_type, row.source_id,
            row.investigation_id, row.title,
        )

    @staticmethod
    def _id_key(value):
        return re.sub(r"[^a-z0-9.]+", "-", value.casefold()).strip("-")
