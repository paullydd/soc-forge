from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import re
from typing import Callable, Mapping

from soc_forge.investigations.provenance import content_digest
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.pipeline import AnalysisResult


@dataclass(frozen=True)
class AttackActivityObservation:
    tactic: str | None
    technique_id: str | None
    technique_name: str | None
    source_type: str
    source_id: str
    investigation_id: str | None
    timestamp: str | None
    attribution: str
    title: str
    related_rule_id: str | None = None

    @property
    def technique_key(self) -> str | None:
        if self.technique_id and self.technique_name:
            return f"{self.technique_id} - {self.technique_name}"
        return self.technique_id or self.technique_name


@dataclass(frozen=True)
class AttackTechniqueActivity:
    technique_key: str
    technique_id: str | None
    technique_name: str | None
    tactics: tuple[str, ...]
    observation_count: int
    machine_observation_count: int
    analyst_observation_count: int
    alert_count: int
    case_count: int
    reconstruction_count: int
    investigation_count: int
    finding_count: int
    source_ids: tuple[str, ...]
    investigation_ids: tuple[str, ...]
    recent_observations: tuple[AttackActivityObservation, ...]
    observations: tuple[AttackActivityObservation, ...] = ()


@dataclass(frozen=True)
class AttackTacticActivity:
    tactic: str
    observation_count: int
    machine_observation_count: int
    analyst_observation_count: int
    technique_keys: tuple[str, ...]
    investigation_count: int
    investigation_ids: tuple[str, ...]


@dataclass(frozen=True)
class AttackActivitySummary:
    mode: str
    observation_count: int
    tactic_count: int
    technique_count: int
    machine_observation_count: int
    analyst_observation_count: int
    investigations_represented: int
    tactics: tuple[AttackTacticActivity, ...]
    techniques: tuple[AttackTechniqueActivity, ...]
    recent_observations: tuple[AttackActivityObservation, ...]
    observations: tuple[AttackActivityObservation, ...] = ()


class AttackActivityService:
    """Projects explicit ATT&CK mappings from current authoritative state."""

    def __init__(self, repository: InvestigationRepository,
                 analysis_provider: Callable[[], object | None] = lambda: None,
                 *, recent_limit: int = 10) -> None:
        self.repository = repository
        self.analysis_provider = analysis_provider
        self.recent_limit = max(0, recent_limit)

    def summarize(self) -> AttackActivitySummary:
        observations = list(self._analyst_observations())
        candidate = self.analysis_provider()
        analysis = candidate if isinstance(candidate, AnalysisResult) else None
        if analysis is not None:
            observations.extend(self._machine_observations(analysis))
        observations = list(self._dedupe(observations))
        observations.sort(key=self._recent_key, reverse=True)
        tactics = self._tactics(observations)
        techniques = self._techniques(observations)
        investigation_ids = {
            row.investigation_id for row in observations if row.investigation_id
        }
        return AttackActivitySummary(
            mode="full" if analysis is not None else "offline",
            observation_count=len(observations),
            tactic_count=len(tactics),
            technique_count=len(techniques),
            machine_observation_count=sum(
                row.attribution == "machine" for row in observations
            ),
            analyst_observation_count=sum(
                row.attribution == "analyst" for row in observations
            ),
            investigations_represented=len(investigation_ids),
            tactics=tactics,
            techniques=techniques,
            recent_observations=tuple(observations[:self.recent_limit]),
            observations=tuple(observations),
        )

    def _analyst_observations(self):
        for summary in self.repository.list_investigations():
            investigation = self.repository.load(summary.investigation_id)
            for finding in investigation.findings:
                for tactic in sorted(set(finding.attack_tactics)):
                    yield AttackActivityObservation(
                        tactic=tactic, technique_id=None, technique_name=None,
                        source_type="finding", source_id=finding.finding_id,
                        investigation_id=investigation.investigation_id,
                        timestamp=finding.updated_at, attribution="analyst",
                        title=finding.title,
                    )
                for technique in sorted(set(finding.attack_techniques)):
                    technique_id, technique_name = self._technique(technique)
                    if technique_id or technique_name:
                        yield AttackActivityObservation(
                            tactic=None, technique_id=technique_id,
                            technique_name=technique_name, source_type="finding",
                            source_id=finding.finding_id,
                            investigation_id=investigation.investigation_id,
                            timestamp=finding.updated_at, attribution="analyst",
                            title=finding.title,
                        )

    def _machine_observations(self, analysis: AnalysisResult):
        for alert in analysis.alerts:
            if not isinstance(alert, Mapping):
                continue
            source_id = "alert-" + content_digest(alert, "alert")[:24]
            title = self._text(alert.get("title")) or "Detection alert"
            timestamp = self._text(alert.get("timestamp")) or None
            rule_id = self._text(alert.get("rule_id")) or None
            for tactic, technique_id, technique_name in self._mapping_rows(
                alert.get("mitre")
            ):
                yield AttackActivityObservation(
                    tactic, technique_id, technique_name, "alert", source_id,
                    None, timestamp, "machine", title, rule_id,
                )
        for case in analysis.cases:
            if not isinstance(case, Mapping):
                continue
            source_id = self._text(case.get("case_id")) or (
                "case-" + content_digest(case, "case")[:24]
            )
            title = self._text(case.get("title")) or "Case"
            timestamp = self._text(case.get("created_at")) or None
            for tactic, technique_id, technique_name in self._mapping_rows(
                case.get("mitre"), mappings_only=True
            ):
                yield AttackActivityObservation(
                    tactic, technique_id, technique_name, "case", source_id,
                    None, timestamp, "machine", title,
                )
        for reconstruction in analysis.reconstructions:
            if not isinstance(reconstruction, Mapping):
                continue
            case_id = self._text(reconstruction.get("case_id"))
            for step in reconstruction.get("attack_path", ()):
                if not isinstance(step, Mapping):
                    continue
                tactic = self._text(step.get("tactic")) or None
                technique_id, technique_name = self._technique(
                    self._text(step.get("technique"))
                )
                if not (tactic or technique_id or technique_name):
                    continue
                source_id = "reconstruction-" + content_digest(
                    {"case_id": case_id, "step": step}, "reconstruction step"
                )[:24]
                yield AttackActivityObservation(
                    tactic, technique_id, technique_name, "reconstruction",
                    source_id, None, self._text(step.get("timestamp")) or None,
                    "machine", self._text(step.get("title")) or "Reconstruction step",
                )

    @classmethod
    def _mapping_rows(cls, value, *, mappings_only=False):
        if not isinstance(value, (list, tuple)):
            return ()
        rows = set()
        for item in value:
            if not isinstance(item, Mapping):
                if mappings_only:
                    continue
                technique_id, technique_name = cls._technique(cls._text(item))
                if technique_id or technique_name:
                    rows.add((None, technique_id, technique_name))
                continue
            tactic = cls._text(item.get("tactic")) or None
            technique_id = cls._text(item.get("technique_id")) or None
            parsed_id, parsed_name = cls._technique(
                cls._text(item.get("technique"))
            )
            technique_id = technique_id or parsed_id
            technique_name = parsed_name
            if tactic or technique_id or technique_name:
                rows.add((tactic, technique_id, technique_name))
        return tuple(sorted(rows, key=lambda row: tuple(value or "" for value in row)))

    @staticmethod
    def _technique(value):
        text = str(value or "").strip()
        if not text:
            return None, None
        match = re.match(r"^(T[0-9]{4}(?:\.[0-9]{3})?)(?:\s*[-—:]\s*(.+))?$",
                         text, re.IGNORECASE)
        if match:
            return match.group(1).upper(), (
                match.group(2).strip() if match.group(2) else None
            )
        return None, text

    @staticmethod
    def _text(value):
        return value.strip() if isinstance(value, str) else ""

    @staticmethod
    def _dedupe(observations):
        rows = {}
        for row in observations:
            key = (
                row.source_type, row.source_id, row.tactic or "",
                row.technique_id or "", row.technique_name or "",
            )
            rows.setdefault(key, row)
        return tuple(rows[key] for key in sorted(rows))

    @staticmethod
    def _recent_key(row):
        return (
            row.timestamp or "", row.attribution, row.source_type,
            row.investigation_id or "", row.source_id, row.tactic or "",
            row.technique_key or "",
        )

    def _tactics(self, observations):
        groups = {}
        for row in observations:
            if row.tactic:
                groups.setdefault(row.tactic, []).append(row)
        result = []
        for tactic, rows in groups.items():
            investigations = tuple(sorted({
                row.investigation_id for row in rows if row.investigation_id
            }))
            result.append(AttackTacticActivity(
                tactic=tactic, observation_count=len(rows),
                machine_observation_count=sum(row.attribution == "machine" for row in rows),
                analyst_observation_count=sum(row.attribution == "analyst" for row in rows),
                technique_keys=tuple(sorted({
                    row.technique_key for row in rows if row.technique_key
                })),
                investigation_count=len(investigations),
                investigation_ids=investigations,
            ))
        return tuple(sorted(result, key=lambda row: (-row.observation_count,
                                                     row.tactic.casefold())))

    def _techniques(self, observations):
        groups = {}
        for row in observations:
            if row.technique_key:
                groups.setdefault(row.technique_key, []).append(row)
        result = []
        for key, rows in groups.items():
            investigations = tuple(sorted({
                row.investigation_id for row in rows if row.investigation_id
            }))
            first = rows[0]
            recent = tuple(sorted(rows, key=self._recent_key, reverse=True)[
                :self.recent_limit
            ])
            result.append(AttackTechniqueActivity(
                technique_key=key, technique_id=first.technique_id,
                technique_name=first.technique_name,
                tactics=tuple(sorted({row.tactic for row in rows if row.tactic})),
                observation_count=len(rows),
                machine_observation_count=sum(row.attribution == "machine" for row in rows),
                analyst_observation_count=sum(row.attribution == "analyst" for row in rows),
                alert_count=sum(row.source_type == "alert" for row in rows),
                case_count=sum(row.source_type == "case" for row in rows),
                reconstruction_count=sum(row.source_type == "reconstruction" for row in rows),
                investigation_count=len(investigations),
                finding_count=sum(row.source_type == "finding" for row in rows),
                source_ids=tuple(sorted({row.source_id for row in rows})),
                investigation_ids=investigations, recent_observations=recent,
            ))
        return tuple(sorted(result, key=lambda row: (-row.observation_count,
                                                     row.technique_key.casefold())))
