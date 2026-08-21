from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from soc_forge.attack_activity import AttackActivityService
from soc_forge.entity_explorer import EntityExplorerService
from soc_forge.pipeline import AnalysisResult
from soc_forge.temporal_analysis import TemporalAnalysisService


@dataclass(frozen=True)
class ExistingHunt:
    hunt_id: str
    title: str
    severity: str | None
    category: str | None
    summary: str
    confidence: str | None
    entities: tuple[tuple[str, object], ...]
    evidence_count: int
    first_seen: str | None
    last_seen: str | None
    techniques: tuple[str, ...]


@dataclass(frozen=True)
class HuntWorkspaceSummary:
    mode: str
    hunt_count: int | None
    result_count: int | None
    investigations_represented: int
    hunts: tuple[ExistingHunt, ...]
    machine_context_available: bool


class HuntWorkspaceService:
    def __init__(self, entity_explorer: EntityExplorerService,
                 attack_activity: AttackActivityService,
                 temporal_analysis: TemporalAnalysisService,
                 analysis_provider: Callable[[], object | None] = lambda: None,
                 *, result_limit: int = 25) -> None:
        self.entity_explorer = entity_explorer
        self.attack_activity = attack_activity
        self.temporal_analysis = temporal_analysis
        self.analysis_provider = analysis_provider
        self.result_limit = max(0, result_limit)

    def summarize(self):
        analysis = self._analysis()
        if analysis is None:
            return HuntWorkspaceSummary(
                "offline", None, None, 0, (), False
            )
        hunts = tuple(sorted(
            (self._hunt(row) for row in analysis.hunt_findings
             if isinstance(row, Mapping)),
            key=lambda row: (
                row.last_seen or "", row.first_seen or "", row.hunt_id,
                row.title.casefold(),
            ), reverse=True,
        ))
        result_count = sum(row.evidence_count for row in hunts)
        return HuntWorkspaceSummary(
            "full", len(hunts), result_count, 0,
            hunts[:self.result_limit], True
        )

    def entity_hunt(self, entity_type, value):
        return self.entity_explorer.search(entity_type, value)

    def technique_hunt(self, technique_id):
        technique_id = str(technique_id).strip().casefold()
        summary = self.attack_activity.summarize()
        matches = tuple(row for row in summary.techniques
                        if (row.technique_id or "").casefold() == technique_id)
        return summary.mode, matches

    def investigation_hunt(self, investigation_id):
        return self.temporal_analysis.analyze(
            investigation_id=str(investigation_id).strip()
        )

    def _analysis(self):
        candidate = self.analysis_provider()
        return candidate if isinstance(candidate, AnalysisResult) else None

    @staticmethod
    def _hunt(row):
        entities = row.get("entities")
        entities = entities if isinstance(entities, Mapping) else {}
        evidence = row.get("evidence")
        evidence = evidence if isinstance(evidence, (list, tuple)) else ()
        mitre = row.get("mitre")
        mitre = mitre if isinstance(mitre, (list, tuple)) else ()
        return ExistingHunt(
            str(row.get("hunt_id") or "HUNT-UNKNOWN"),
            str(row.get("title") or "Untitled Hunt"),
            str(row.get("severity")).strip() if row.get("severity") else None,
            str(row.get("category")).strip() if row.get("category") else None,
            str(row.get("summary") or ""),
            str(row.get("confidence")).strip() if row.get("confidence") else None,
            tuple(sorted((str(key), value) for key, value in entities.items())),
            len(evidence),
            str(row.get("first_seen")).strip() if row.get("first_seen") else None,
            str(row.get("last_seen")).strip() if row.get("last_seen") else None,
            tuple(sorted({str(item).strip() for item in mitre if str(item).strip()})),
        )
