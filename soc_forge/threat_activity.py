from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.pipeline import AnalysisResult

OPEN_ACTION_STATUSES = frozenset({"proposed", "approved", "in_progress"})


@dataclass(frozen=True)
class AttackActivity:
    value: str
    machine_observations: int
    analyst_observations: int

    @property
    def observation_count(self) -> int:
        return self.machine_observations + self.analyst_observations


@dataclass(frozen=True)
class RecentActivity:
    timestamp: str
    origin: str
    source_type: str
    investigation_id: str
    source_id: str
    description: str


@dataclass(frozen=True)
class ThreatActivityOverview:
    mode: str
    investigation_count: int
    active_finding_count: int
    historical_finding_count: int
    open_response_action_count: int
    alert_count: int | None
    case_count: int | None
    hunt_count: int | None
    reconstruction_count: int | None
    tactics: tuple[AttackActivity, ...]
    techniques: tuple[AttackActivity, ...]
    recent_activity: tuple[RecentActivity, ...]
    investigations_with_activity: int


class ThreatActivityOverviewService:
    """Build a deterministic, non-persisted view of observed activity."""

    def __init__(self, repository: InvestigationRepository,
                 analysis_provider: Callable[[], object | None] = lambda: None,
                 *, recent_limit: int = 10) -> None:
        self.repository = repository
        self.analysis_provider = analysis_provider
        self.recent_limit = max(0, recent_limit)

    def summarize(self) -> ThreatActivityOverview:
        investigations = tuple(self.repository.load(row.investigation_id)
                               for row in self.repository.list_investigations())
        candidate = self.analysis_provider()
        machine = candidate if isinstance(candidate, AnalysisResult) else None
        mt, at, mx, ax = Counter(), Counter(), Counter(), Counter()
        recent: list[RecentActivity] = []
        active = historical = open_actions = with_activity = 0
        for investigation in investigations:
            if investigation.findings or investigation.response_actions:
                with_activity += 1
            for finding in investigation.findings:
                active += finding.lifecycle_state == "active"
                historical += finding.lifecycle_state != "active"
                at.update(set(finding.attack_tactics))
                ax.update(set(finding.attack_techniques))
                recent.append(RecentActivity(
                    finding.updated_at, "analyst", "finding",
                    investigation.investigation_id, finding.finding_id,
                    f"{finding.finding_id} {finding.status}",
                ))
            for action in investigation.response_actions:
                open_actions += action.status in OPEN_ACTION_STATUSES
                for transition in action.transition_history:
                    recent.append(RecentActivity(
                        transition.timestamp, "analyst", "response_action",
                        investigation.investigation_id, action.action_id,
                        f"{action.action_id} moved to {transition.to_status.upper()}",
                    ))
        if machine is not None:
            for index, alert in enumerate(machine.alerts):
                if not isinstance(alert, Mapping):
                    continue
                for tactic, technique in self._mappings(alert.get("mitre")):
                    mt.update((tactic,) if tactic else ())
                    mx.update((technique,) if technique else ())
                timestamp = self._text(alert.get("timestamp"))
                if timestamp:
                    source_id = self._text(alert.get("rule_id")) or f"ALERT-{index + 1:03d}"
                    title = self._text(alert.get("title")) or "Alert"
                    recent.append(RecentActivity(timestamp, "machine", "alert", "",
                                                 source_id, f"{source_id} {title}"))
        recent.sort(key=lambda row: (row.timestamp, row.source_type,
                                     row.investigation_id, row.source_id), reverse=True)
        return ThreatActivityOverview(
            "full" if machine else "offline", len(investigations), active, historical,
            open_actions, len(machine.alerts) if machine else None,
            len(machine.cases) if machine else None,
            len(machine.hunt_findings) if machine else None,
            len(machine.reconstructions) if machine else None,
            self._rows(mt, at), self._rows(mx, ax),
            tuple(recent[:self.recent_limit]), with_activity,
        )

    @staticmethod
    def _rows(machine: Counter[str], analyst: Counter[str]) -> tuple[AttackActivity, ...]:
        rows = (AttackActivity(value, machine[value], analyst[value])
                for value in set(machine) | set(analyst))
        return tuple(sorted(rows, key=lambda row: (-row.observation_count,
                                                   row.value.casefold())))

    @classmethod
    def _mappings(cls, value: object) -> tuple[tuple[str, str], ...]:
        if not isinstance(value, (list, tuple)):
            return ()
        result = set()
        for item in value:
            if isinstance(item, Mapping):
                tactic = cls._text(item.get("tactic"))
                technique = " - ".join(filter(None, (
                    cls._text(item.get("technique_id")),
                    cls._text(item.get("technique")),
                )))
                if tactic or technique:
                    result.add((tactic, technique))
            elif cls._text(item):
                result.add(("", cls._text(item)))
        return tuple(sorted(result))

    @staticmethod
    def _text(value: Any) -> str:
        return value.strip() if isinstance(value, str) else ""
