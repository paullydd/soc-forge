from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule, load_rules


RECENT_DETECTION_LIMIT = 5


@dataclass(frozen=True)
class AttackMapping:
    tactic: str
    technique: str
    technique_id: str

    @property
    def presentation(self) -> str:
        technique = " - ".join(
            value for value in (self.technique_id, self.technique) if value
        )
        return " | ".join(value for value in (self.tactic, technique) if value)


@dataclass(frozen=True)
class RuleCatalogEntry:
    rule_id: str
    title: str
    enabled: bool
    severity: str
    score: int
    attack_mappings: tuple[AttackMapping, ...]
    description: str
    tags: tuple[str, ...]
    author: str
    created: str
    logsource: str
    match_metadata: str
    emit_metadata: str
    aggregate_metadata: str
    score_modifiers_metadata: str


@dataclass(frozen=True)
class RecentDetection:
    rule_id: str
    title: str
    severity: str
    timestamp: str


@dataclass(frozen=True)
class DetectionOverview:
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    tactics_count: int
    techniques_count: int
    recent_alert_count: int
    recently_triggered_rule_count: int
    recently_triggered_rules: tuple[str, ...]
    recent_detections: tuple[RecentDetection, ...]
    last_detection_timestamp: str | None


class DetectionEngineeringService:
    """Read-only projections over authoritative rule and current alert data."""

    def __init__(
        self,
        *,
        rules_path: Path | str = BUILTIN_RULES_PATH,
        rule_loader: Callable[[list[str]], list[Rule]] = load_rules,
        alert_loader: Callable[[], Iterable[Mapping[str, Any]]] = lambda: (),
    ):
        self.rules_path = Path(rules_path)
        self.rule_loader = rule_loader
        self.alert_loader = alert_loader

    def rule_catalog(self) -> tuple[RuleCatalogEntry, ...]:
        rules = self.rule_loader([str(self.rules_path)])
        return tuple(
            sorted((self._catalog_entry(rule) for rule in rules), key=lambda item: item.rule_id)
        )

    def overview(
        self, catalog: Iterable[RuleCatalogEntry] | None = None
    ) -> DetectionOverview:
        entries = tuple(self.rule_catalog() if catalog is None else catalog)
        alerts = tuple(dict(alert) for alert in self.alert_loader())
        ordered_alerts = tuple(
            sorted(
                alerts,
                key=lambda item: (
                    str(item.get("timestamp", "")),
                    str(item.get("rule_id", "")),
                    str(item.get("title", "")),
                ),
                reverse=True,
            )
        )
        tactics = {
            mapping.tactic
            for entry in entries
            for mapping in entry.attack_mappings
            if mapping.tactic
        }
        techniques = {
            mapping.technique_id or mapping.technique
            for entry in entries
            for mapping in entry.attack_mappings
            if mapping.technique_id or mapping.technique
        }
        triggered = tuple(
            sorted(
                {
                    str(alert.get("rule_id", "")).strip()
                    for alert in ordered_alerts
                    if str(alert.get("rule_id", "")).strip()
                }
            )
        )
        recent = tuple(
            RecentDetection(
                rule_id=str(alert.get("rule_id", "") or "Unknown rule"),
                title=str(alert.get("title", "") or "Unknown alert"),
                severity=str(alert.get("severity", "") or "unknown").lower(),
                timestamp=str(alert.get("timestamp", "") or "Unknown time"),
            )
            for alert in ordered_alerts[:RECENT_DETECTION_LIMIT]
        )
        return DetectionOverview(
            total_rules=len(entries),
            enabled_rules=sum(entry.enabled for entry in entries),
            disabled_rules=sum(not entry.enabled for entry in entries),
            tactics_count=len(tactics),
            techniques_count=len(techniques),
            recent_alert_count=len(ordered_alerts),
            recently_triggered_rule_count=len(triggered),
            recently_triggered_rules=triggered,
            recent_detections=recent,
            last_detection_timestamp=(
                None if not ordered_alerts else str(ordered_alerts[0].get("timestamp", "")) or None
            ),
        )

    @classmethod
    def _catalog_entry(cls, rule: Rule) -> RuleCatalogEntry:
        return RuleCatalogEntry(
            rule_id=rule.id,
            title=rule.title,
            enabled=rule.enabled,
            severity=rule.severity,
            score=rule.score,
            attack_mappings=cls._attack_mappings(rule.mitre),
            description=rule.description,
            tags=tuple(sorted({str(tag) for tag in (rule.tags or ()) if str(tag)})),
            author=rule.author,
            created=rule.created,
            logsource=rule.logsource,
            match_metadata=cls._metadata(rule.match),
            emit_metadata=cls._metadata(rule.emit),
            aggregate_metadata=cls._metadata(rule.aggregate),
            score_modifiers_metadata=cls._metadata(rule.score_modifiers),
        )

    @staticmethod
    def _attack_mappings(values: Iterable[Mapping[str, Any]]) -> tuple[AttackMapping, ...]:
        mappings = {
            AttackMapping(
                tactic=str(item.get("tactic", "") or "").strip(),
                technique=str(item.get("technique", "") or "").strip(),
                technique_id=str(
                    item.get("technique_id", item.get("id", "")) or ""
                ).strip(),
            )
            for item in values
            if isinstance(item, Mapping)
        }
        return tuple(
            sorted(
                mappings,
                key=lambda item: (item.tactic, item.technique_id, item.technique),
            )
        )

    @staticmethod
    def _metadata(value: Any) -> str:
        if value in ({}, [], (), None):
            return "None"
        return json.dumps(value, sort_keys=True, separators=(", ", ": "), ensure_ascii=False)
