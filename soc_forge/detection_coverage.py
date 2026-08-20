from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Any

from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule, load_rules


@dataclass(frozen=True)
class DetectionCoverageRule:
    rule_id: str
    title: str
    enabled: bool
    has_attack_mapping: bool


@dataclass(frozen=True)
class DetectionCoverageTactic:
    tactic: str
    technique_keys: tuple[str, ...]
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class DetectionCoverageTechnique:
    technique_key: str
    technique_id: str
    technique_name: str
    tactics: tuple[str, ...]
    rule_ids: tuple[str, ...]
    enabled_rule_ids: tuple[str, ...]
    disabled_rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class DetectionCoverageSummary:
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    rules_with_attack_mapping: int
    rules_without_attack_mapping: int
    tactics: tuple[DetectionCoverageTactic, ...]
    techniques: tuple[DetectionCoverageTechnique, ...]
    rules: tuple[DetectionCoverageRule, ...]


@dataclass(frozen=True)
class DetectionGap:
    gap_id: str
    gap_type: str
    title: str
    reason: str
    related_rule_ids: tuple[str, ...]
    related_tactics: tuple[str, ...]
    related_techniques: tuple[str, ...]


@dataclass(frozen=True)
class DetectionGapSummary:
    gaps: tuple[DetectionGap, ...]
    expected_baseline_configured: bool
    scope_note: str


class DetectionCoverageService:
    """Read-only ruleset coverage derived from explicit ATT&CK metadata."""

    def __init__(
        self,
        *,
        rules_path: Path | str = BUILTIN_RULES_PATH,
        rule_loader: Callable[[list[str]], list[Rule]] = load_rules,
    ):
        self.rules_path = Path(rules_path)
        self.rule_loader = rule_loader

    def load_rules(self) -> tuple[Rule, ...]:
        return tuple(
            self.rule_loader([str(self.rules_path)])
        )

    def summarize(
        self, rules: Iterable[Rule] | None = None
    ) -> DetectionCoverageSummary:
        return self.project(
            self.load_rules() if rules is None else rules
        )

    @classmethod
    def project(
        cls, rules: Iterable[Rule]
    ) -> DetectionCoverageSummary:
        ordered_rules = tuple(sorted(rules, key=lambda rule: rule.id))
        coverage_rules = []
        tactic_techniques: dict[str, set[str]] = {}
        tactic_rules: dict[str, set[str]] = {}
        technique_data: dict[str, dict[str, Any]] = {}

        for rule in ordered_rules:
            mappings = tuple(cls._explicit_mappings(rule.mitre))
            coverage_rules.append(
                DetectionCoverageRule(
                    rule_id=rule.id,
                    title=rule.title,
                    enabled=rule.enabled,
                    has_attack_mapping=bool(mappings),
                )
            )
            for tactic, technique_id, technique_name in mappings:
                technique_key = technique_id or technique_name
                if tactic:
                    tactic_rules.setdefault(tactic, set()).add(rule.id)
                    if technique_key:
                        tactic_techniques.setdefault(tactic, set()).add(
                            technique_key
                        )
                if not technique_key:
                    continue
                row = technique_data.setdefault(
                    technique_key,
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactics": set(),
                        "rule_ids": set(),
                        "enabled_rule_ids": set(),
                        "disabled_rule_ids": set(),
                    },
                )
                if tactic:
                    row["tactics"].add(tactic)
                row["rule_ids"].add(rule.id)
                target = (
                    "enabled_rule_ids"
                    if rule.enabled
                    else "disabled_rule_ids"
                )
                row[target].add(rule.id)

        tactics = tuple(
            DetectionCoverageTactic(
                tactic=tactic,
                technique_keys=tuple(
                    sorted(tactic_techniques.get(tactic, set()))
                ),
                rule_ids=tuple(sorted(rule_ids)),
            )
            for tactic, rule_ids in sorted(tactic_rules.items())
        )
        techniques = tuple(
            DetectionCoverageTechnique(
                technique_key=key,
                technique_id=str(row["technique_id"]),
                technique_name=str(row["technique_name"]),
                tactics=tuple(sorted(row["tactics"])),
                rule_ids=tuple(sorted(row["rule_ids"])),
                enabled_rule_ids=tuple(sorted(row["enabled_rule_ids"])),
                disabled_rule_ids=tuple(sorted(row["disabled_rule_ids"])),
            )
            for key, row in sorted(technique_data.items())
        )
        rule_rows = tuple(coverage_rules)
        with_mapping = sum(
            item.has_attack_mapping for item in rule_rows
        )
        return DetectionCoverageSummary(
            total_rules=len(rule_rows),
            enabled_rules=sum(item.enabled for item in rule_rows),
            disabled_rules=sum(not item.enabled for item in rule_rows),
            rules_with_attack_mapping=with_mapping,
            rules_without_attack_mapping=len(rule_rows) - with_mapping,
            tactics=tactics,
            techniques=techniques,
            rules=rule_rows,
        )

    @staticmethod
    def _explicit_mappings(
        values: Iterable[Mapping[str, Any]],
    ) -> Iterable[tuple[str, str, str]]:
        seen = set()
        for value in values or ():
            if not isinstance(value, Mapping):
                continue
            mapping = (
                str(value.get("tactic", "") or "").strip(),
                str(
                    value.get(
                        "technique_id", value.get("id", "")
                    )
                    or ""
                ).strip(),
                str(value.get("technique", "") or "").strip(),
            )
            if any(mapping) and mapping not in seen:
                seen.add(mapping)
                yield mapping


class DetectionGapService:
    """Explicit metadata-quality and enabled-availability gap projection."""

    SCOPE_NOTE = (
        "No expected ATT&CK baseline is configured. Gap analysis is limited "
        "to explicit rule metadata quality and enabled-rule availability."
    )

    def __init__(self, coverage_service: DetectionCoverageService):
        self.coverage_service = coverage_service

    def summarize(
        self,
        coverage: DetectionCoverageSummary | None = None,
    ) -> DetectionGapSummary:
        summary = coverage or self.coverage_service.summarize()
        gaps = []
        for rule in summary.rules:
            if rule.has_attack_mapping:
                continue
            gaps.append(
                DetectionGap(
                    gap_id=f"DGAP:UNMAPPED:{rule.rule_id}",
                    gap_type="UNMAPPED_RULE",
                    title=f"Rule has no explicit ATT&CK mapping: {rule.rule_id}",
                    reason=(
                        "The loaded rule contains no explicit ATT&CK tactic "
                        "or technique metadata."
                    ),
                    related_rule_ids=(rule.rule_id,),
                    related_tactics=(),
                    related_techniques=(),
                )
            )
        for technique in summary.techniques:
            if technique.enabled_rule_ids or not technique.disabled_rule_ids:
                continue
            safe_key = re.sub(
                r"[^A-Z0-9.]+",
                "_",
                technique.technique_key.upper(),
            ).strip("_")
            gaps.append(
                DetectionGap(
                    gap_id=f"DGAP:DISABLED_COVERAGE:{safe_key}",
                    gap_type="DISABLED_COVERAGE",
                    title=(
                        "Technique is represented only by disabled rules: "
                        f"{technique.technique_key}"
                    ),
                    reason=(
                        "All loaded rules explicitly mapped to this technique "
                        "are disabled."
                    ),
                    related_rule_ids=technique.disabled_rule_ids,
                    related_tactics=technique.tactics,
                    related_techniques=(technique.technique_key,),
                )
            )
        return DetectionGapSummary(
            gaps=tuple(
                sorted(
                    gaps,
                    key=lambda gap: (
                        gap.gap_type,
                        gap.related_tactics,
                        gap.related_techniques,
                        gap.related_rule_ids,
                        gap.gap_id,
                    ),
                )
            ),
            expected_baseline_configured=False,
            scope_note=self.SCOPE_NOTE,
        )
