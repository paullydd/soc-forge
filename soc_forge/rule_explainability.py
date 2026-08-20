from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from soc_forge.detection_engineering import AttackMapping
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import Rule, load_rules


_OPERATOR_TEXT = {
    "eq": "equals",
    "contains": "contains",
    "regex": "matches regular expression",
    "exists": "exists",
}
_TEMPLATE_RE = re.compile(r"^\$\{([A-Za-z0-9_]+)\}$")


@dataclass(frozen=True)
class MatchCondition:
    field: str
    operator: str
    expected: str | None
    text: str


@dataclass(frozen=True)
class ScoreModifierExplanation:
    conditions: tuple[MatchCondition, ...]
    logic: tuple[str, ...]
    score_addition: int
    bumps_severity: bool
    detail_updates: tuple[tuple[str, str], ...]
    reason: str


@dataclass(frozen=True)
class RuleExplanation:
    rule_id: str
    title: str
    summary: str
    enabled: bool
    severity: str
    description: str
    referenced_fields: tuple[str, ...]
    match_conditions: tuple[MatchCondition, ...]
    match_logic: tuple[str, ...]
    operators: tuple[str, ...]
    aggregate_behavior: str
    grouping_fields: tuple[str, ...]
    aggregate_field: str
    threshold: int | None
    time_window_minutes: int | None
    emit_summary: str
    emit_fields: tuple[str, ...]
    emit_source_fields: tuple[str, ...]
    score_modifiers: tuple[ScoreModifierExplanation, ...]
    attack_mappings: tuple[AttackMapping, ...]
    attack_tactics: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    logsource: str
    tags: tuple[str, ...]
    author: str
    created: str
    limitations: tuple[str, ...]
    assumptions: tuple[str, ...]


class RuleExplanationService:
    """Deterministic, read-only projections over authoritative loaded rules."""

    def __init__(
        self,
        *,
        rules_path: Path | str = BUILTIN_RULES_PATH,
        rule_loader: Callable[[list[str]], list[Rule]] = load_rules,
    ):
        self.rules_path = Path(rules_path)
        self.rule_loader = rule_loader

    def explanations(self) -> tuple[RuleExplanation, ...]:
        rules = self.rule_loader([str(self.rules_path)])
        return tuple(
            self.explain(rule) for rule in sorted(rules, key=lambda item: item.id)
        )

    def explanation_for(self, rule_id: str) -> RuleExplanation:
        for explanation in self.explanations():
            if explanation.rule_id == rule_id:
                return explanation
        raise ValueError(f"Rule not found: {rule_id}")

    @classmethod
    def explain(cls, rule: Rule) -> RuleExplanation:
        match_conditions, match_logic = cls._logic(rule.match)
        modifiers = tuple(cls._modifier(value) for value in rule.score_modifiers or ())
        aggregate = rule.aggregate or {}
        group_by = tuple(str(value) for value in aggregate.get("group_by", ()) or ())
        distinct = aggregate.get("distinct_count", {}) or {}
        aggregate_field = str(distinct.get("field", "") or "")
        threshold = cls._optional_int(distinct.get("gte"))
        time_window = cls._optional_int(aggregate.get("window_minutes"))
        emit = rule.emit or {}
        details = emit.get("details")
        explicit_details = details if isinstance(details, Mapping) else {}
        emit_fields = tuple(sorted(str(key) for key in explicit_details))
        emit_source_fields = tuple(
            sorted(
                {
                    match.group(1)
                    for value in explicit_details.values()
                    if isinstance(value, str)
                    for match in [_TEMPLATE_RE.match(value)]
                    if match
                }
            )
        )
        referenced = {
            condition.field for condition in match_conditions if condition.field
        }
        referenced.update(group_by)
        if aggregate_field:
            referenced.add(aggregate_field)
        if aggregate:
            referenced.add("timestamp")
        referenced.update(emit_source_fields)
        for modifier in modifiers:
            referenced.update(
                condition.field
                for condition in modifier.conditions
                if condition.field
            )
        mappings = cls._attack_mappings(rule.mitre)
        tactics = tuple(sorted({item.tactic for item in mappings if item.tactic}))
        techniques = tuple(
            sorted(
                {
                    " - ".join(
                        value
                        for value in (item.technique_id, item.technique)
                        if value
                    )
                    for item in mappings
                    if item.technique_id or item.technique
                }
            )
        )
        operator_set = {condition.operator for condition in match_conditions}
        for modifier in modifiers:
            operator_set.update(condition.operator for condition in modifier.conditions)
        return RuleExplanation(
            rule_id=rule.id,
            title=rule.title,
            summary=rule.description,
            enabled=rule.enabled,
            severity=rule.severity,
            description=rule.description,
            referenced_fields=tuple(sorted(referenced)),
            match_conditions=match_conditions,
            match_logic=match_logic,
            operators=tuple(
                operator for operator in _OPERATOR_TEXT if operator in operator_set
            ),
            aggregate_behavior=("Distinct count" if aggregate else ""),
            grouping_fields=group_by,
            aggregate_field=aggregate_field,
            threshold=threshold,
            time_window_minutes=time_window,
            emit_summary=str(emit.get("summary", "") or ""),
            emit_fields=emit_fields,
            emit_source_fields=emit_source_fields,
            score_modifiers=modifiers,
            attack_mappings=mappings,
            attack_tactics=tactics,
            attack_techniques=techniques,
            logsource=rule.logsource,
            tags=tuple(sorted({str(tag) for tag in (rule.tags or ()) if str(tag)})),
            author=rule.author,
            created=rule.created,
            limitations=(),
            assumptions=(),
        )

    @classmethod
    def _logic(
        cls, node: Mapping[str, Any], depth: int = 0
    ) -> tuple[tuple[MatchCondition, ...], tuple[str, ...]]:
        indent = "  " * depth
        if "all" in node:
            conditions = []
            lines = [f"{indent}All of:"]
            for child in node.get("all", ()) or ():
                child_conditions, child_lines = cls._logic(child, depth + 1)
                conditions.extend(child_conditions)
                lines.extend(child_lines)
            return tuple(conditions), tuple(lines)
        if "any" in node:
            conditions = []
            lines = [f"{indent}Any of:"]
            for child in node.get("any", ()) or ():
                child_conditions, child_lines = cls._logic(child, depth + 1)
                conditions.extend(child_conditions)
                lines.extend(child_lines)
            return tuple(conditions), tuple(lines)
        field = str(node.get("field", ""))
        operator = str(node.get("op", ""))
        expected = None if operator == "exists" else cls._value(node.get("value"))
        text = f"{field} {_OPERATOR_TEXT[operator]}"
        if expected is not None:
            text += f" {expected}"
        condition = MatchCondition(
            field=field,
            operator=operator,
            expected=expected,
            text=text,
        )
        return (condition,), (f"{indent}- {text}",)

    @classmethod
    def _modifier(cls, value: Mapping[str, Any]) -> ScoreModifierExplanation:
        conditions, logic = cls._logic(value["when"])
        updates = value.get("set_details")
        detail_updates = tuple(
            (str(key), cls._value(item))
            for key, item in sorted(
                (updates if isinstance(updates, Mapping) else {}).items(),
                key=lambda pair: str(pair[0]),
            )
        )
        return ScoreModifierExplanation(
            conditions=conditions,
            logic=logic,
            score_addition=int(value.get("add", 0) or 0),
            bumps_severity=bool(value.get("bump_severity", False)),
            detail_updates=detail_updates,
            reason=str(value.get("reason", "") or ""),
        )

    @staticmethod
    def _attack_mappings(
        values: Iterable[Mapping[str, Any]],
    ) -> tuple[AttackMapping, ...]:
        return tuple(
            sorted(
                {
                    AttackMapping(
                        tactic=str(item.get("tactic", "") or "").strip(),
                        technique=str(item.get("technique", "") or "").strip(),
                        technique_id=str(
                            item.get("technique_id", item.get("id", "")) or ""
                        ).strip(),
                    )
                    for item in values
                    if isinstance(item, Mapping)
                },
                key=lambda item: (
                    item.tactic,
                    item.technique_id,
                    item.technique,
                ),
            )
        )

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        return None if value is None else int(value)

    @staticmethod
    def _value(value: Any) -> str:
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
