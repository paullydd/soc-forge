from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Any, Iterable, List

import yaml

from soc_forge.rules.engine import _iter_yaml_files

RULE_ID_RE = re.compile(r"^[A-Z]+-[0-9]{3}$")
MITRE_ID_RE = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
QUALITY_METADATA = ("description", "author", "created", "logsource", "tags")
CONTEXT_DETAIL_FIELDS = {
    "host",
    "ip",
    "src_ip",
    "username",
    "actor",
    "target_user",
    "group",
    "group_name",
    "service_name",
    "task_name",
}


@dataclass(frozen=True)
class RuleQualityFinding:
    severity: str
    rule_id: str
    field: str
    message: str


@dataclass(frozen=True)
class RuleQualityReport:
    findings: List[RuleQualityFinding]

    @property
    def errors(self) -> List[RuleQualityFinding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> List[RuleQualityFinding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def passed(self) -> bool:
        return not self.errors and not self.warnings


def _finding(severity: str, rule_id: str, field: str, message: str) -> RuleQualityFinding:
    return RuleQualityFinding(severity=severity, rule_id=rule_id or "<unknown>", field=field, message=message)


def _raw_rules_from_paths(paths: Iterable[str]) -> List[dict[str, Any]]:
    raw_rules: List[dict[str, Any]] = []
    for p in paths:
        for file_path in _iter_yaml_files(Path(p).expanduser()):
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
            for rule in raw.get("rules", []) or []:
                if isinstance(rule, dict):
                    raw_rules.append(rule)
    return raw_rules


def _validate_created(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _count_predicates(node: Any) -> int:
    if not isinstance(node, dict):
        return 0
    if "all" in node:
        return sum(_count_predicates(child) for child in node.get("all") or [])
    if "any" in node:
        return sum(_count_predicates(child) for child in node.get("any") or [])
    return 1 if node.get("field") and node.get("op") else 0


def evaluate_rule_quality(raw_rules: Iterable[dict[str, Any]]) -> RuleQualityReport:
    findings: List[RuleQualityFinding] = []

    for raw in raw_rules:
        rule_id = str(raw.get("id") or "<unknown>")

        if not RULE_ID_RE.match(rule_id):
            findings.append(_finding("warning", rule_id, "id", "Rule id should follow a stable prefix-number pattern such as SOCF-007."))

        for field in QUALITY_METADATA:
            value = raw.get(field)
            if field == "tags":
                if not isinstance(value, list) or not value or any(not isinstance(t, str) or not t.strip() for t in value):
                    findings.append(_finding("warning", rule_id, field, "Rule should include at least one non-empty tag."))
            elif not isinstance(value, str) or not value.strip():
                findings.append(_finding("warning", rule_id, field, f"Rule should include non-empty {field}."))

        if raw.get("created") and not _validate_created(raw.get("created")):
            findings.append(_finding("warning", rule_id, "created", "created should use YYYY-MM-DD format."))

        mitre = raw.get("mitre")
        if not isinstance(mitre, list) or not mitre:
            findings.append(_finding("warning", rule_id, "mitre", "Rule should include at least one MITRE mapping."))
        else:
            for idx, mapping in enumerate(mitre):
                field = f"mitre[{idx}]"
                if not isinstance(mapping, dict):
                    findings.append(_finding("warning", rule_id, field, "MITRE mapping should be a mapping."))
                    continue
                if not str(mapping.get("tactic") or "").strip():
                    findings.append(_finding("warning", rule_id, field, "MITRE mapping should include tactic."))
                if not str(mapping.get("technique") or "").strip():
                    findings.append(_finding("warning", rule_id, field, "MITRE mapping should include technique."))
                technique_id = str(mapping.get("id") or mapping.get("technique_id") or "").strip()
                if not technique_id:
                    findings.append(_finding("warning", rule_id, field, "MITRE mapping should include id or technique_id."))
                elif not MITRE_ID_RE.match(technique_id):
                    findings.append(_finding("warning", rule_id, field, f"MITRE id looks unusual: {technique_id}"))

        emit = raw.get("emit")
        details = emit.get("details") if isinstance(emit, dict) else None
        if not isinstance(details, dict) or not details:
            findings.append(_finding("warning", rule_id, "emit.details", "Rule should emit explicit evidence details instead of relying on fallback fields."))
        else:
            if "message" not in details:
                findings.append(_finding("warning", rule_id, "emit.details.message", "Rule evidence should include the source message when available."))
            if not (set(details) & CONTEXT_DETAIL_FIELDS):
                findings.append(_finding("warning", rule_id, "emit.details", "Rule evidence should include at least one host, identity, IP, group, service, or task context field."))

        predicate_count = _count_predicates(raw.get("match"))
        if predicate_count == 0:
            findings.append(_finding("warning", rule_id, "match", "Rule should contain at least one concrete predicate."))

    return RuleQualityReport(findings=findings)


def evaluate_rule_quality_from_paths(paths: Iterable[str]) -> RuleQualityReport:
    return evaluate_rule_quality(_raw_rules_from_paths(paths))


def format_rule_quality_report(report: RuleQualityReport) -> str:
    lines = ["Rule Quality", ""]
    if report.passed:
        lines.append("PASS: no rule quality findings.")
        return "\n".join(lines) + "\n"

    if report.errors:
        lines.append("Errors")
        for finding in report.errors:
            lines.append(f"- {finding.rule_id} {finding.field}: {finding.message}")
        lines.append("")

    if report.warnings:
        lines.append("Warnings")
        for finding in report.warnings:
            lines.append(f"- {finding.rule_id} {finding.field}: {finding.message}")

    return "\n".join(lines) + "\n"
