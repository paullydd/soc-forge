from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

import re
import yaml

# NOTE: We'll return dict alerts for now to avoid forcing a refactor of Alert import paths.
# Once you move Alert into soc_forge/models.py, you can switch to returning Alert objects.
# For Phase 4 stability, this keeps your existing report/correlation pipeline working.

VALID_OPS = {"eq", "contains", "regex", "exists"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

@dataclass(frozen=True)
class Rule:
    id: str
    enabled: bool
    title: str
    severity: str
    score: int
    mitre: List[Dict[str, str]]
    match: Dict[str, Any]
    emit: Dict[str, Any]
    score_modifiers: List[Dict[str, Any]]

    description: str = ""
    author: str = ""
    created: str = ""
    logsource: str = ""
    tags: List[str] = None


# ----------------------------
# Rule loading
# ----------------------------

def _iter_yaml_files(path: Path) -> Iterable[Path]:
    """Yield YAML files from a file or directory path (directories searched recursively)."""
    if path.is_file():
        if path.suffix.lower() in (".yml", ".yaml"):
            yield path
        return

    if path.is_dir():
        for p in sorted(path.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
                yield p
        return

    raise FileNotFoundError(f"Rules path not found: {path}")


def _load_rule_file(file_path: Path) -> List[Rule]:
    raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    rules_raw = raw.get("rules", []) or []

    if not isinstance(rules_raw, list):
        raise ValueError(f"{file_path}: 'rules' must be a list")

    # ---- Validation pass (collect all issues) ----
    errors: List[str] = []
    for i, r in enumerate(rules_raw):
        if isinstance(r, dict):
            _validate_rule_dict(r, file_path, i, errors)
        else:
            errors.append(f"{file_path} rule[{i}]: each rule must be a mapping/object")

    if errors:
        raise ValueError("Rule validation failed:\n" + "\n".join(errors))

    # ---- Build Rule objects ----
    rules: List[Rule] = []
    for r in rules_raw:
        rule_id = r.get("id")
        # id/title/etc already validated, but keep safe casts
        rules.append(
            Rule(
                id=str(rule_id),
                enabled=bool(r.get("enabled", True)),
                title=str(r.get("title", "")),
                severity=str(r.get("severity", "medium")),
                score=int(r.get("score", 0)),
                mitre=list(r.get("mitre", []) or []),
                match=dict(r.get("match", {}) or {}),
                emit=dict(r.get("emit", {}) or {}),
                score_modifiers=list(r.get("score_modifiers", []) or []),
                description=str(r.get("description", "") or ""),
                author=str(r.get("author", "") or ""),
                created=str(r.get("created", "") or ""),
                logsource=str(r.get("logsource", "") or ""),
                tags=list(r.get("tags", []) or []),
            )
        )

    return rules


def load_rules(paths: Union[str, List[str]]) -> List[Rule]:
    """
    Load rules from a list of file/dir paths.
    - Directories are searched recursively for *.yml/*.yaml.
    - Files may each contain multiple rules in a top-level 'rules:' list.
    """
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        raise ValueError("load_rules(paths): at least one path is required")

    all_rules: List[Rule] = []
    seen_ids: Dict[str, Path] = {}

    for p in paths:
        base = Path(p).expanduser()

        for file_path in _iter_yaml_files(base):
            for rule in _load_rule_file(file_path):
                if rule.id in seen_ids:
                    raise ValueError(
                        f"Duplicate rule id '{rule.id}' in {file_path} "
                        f"(already defined in {seen_ids[rule.id]})"
                    )
                seen_ids[rule.id] = file_path
                all_rules.append(rule)

    return all_rules


# ----------------------------
# Matching engine
# ----------------------------

def _get_field(event: Dict[str, Any], field: str) -> Any:
    # TODO: allow nested fields later (e.g., "raw.Message" -> event["raw"]["Message"])
    return event.get(field)


def _op_eval(op: str, actual: Any, expected: Any) -> bool:
    if op == "eq":
        return actual == expected

    if op == "contains":
        if actual is None:
            return False
        return str(expected).lower() in str(actual).lower()

    if op == "regex":
        if actual is None:
            return False
        return re.search(str(expected), str(actual)) is not None

    if op == "exists":
        return actual is not None and str(actual) != ""

    raise ValueError(f"Unsupported op: {op}")


def _eval_node(node: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """
    Node forms:
      {"all":[...]}
      {"any":[...]}
      {"field":"message","op":"regex","value":"..."}
    """
    if not node:
        return False

    if "all" in node:
        children = node["all"] or []
        return all(_eval_node(child, event) for child in children)

    if "any" in node:
        children = node["any"] or []
        return any(_eval_node(child, event) for child in children)

    field = node.get("field")
    op = node.get("op")
    expected = node.get("value")

    if not field or not op:
        raise ValueError(f"Invalid predicate node (missing field/op): {node}")

    actual = _get_field(event, field)
    return _op_eval(op, actual, expected)

def _is_nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""


def _validate_match_tree(node: Any, where: str, errors: List[str]) -> None:
    """
    Validates match-tree nodes:
      {"all":[...]}
      {"any":[...]}
      {"field":"...", "op":"...", "value": ...}
    """
    if not isinstance(node, dict) or not node:
        errors.append(f"{where}: match node must be a non-empty mapping")
        return

    if "all" in node:
        children = node.get("all")
        if not isinstance(children, list) or not children:
            errors.append(f"{where}: 'all' must be a non-empty list")
            return
        for i, child in enumerate(children):
            _validate_match_tree(child, f"{where}.all[{i}]", errors)
        return

    if "any" in node:
        children = node.get("any")
        if not isinstance(children, list) or not children:
            errors.append(f"{where}: 'any' must be a non-empty list")
            return
        for i, child in enumerate(children):
            _validate_match_tree(child, f"{where}.any[{i}]", errors)
        return

    # predicate form
    field = node.get("field")
    op = node.get("op")

    if not _is_nonempty_str(field):
        errors.append(f"{where}: predicate missing/invalid 'field'")
        return

    if op not in VALID_OPS:
        errors.append(f"{where}: unsupported op '{op}' (allowed: {sorted(VALID_OPS)})")
        return

    # value rules
    if op in {"eq", "contains", "regex"}:
        if "value" not in node:
            errors.append(f"{where}: op '{op}' requires 'value'")
            return

        # extra safety: regex should compile
        if op == "regex":
            try:
                re.compile(str(node.get("value")))
            except re.error as e:
                errors.append(f"{where}: invalid regex: {e}")
                return

    # exists: value is optional; ignore if present

def _validate_rule_dict(r: Dict[str, Any], file_path: Path, idx: int, errors: List[str]) -> None:
    prefix = f"{file_path} rule[{idx}]"

    rid = r.get("id")
    if not _is_nonempty_str(str(rid) if rid is not None else ""):
        errors.append(f"{prefix}: missing/invalid 'id'")

    title = r.get("title")
    if not _is_nonempty_str(title):
        errors.append(f"{prefix}: missing/invalid 'title'")

    sev = r.get("severity", "medium")
    if str(sev).lower() not in VALID_SEVERITIES:
        errors.append(f"{prefix}: invalid severity '{sev}' (allowed: {sorted(VALID_SEVERITIES)})")

    score = r.get("score", 0)
    try:
        s = int(score)
        if s < 0:
            errors.append(f"{prefix}: score must be >= 0 (got {s})")
    except Exception:
        errors.append(f"{prefix}: score must be an int (got {score!r})")

    match = r.get("match")
    if not isinstance(match, dict) or not match:
        errors.append(f"{prefix}: missing/invalid 'match' (must be a non-empty mapping)")
    else:
        _validate_match_tree(match, f"{prefix}.match", errors)

    emit = r.get("emit", {})
    if emit is not None:
        if not isinstance(emit, dict):
            errors.append(f"{prefix}: 'emit' must be a mapping if present")
        else:
            details = emit.get("details")
            if details is not None and not isinstance(details, dict):
                errors.append(f"{prefix}: emit.details must be a mapping if present")

    mods = r.get("score_modifiers", [])
    if mods is not None:
        if not isinstance(mods, list):
            errors.append(f"{prefix}: score_modifiers must be a list if present")
        else:
            for mi, mod in enumerate(mods):
                mp = f"{prefix}.score_modifiers[{mi}]"
                if not isinstance(mod, dict):
                    errors.append(f"{mp}: modifier must be a mapping")
                    continue
                when = mod.get("when")
                if when is None or not isinstance(when, dict):
                    errors.append(f"{mp}: missing/invalid 'when' (must be match tree mapping)")
                else:
                    _validate_match_tree(when, f"{mp}.when", errors)

                add = mod.get("add", 0)
                try:
                    int(add)
                except Exception:
                    errors.append(f"{mp}: 'add' must be int (got {add!r})")

                bump = mod.get("bump_severity", False)
                if not isinstance(bump, bool):
                    errors.append(f"{mp}: 'bump_severity' must be bool (got {bump!r})")

                sd = mod.get("set_details")
                if sd is not None and not isinstance(sd, dict):
                    errors.append(f"{mp}: 'set_details' must be a mapping if present")

    desc = r.get("description", "")
    if desc is not None and not isinstance(desc, str):
        errors.append(f"{prefix}: description must be a string if present")

    author = r.get("author", "")
    if author is not None and not isinstance(author, str):
        errors.append(f"{prefix}: author must be a string if present")

    created = r.get("created", "")
    if created is not None and not isinstance(created, str):
        errors.append(f"{prefix}: created must be a string if present")

    logsource = r.get("logsource", "")
    if logsource is not None and not isinstance(logsource, str):
        errors.append(f"{prefix}: logsource must be a string if present")

    tags = r.get("tags", [])
    if tags is not None:
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            errors.append(f"{prefix}: tags must be a list of strings if present")

# ----------------------------
# Emit + modifiers (Option B)
# ----------------------------

def _bump_severity(sev: str) -> str:
    ladder = ["low", "medium", "high", "critical"]
    s = (sev or "medium").lower()
    if s not in ladder:
        return sev
    idx = ladder.index(s)
    return ladder[min(idx + 1, len(ladder) - 1)]


_TEMPLATE_RE = re.compile(r"^\$\{([A-Za-z0-9_]+)\}$")


def _render_template(value: Any, event: Dict[str, Any]) -> Any:
    """
    If value is a string exactly like '${field}', replace with event[field].
    Otherwise return value unchanged.
    """
    if isinstance(value, str):
        m = _TEMPLATE_RE.match(value)
        if m:
            field = m.group(1)
            v = event.get(field)
            return "" if v is None else v
    return value


def _emit_details(rule: Rule, event: Dict[str, Any]) -> Dict[str, Any]:
    emit = rule.emit or {}
    details_tmpl = emit.get("details")

    # If rule doesn't define emit.details, fall back to your Phase-3-ish defaults.
    if not isinstance(details_tmpl, dict):
        return {
            "username": event.get("username"),
            "ip": event.get("ip"),
            "host": event.get("host"),
            "message": event.get("message"),
        }

    out: Dict[str, Any] = {}
    for k, v in details_tmpl.items():
        out[k] = _render_template(v, event)
    return out


def _apply_score_modifiers(alert: Dict[str, Any], event: Dict[str, Any], rule: Rule) -> None:
    for mod in rule.score_modifiers or []:
        if not isinstance(mod, dict):
            continue

        when = mod.get("when")
        if not isinstance(when, dict):
            continue

        if not _eval_node(when, event):
            continue

        add = int(mod.get("add", 0) or 0)
        alert["score"] = int(alert.get("score", 0) or 0) + add

        if bool(mod.get("bump_severity", False)):
            alert["severity"] = _bump_severity(str(alert.get("severity", "medium")))

        set_details = mod.get("set_details")
        if isinstance(set_details, dict):
            details = alert.get("details") or {}
            if not isinstance(details, dict):
                details = {}
            details.update(set_details)
            alert["details"] = details

        reason = mod.get("reason")
        if reason:
            details = alert.get("details") or {}
            if not isinstance(details, dict):
                details = {}
            details.setdefault("modifier_reasons", []).append(str(reason))
            alert["details"] = details


# ----------------------------
# Runner
# ----------------------------

def run_rules(events: List[Dict[str, Any]], rules: List[Rule]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    for ev in events:
        for rule in rules:
            if not rule.enabled:
                continue

            if _eval_node(rule.match, ev):
                alert = {
                    "rule_id": rule.id,
                    "severity": rule.severity,
                    "title": rule.title,
                    "timestamp": ev.get("timestamp"),
                    "details": _emit_details(rule, ev),
                    "mitre": rule.mitre,
                    "score": rule.score,
                    "status": "new",
                    "correlation_id": None,
                    "rule": {
                        "description": getattr(rule, "description", ""),
                        "author": getattr(rule, "author", ""),
                        "created": getattr(rule, "created", ""),
                        "logsource": getattr(rule, "logsource", ""),
                        "tags": getattr(rule, "tags", []) or [],
                    },
                }

                _apply_score_modifiers(alert, ev, rule)
                alerts.append(alert)

    return alerts