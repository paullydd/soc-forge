from __future__ import annotations

from collections import Counter
from typing import Dict, Iterable, List, Tuple

from soc_forge.rules.engine import Rule


def mitre_coverage_by_tactic(rules: Iterable[Rule], *, enabled_only: bool = True) -> List[Tuple[str, int]]:
    """
    Returns a sorted list of (tactic, count) where count is the number of rules
    that declare that tactic in their mitre list.
    """
    c: Counter[str] = Counter()

    for r in rules:
        if enabled_only and not r.enabled:
            continue

        seen_in_rule = set()
        for m in r.mitre or []:
            tactic = (m.get("tactic") or "").strip()
            if not tactic:
                continue
            # avoid counting the same tactic twice for one rule
            if tactic not in seen_in_rule:
                c[tactic] += 1
                seen_in_rule.add(tactic)

    # sort by count desc, then name asc
    return sorted(c.items(), key=lambda x: (-x[1], x[0]))


def format_coverage_table(rows: List[Tuple[str, int]]) -> str:
    if not rows:
        return "MITRE Coverage\n\n(no tactics found)\n"

    width = max(len(t) for t, _ in rows)
    lines = ["MITRE Coverage", ""]
    for tactic, n in rows:
        dots = "." * max(2, 20 - len(tactic))  # simple alignment
        lines.append(f"{tactic:<{width}} {dots} {n}")
    return "\n".join(lines) + "\n"
