from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.detection_coverage import (
    DetectionCoverageService,
    DetectionCoverageSummary,
    DetectionGap,
    DetectionGapService,
    DetectionGapSummary,
)
from soc_forge.detection_engineering import (
    DetectionEngineeringService,
    RuleCatalogEntry,
)
from soc_forge.menus.detection_engineering import render_rule_detail
from soc_forge.menus.rule_explainability import render_rule_explanation
from soc_forge.rule_explainability import RuleExplanationService
from soc_forge.ui.terminal import (
    render_application_header,
    render_breadcrumb,
    render_empty_state,
    render_error,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


def _screen(
    breadcrumb: tuple[str, ...],
    panels: Iterable[str],
    *,
    width: int | None,
    ansi: bool | None,
    unicode: bool,
) -> str:
    resolved = resolve_terminal_width(width)
    return "\n".join(
        (
            render_application_header(
                width=resolved, ansi=ansi, unicode=unicode
            ),
            render_breadcrumb(
                breadcrumb,
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            *panels,
        )
    )


def render_coverage_menu(
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    panel = render_panel(
        (
            "[1] Coverage Summary",
            "[2] View by ATT&CK Tactic",
            "[3] View by ATT&CK Technique",
            "[4] View Rules Without ATT&CK Mapping",
            "[0] Back",
        ),
        title="DETECTION COVERAGE",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return _screen(
        ("SOC-FORGE", "DETECTION", "COVERAGE"),
        (panel,),
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )


def render_coverage_summary(
    summary: DetectionCoverageSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    panel = render_panel(
        render_metadata(
            (
                ("Rules", summary.total_rules),
                ("Enabled rules", summary.enabled_rules),
                ("Disabled rules", summary.disabled_rules),
                (
                    "Rules with ATT&CK mapping",
                    summary.rules_with_attack_mapping,
                ),
                (
                    "Rules without mapping",
                    summary.rules_without_attack_mapping,
                ),
                (
                    "ATT&CK tactics represented",
                    len(summary.tactics),
                ),
                (
                    "ATT&CK techniques represented",
                    len(summary.techniques),
                ),
            ),
            width=resolved - 4,
            ansi=ansi,
            wrap_values=True,
        ),
        title="COVERAGE SUMMARY",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    note = render_panel(
        (
            "Counts describe explicit mappings in the current loaded ruleset.",
            "No global ATT&CK completeness percentage is calculated.",
        ),
        title="SCOPE",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return _screen(
        ("SOC-FORGE", "DETECTION", "COVERAGE", "SUMMARY"),
        (panel, note),
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )


def render_tactic_coverage(
    summary: DetectionCoverageSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> tuple[str, tuple[str, ...]]:
    resolved = resolve_terminal_width(width)
    rows = []
    rule_ids = []
    for tactic in summary.tactics:
        rows.append(tactic.tactic.upper())
        rows.append(
            "Techniques: "
            + (", ".join(tactic.technique_keys) or "None explicitly identified")
        )
        rows.append("Rules: " + ", ".join(tactic.rule_ids))
        rows.append("")
        rule_ids.extend(tactic.rule_ids)
    panel = render_panel(
        rows
        or (
            render_empty_state(
                "No explicit ATT&CK tactics.", width=resolved - 4, ansi=ansi
            ),
        ),
        title="COVERAGE BY ATT&CK TACTIC",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return (
        _screen(
            ("SOC-FORGE", "DETECTION", "COVERAGE", "TACTICS"),
            (panel,),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        tuple(sorted(set(rule_ids))),
    )


def render_technique_coverage(
    summary: DetectionCoverageSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> tuple[str, tuple[str, ...]]:
    resolved = resolve_terminal_width(width)
    rows = []
    rule_ids = []
    for technique in summary.techniques:
        name = " - ".join(
            value
            for value in (
                technique.technique_id,
                technique.technique_name,
            )
            if value
        )
        rows.append(name or technique.technique_key)
        rows.append("Tactics: " + (", ".join(technique.tactics) or "None"))
        rows.append("Enabled rules: " + (", ".join(technique.enabled_rule_ids) or "None"))
        rows.append("Disabled rules: " + (", ".join(technique.disabled_rule_ids) or "None"))
        rows.append("")
        rule_ids.extend(technique.rule_ids)
    panel = render_panel(
        rows
        or (
            render_empty_state(
                "No explicit ATT&CK techniques.", width=resolved - 4, ansi=ansi
            ),
        ),
        title="COVERAGE BY ATT&CK TECHNIQUE",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return (
        _screen(
            ("SOC-FORGE", "DETECTION", "COVERAGE", "TECHNIQUES"),
            (panel,),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        tuple(sorted(set(rule_ids))),
    )


def render_unmapped_rules(
    summary: DetectionCoverageSummary,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> tuple[str, tuple[str, ...]]:
    resolved = resolve_terminal_width(width)
    rules = tuple(
        rule for rule in summary.rules if not rule.has_attack_mapping
    )
    rows = tuple(
        f"{rule.rule_id} - {rule.title} "
        f"{'[ENABLED]' if rule.enabled else '[DISABLED]'}"
        for rule in rules
    )
    panel = render_panel(
        rows
        or (
            render_empty_state(
                "All loaded rules have explicit ATT&CK metadata.",
                width=resolved - 4,
                ansi=ansi,
            ),
        ),
        title="RULES WITHOUT ATT&CK MAPPING",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return (
        _screen(
            ("SOC-FORGE", "DETECTION", "COVERAGE", "UNMAPPED RULES"),
            (panel,),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        tuple(rule.rule_id for rule in rules),
    )


def render_gaps_menu(
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    panel = render_panel(
        (
            "[1] View All Gaps",
            "[2] Unmapped Rules",
            "[3] Disabled Coverage Gaps",
            "[0] Back",
        ),
        title="DETECTION GAPS",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return _screen(
        ("SOC-FORGE", "DETECTION", "GAPS"),
        (panel,),
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )


def render_gaps(
    summary: DetectionGapSummary,
    gaps: Iterable[DetectionGap] | None = None,
    *,
    title: str = "DETECTION GAPS",
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> tuple[str, tuple[str, ...]]:
    resolved = resolve_terminal_width(width)
    selected = tuple(summary.gaps if gaps is None else gaps)
    rows = []
    rule_ids = []
    for gap in selected:
        rows.extend(
            (
                gap.gap_id,
                gap.title,
                f"Reason: {gap.reason}",
                "Rules: " + (", ".join(gap.related_rule_ids) or "None"),
                "",
            )
        )
        rule_ids.extend(gap.related_rule_ids)
    gaps_panel = render_panel(
        rows
        or (
            render_empty_state(
                "No explicit gaps in this category.",
                width=resolved - 4,
                ansi=ansi,
            ),
        ),
        title=title,
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    scope = render_panel(
        render_metadata(
            (
                ("Expected baseline configured", "No"),
                ("Scope", summary.scope_note),
            ),
            width=resolved - 4,
            ansi=ansi,
            wrap_values=True,
        ),
        title="GAP ANALYSIS LIMITS",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return (
        _screen(
            ("SOC-FORGE", "DETECTION", "GAPS", title),
            (gaps_panel, scope),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        tuple(sorted(set(rule_ids))),
    )


class DetectionCoverageConsoleController:
    def __init__(
        self,
        coverage_service: DetectionCoverageService,
        gap_service: DetectionGapService,
        catalog_service: DetectionEngineeringService,
        explanation_service: RuleExplanationService,
        *,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[], None] = lambda: None,
        pause_func: Callable[[], None] = lambda: None,
    ):
        self.coverage_service = coverage_service
        self.gap_service = gap_service
        self.catalog_service = catalog_service
        self.explanation_service = explanation_service
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func
        self._rules_by_id = {}

    def run_coverage(self) -> None:
        loaded = self._load()
        if loaded is None:
            return
        summary, entries = loaded
        while True:
            self.screen()
            self.output(render_coverage_menu())
            choice = self.input("Select option: ").strip()
            if choice == "0":
                return
            if choice == "1":
                self._simple_view(render_coverage_summary(summary))
            elif choice == "2":
                self._rule_view(*render_tactic_coverage(summary), entries)
            elif choice == "3":
                self._rule_view(*render_technique_coverage(summary), entries)
            elif choice == "4":
                self._rule_view(*render_unmapped_rules(summary), entries)
            else:
                self.output(render_error("Invalid coverage selection."))
                self.pause()

    def run_gaps(self) -> None:
        loaded = self._load()
        if loaded is None:
            return
        coverage, entries = loaded
        gaps = self.gap_service.summarize(coverage)
        while True:
            self.screen()
            self.output(render_gaps_menu())
            choice = self.input("Select option: ").strip()
            if choice == "0":
                return
            if choice == "1":
                selected = gaps.gaps
                title = "ALL EXPLICIT GAPS"
            elif choice == "2":
                selected = tuple(
                    gap for gap in gaps.gaps
                    if gap.gap_type == "UNMAPPED_RULE"
                )
                title = "UNMAPPED RULE GAPS"
            elif choice == "3":
                selected = tuple(
                    gap for gap in gaps.gaps
                    if gap.gap_type == "DISABLED_COVERAGE"
                )
                title = "DISABLED COVERAGE GAPS"
            else:
                self.output(render_error("Invalid gap selection."))
                self.pause()
                continue
            self._rule_view(
                *render_gaps(gaps, selected, title=title),
                entries,
            )

    def _load(
        self,
    ) -> tuple[
        DetectionCoverageSummary, dict[str, RuleCatalogEntry]
    ] | None:
        try:
            rules = self.coverage_service.load_rules()
            coverage = self.coverage_service.summarize(rules)
            self._rules_by_id = {rule.id: rule for rule in rules}
            entries = {
                entry.rule_id: entry
                for entry in self.catalog_service.rule_catalog(rules)
            }
        except (OSError, ValueError) as exc:
            self.output(
                render_error(f"Detection coverage unavailable: {exc}")
            )
            self.pause()
            return None
        return coverage, entries

    def _simple_view(self, output: str) -> None:
        while True:
            self.screen()
            self.output(output)
            if self.input("[0] Back: ").strip() == "0":
                return
            self.output(render_error("Invalid option."))
            self.pause()

    def _rule_view(
        self,
        output: str,
        rule_ids: tuple[str, ...],
        entries: dict[str, RuleCatalogEntry],
    ) -> None:
        while True:
            self.screen()
            numbered = tuple(
                rule_id for rule_id in rule_ids if rule_id in entries
            )
            rule_menu = render_panel(
                tuple(
                    f"[{index}] Open {rule_id}"
                    for index, rule_id in enumerate(numbered, start=1)
                )
                or ("[0] Back",),
                title="RULE DRILL-DOWN",
            )
            self.output(output + "\n" + rule_menu)
            choice = self.input("[0] Back or rule number: ").strip()
            if choice == "0":
                return
            if (
                not choice.isdigit()
                or not 1 <= int(choice) <= len(numbered)
            ):
                self.output(render_error("Invalid rule selection."))
                self.pause()
                continue
            entry = entries[numbered[int(choice) - 1]]
            while True:
                self.screen()
                self.output(render_rule_detail(entry))
                action = self.input(
                    "[1] Explain Rule  [0] Back: "
                ).strip()
                if action == "0":
                    break
                if action != "1":
                    self.output(render_error("Invalid rule action."))
                    self.pause()
                    continue
                try:
                    explanation = self.explanation_service.explain(
                        self._rules_by_id[entry.rule_id]
                    )
                except (KeyError, OSError, ValueError) as exc:
                    self.output(
                        render_error(
                            f"Rule Explainability unavailable: {exc}"
                        )
                    )
                    self.pause()
                    continue
                while True:
                    self.screen()
                    self.output(render_rule_explanation(explanation))
                    if self.input("[0] Back: ").strip() == "0":
                        break
                    self.output(render_error("Invalid option."))
                    self.pause()
