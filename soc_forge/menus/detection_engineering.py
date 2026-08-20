from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.detection_engineering import (
    DetectionEngineeringService,
    DetectionOverview,
    RuleCatalogEntry,
)
from soc_forge.menus.rule_explainability import (
    render_rule_explanation,
    render_rule_explanation_catalog,
)
from soc_forge.rule_explainability import (
    RuleExplanation,
    RuleExplanationService,
)
from soc_forge.ui.terminal import (
    render_application_header,
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_error,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


def render_detection_overview(
    overview: DetectionOverview,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    state = render_panel(
        render_metadata(
            (
                ("Total Rules", overview.total_rules),
                ("Enabled", overview.enabled_rules),
                ("Disabled", overview.disabled_rules),
                ("ATT&CK Tactics", overview.tactics_count),
                ("ATT&CK Techniques", overview.techniques_count),
                ("Recent Alerts", overview.recent_alert_count),
                ("Distinct Triggered Rules", overview.recently_triggered_rule_count),
                ("Last Detection", overview.last_detection_timestamp or "Unavailable"),
            ),
            width=resolved - 4,
            ansi=ansi,
        ),
        title="DETECTION STATE",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    if overview.recent_detections:
        recent_lines = tuple(
            f"{item.rule_id}  {item.title}  {item.timestamp}"
            for item in overview.recent_detections
        )
    else:
        recent_lines = (
            render_empty_state(
                "No recent detections available.", width=resolved - 4, ansi=ansi
            ),
        )
    recent = render_panel(
        recent_lines,
        title="RECENT DETECTIONS",
        width=resolved,
        ansi=ansi,
        unicode=unicode,
    )
    return "\n".join(
        (
            render_application_header(width=resolved, ansi=ansi, unicode=unicode),
            render_breadcrumb(
                ("SOC-FORGE", "DETECTION", "OVERVIEW"),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            state,
            recent,
        )
    )


def render_rule_catalog(
    entries: Iterable[RuleCatalogEntry],
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = []
    for index, entry in enumerate(entries, start=1):
        mappings = "; ".join(
            mapping.presentation for mapping in entry.attack_mappings
        ) or "None"
        rows.extend(
            (
                f"[{index}] {entry.rule_id} - {entry.title}",
                (
                    f"{'[ENABLED]' if entry.enabled else '[DISABLED]'} "
                    f"{render_badge('severity', entry.severity, ansi=ansi)}"
                ),
                f"ATT&CK: {mappings}",
                "",
            )
        )
    if not rows:
        rows.append(render_empty_state("No rules available.", width=resolved - 4, ansi=ansi))
    return "\n".join(
        (
            render_application_header(width=resolved, ansi=ansi, unicode=unicode),
            render_breadcrumb(
                ("SOC-FORGE", "DETECTION", "RULE CATALOG"),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                rows, title="RULE CATALOG", width=resolved, ansi=ansi, unicode=unicode
            ),
        )
    )


def render_rule_detail(
    entry: RuleCatalogEntry,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    attack = "; ".join(
        mapping.presentation for mapping in entry.attack_mappings
    ) or "None"
    rows = (
        ("Rule ID", entry.rule_id),
        ("Title", entry.title),
        ("Enabled", "Yes" if entry.enabled else "No"),
        ("Severity", entry.severity.upper()),
        ("Score", entry.score),
        ("Description", entry.description or "Not provided"),
        ("ATT&CK", attack),
        ("Tags", ", ".join(entry.tags) or "None"),
        ("Log source", entry.logsource or "Not provided"),
        ("Author", entry.author or "Not provided"),
        ("Created", entry.created or "Not provided"),
        ("Match metadata", entry.match_metadata),
        ("Emit metadata", entry.emit_metadata),
        ("Aggregate metadata", entry.aggregate_metadata),
        ("Score modifiers", entry.score_modifiers_metadata),
    )
    return "\n".join(
        (
            render_application_header(width=resolved, ansi=ansi, unicode=unicode),
            render_breadcrumb(
                ("SOC-FORGE", "DETECTION", "RULE CATALOG", entry.rule_id),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                render_metadata(
                    rows, width=resolved - 4, ansi=ansi, wrap_values=True
                ),
                title="RULE DETAIL",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
        )
    )


class DetectionEngineeringConsoleController:
    def __init__(
        self,
        service: DetectionEngineeringService,
        *,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[], None] = lambda: None,
        pause_func: Callable[[], None] = lambda: None,
        explanation_service: RuleExplanationService | None = None,
    ):
        self.service = service
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func
        self.explanation_service = explanation_service or RuleExplanationService(
            rules_path=service.rules_path,
            rule_loader=service.rule_loader,
        )

    def show_overview(self) -> None:
        self.screen()
        try:
            self.output(render_detection_overview(self.service.overview()))
        except (OSError, ValueError) as exc:
            self.output(render_error(f"Detection Overview unavailable: {exc}"))
        self.pause()

    def run_rule_catalog(self) -> None:
        try:
            entries = self.service.rule_catalog()
        except (OSError, ValueError) as exc:
            self.screen()
            self.output(render_error(f"Rule Catalog unavailable: {exc}"))
            self.pause()
            return
        while True:
            self.screen()
            self.output(render_rule_catalog(entries))
            choice = self.input("Select rule (blank to return): ").strip()
            if choice == "":
                return
            if not choice.isdigit() or not 1 <= int(choice) <= len(entries):
                self.output(render_error("Invalid rule selection."))
                self.pause()
                continue
            entry = entries[int(choice) - 1]
            while True:
                self.screen()
                self.output(render_rule_detail(entry))
                action = self.input(
                    "Select option ([1] Explain Rule, blank to return): "
                ).strip()
                if action == "":
                    break
                if action != "1":
                    self.output(render_error("Invalid rule detail selection."))
                    self.pause()
                    continue
                try:
                    explanation = self.explanation_service.explanation_for(
                        entry.rule_id
                    )
                except (OSError, ValueError) as exc:
                    self.output(
                        render_error(f"Rule Explainability unavailable: {exc}")
                    )
                    self.pause()
                    continue
                self._show_explanation(explanation)

    def run_rule_explainability(self) -> None:
        try:
            explanations = self.explanation_service.explanations()
        except (OSError, ValueError) as exc:
            self.screen()
            self.output(
                render_error(f"Rule Explainability unavailable: {exc}")
            )
            self.pause()
            return
        while True:
            self.screen()
            self.output(render_rule_explanation_catalog(explanations))
            choice = self.input("Select rule (blank to return): ").strip()
            if choice == "":
                return
            if (
                not choice.isdigit()
                or not 1 <= int(choice) <= len(explanations)
            ):
                self.output(render_error("Invalid rule selection."))
                self.pause()
                continue
            self._show_explanation(explanations[int(choice) - 1])

    def _show_explanation(self, explanation: RuleExplanation) -> None:
        while True:
            self.screen()
            self.output(render_rule_explanation(explanation))
            choice = self.input("[0] Back: ").strip()
            if choice == "0":
                return
            self.output(render_error("Invalid option."))
            self.pause()
