from __future__ import annotations

from soc_forge.ui.screen import screen_output
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb,
    render_message_block, render_metadata, render_panel, resolve_terminal_width,
)

CAUTION = (
    "Temporal proximity across Investigations does not establish a shared "
    "attack, attacker, campaign, or causal relationship."
)


def _screen(panels, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=width, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "TEMPORAL ANALYSIS"),
                          width=width, ansi=ansi, unicode=unicode), *panels,
    ))


def render_temporal_menu(*, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return _screen((render_panel((
        "[1] Chronological Activity", "[2] Recent Activity",
        "[3] Filter by Investigation", "[4] Filter by Source Type",
        "[5] Filter by ATT&CK", "[0] Back",
    ), title="TEMPORAL ANALYSIS", width=width, ansi=ansi, unicode=unicode),),
        width=width, ansi=ansi, unicode=unicode)


def render_temporal(result, *, recent=False, label=None, width=None,
                    ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    state = render_panel(render_metadata((
        ("Mode", render_badge("summary_mode", result.mode, ansi=ansi)),
        ("Timed Entries", result.timed_entry_count),
        ("Untimed Entries", result.untimed_entry_count),
        ("Machine Entries", result.machine_entry_count),
        ("Analyst Entries", result.analyst_entry_count),
        ("Investigations Represented", result.investigations_represented),
        ("First Activity", result.first_timestamp or "None"),
        ("Last Activity", result.last_timestamp or "None"),
        ("View", label or ("Recent activity" if recent else "Cross-state chronological activity")),
    ), width=width - 4, ansi=ansi), title="TEMPORAL STATE",
        width=width, ansi=ansi, unicode=unicode)
    entries = tuple(reversed(result.entries[-10:])) if recent else result.entries
    rows = []
    for row in entries:
        rows.extend((
            f"{row.timestamp} [{row.attribution.upper()}] {row.source_type.upper()}",
            f"{row.title} | Investigation: {row.investigation_id or 'None'}",
            "",
        ))
    if not rows:
        rows = render_message_block(
            "empty", "No timestamped activity matched this view.",
            width=width - 4, ansi=ansi,
        ).splitlines()
    panels = [state, render_panel(rows, title=(
        "RECENT ACTIVITY" if recent else "CHRONOLOGICAL ACTIVITY"
    ), width=width, ansi=ansi, unicode=unicode)]
    if result.untimed_entries:
        untimed = tuple(
            f"[{row.attribution.upper()}] {row.source_type.upper()} {row.source_id} | "
            f"{row.title} | Investigation: {row.investigation_id or 'None'}"
            for row in result.untimed_entries
        )
        panels.append(render_panel(untimed, title="UNTIMED ACTIVITY",
                                   width=width, ansi=ansi, unicode=unicode))
    caution = render_message_block(
        "warning", CAUTION, width=width - 4, ansi=ansi
    ).splitlines()
    panels.append(render_panel(caution, title="INTERPRETATION", width=width,
                               ansi=ansi, unicode=unicode))
    return _screen(panels, width=width, ansi=ansi, unicode=unicode)


class TemporalAnalysisConsoleController:
    SOURCE_TYPES = (
        "event", "alert", "case", "reconstruction", "evidence",
        "hypothesis", "decision", "finding", "response_action",
    )

    def __init__(self, service, *, input_func=input, output_func=print) -> None:
        self.service = service
        self.input_func = input_func
        self.output_func = output_func
        self.screen_output = screen_output(output_func)

    def run(self):
        while True:
            self.screen_output(render_temporal_menu())
            choice = self.input_func("\nSelect option: ").strip()
            if choice == "0":
                return
            if choice == "1":
                self._show(self.service.analyze())
            elif choice == "2":
                self._show(self.service.analyze(), recent=True)
            elif choice == "3":
                value = self.input_func("\nInvestigation ID: ").strip()
                self._show(self.service.analyze(investigation_id=value),
                           label=f"Cross-state temporal view filtered to {value}")
            elif choice == "4":
                value = self.input_func(
                    "\nSource type (" + ", ".join(self.SOURCE_TYPES) + "): "
                ).strip().casefold()
                if value not in self.SOURCE_TYPES:
                    self.output_func("ERROR: Unsupported source type.")
                else:
                    self._show(self.service.analyze(source_type=value),
                               label=f"Source type: {value}")
            elif choice == "5":
                kind = self.input_func("\nFilter by tactic or technique: ").strip().casefold()
                value = self.input_func("\nExact tactic or technique ID: ").strip()
                if kind == "tactic":
                    result = self.service.analyze(tactic=value)
                elif kind == "technique":
                    result = self.service.analyze(technique_id=value)
                else:
                    self.output_func("ERROR: Select tactic or technique.")
                    continue
                self._show(result, label=f"ATT&CK {kind}: {value}")
            else:
                self.output_func("ERROR: Invalid option.")

    def _show(self, result, *, recent=False, label=None):
        self.screen_output(render_temporal(result, recent=recent, label=label))
        self.input_func("\nPress Enter to go back...")
