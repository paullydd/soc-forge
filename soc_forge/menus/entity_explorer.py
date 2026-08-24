from __future__ import annotations

from soc_forge.ui.screen import screen_output
from soc_forge.entity_explorer import ENTITY_TYPES, EntityExplorerResult, EntityExplorerService
from soc_forge.investigations.query_models import InvalidEntityValueError
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb, render_empty_state,
    render_metadata, render_panel, resolve_terminal_width,
)

TYPE_LABELS = {"host": "Host", "user": "User", "ip": "IP Address", "process": "Process"}


def _screen(panels, *, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=resolved, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "ENTITY EXPLORER"),
                          width=resolved, ansi=ansi, unicode=unicode),
        *panels,
    ))


def render_entity_type_menu(*, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return _screen((render_panel((
        "[1] Host", "[2] User", "[3] IP Address", "[4] Process", "[0] Back",
    ), title="ENTITY TYPE", width=resolved, ansi=ansi, unicode=unicode),),
        width=resolved, ansi=ansi, unicode=unicode)


def render_entity_result(result: EntityExplorerResult, *, width=None,
                         ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    summary = render_panel(render_metadata((
        ("Entity", result.query), ("Type", result.entity_type.upper()),
        ("Mode", render_badge("summary_mode", result.mode, ansi=ansi)),
        ("Observations", result.observation_count), ("Alerts", result.alert_count),
        ("Investigations", result.investigation_count),
        ("Findings", result.finding_count),
        ("Response Actions", result.response_action_count),
        ("Cases", result.case_count),
    ), width=resolved - 4, ansi=ansi), title="ENTITY",
        width=resolved, ansi=ansi, unicode=unicode)
    attack_rows = [
        *(f"TACTIC | {row.value} | Observations {row.observation_count}"
          for row in result.attack_tactics),
        *(f"TECHNIQUE | {row.value} | Observations {row.observation_count}"
          for row in result.attack_techniques),
    ]
    attack = render_panel(
        attack_rows or (render_empty_state("No explicit ATT&CK mappings.",
                                           width=resolved - 4, ansi=ansi),),
        title="ATT&CK ACTIVITY", width=resolved, ansi=ansi, unicode=unicode)
    investigation_rows = result.investigation_ids or (
        render_empty_state("No durable Investigation membership.",
                           width=resolved - 4, ansi=ansi),)
    investigations = render_panel((
        *investigation_rows,
        "Shared entity observations do not establish that Investigations are part of the same attack.",
    ), title="INVESTIGATIONS", width=resolved, ansi=ansi, unicode=unicode)
    related = render_panel(
        tuple(f"{row.entity_type.upper()} | {row.entity_value} | "
              f"Observed together {row.observation_count} times"
              for row in result.related_entities)
        or (render_empty_state("No structured co-observed entities.",
                               width=resolved - 4, ansi=ansi),),
        title="RELATED ENTITIES", width=resolved, ansi=ansi, unicode=unicode)
    observations = render_panel(
        tuple(f"{row.timestamp or 'Timestamp unavailable'} "
              f"[{row.origin.upper()}] {row.source_type.upper()} | {row.title}"
              + (f" | {row.investigation_id}" if row.investigation_id else "")
              for row in result.observations)
        or (render_empty_state("No observations found for this entity.",
                               width=resolved - 4, ansi=ansi),),
        title="RECENT OBSERVATIONS", width=resolved, ansi=ansi, unicode=unicode)
    scope = render_panel((
        "Exact structured-field matches only. No prose extraction, fuzzy matching, or enrichment.",
        "Repeated observations do not establish a shared attacker or campaign.",
    ), title="INTERPRETATION", width=resolved, ansi=ansi, unicode=unicode)
    return _screen((summary, attack, investigations, related, observations, scope),
                   width=resolved, ansi=ansi, unicode=unicode)


class EntityExplorerConsoleController:
    def __init__(self, service: EntityExplorerService, *, input_func=input,
                 output_func=print) -> None:
        self.service = service
        self.input_func = input_func
        self.output_func = output_func
        self.screen_output = screen_output(output_func)

    def run(self) -> None:
        while True:
            self.screen_output(render_entity_type_menu())
            choice = self.input_func("\nSelect entity type: ").strip()
            if choice == "0":
                return
            if choice not in {"1", "2", "3", "4"}:
                self.output_func("ERROR: Invalid option.")
                continue
            entity_type = ENTITY_TYPES[int(choice) - 1]
            value = self.input_func(
                f"Exact {TYPE_LABELS[entity_type]} value: "
            ).strip()
            if not value:
                continue
            try:
                result = self.service.search(entity_type, value)
            except InvalidEntityValueError as exc:
                self.output_func(f"ERROR: {exc}")
                continue
            self.screen_output(render_entity_result(result))
            self.input_func("\nPress Enter to go back...")
