from __future__ import annotations

from soc_forge.ui.screen import screen_output
from soc_forge.cross_investigation import (
    CAUTION, CrossInvestigationRelationship, CrossInvestigationSummary,
)
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb, render_empty_state,
    render_message_block, render_metadata, render_panel, resolve_terminal_width,
)

EMPTY = (
    "No shared structured observations were found across Investigations. "
    "This only means the current supported structured overlap rules found no "
    "relationship."
)


def _screen(panels, *, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=resolved, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "CROSS-INVESTIGATION"),
                          width=resolved, ansi=ansi, unicode=unicode),
        *panels,
    ))


def render_cross_investigation_menu(*, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return _screen((render_panel((
        "[1] Overview", "[2] Shared Entities", "[3] Shared ATT&CK Tactics",
        "[4] Shared ATT&CK Techniques", "[5] Relationship Detail", "[0] Back",
    ), title="CROSS-INVESTIGATION ANALYSIS", width=resolved,
        ansi=ansi, unicode=unicode),), width=resolved, ansi=ansi, unicode=unicode)


def render_overview(summary: CrossInvestigationSummary, *, width=None,
                    ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    state = render_panel(render_metadata((
        ("Mode", render_badge("summary_mode", summary.mode, ansi=ansi)),
        ("Relationships", summary.relationship_count),
        ("Investigations Represented", summary.investigation_count),
        ("Shared Entities", summary.shared_entity_count),
        ("Shared Tactics", summary.shared_tactic_count),
        ("Shared Techniques", summary.shared_technique_count),
    ), width=resolved - 4, ansi=ansi), title="CROSS-INVESTIGATION STATE",
        width=resolved, ansi=ansi, unicode=unicode)
    rows = tuple(
        f"{row.display_value} | Investigations {len(row.investigation_ids)} | "
        f"Observations {row.observation_count}"
        for row in summary.relationships[:10]
    ) or tuple(render_message_block("empty", EMPTY, width=resolved - 4, ansi=ansi).splitlines())
    scope_rows = (
        *render_message_block("info", "Ordering: Investigation count, observation count, type, then normalized key.", width=resolved - 4, ansi=ansi).splitlines(),
        *render_message_block("warning", CAUTION, width=resolved - 4, ansi=ansi).splitlines(),
    )
    scope = render_panel(scope_rows, title="INTERPRETATION", width=resolved,
                         ansi=ansi, unicode=unicode)
    return _screen((state, render_panel(rows, title="TOP SHARED OBSERVATIONS",
                                        width=resolved, ansi=ansi,
                                        unicode=unicode), scope),
                   width=resolved, ansi=ansi, unicode=unicode)


def render_relationships(summary, relationship_type, title, *, width=None,
                         ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    matching = tuple(
        row for row in summary.relationships
        if row.relationship_type == relationship_type
    )
    rows = []
    last_group = None
    for index, row in enumerate(matching, 1):
        group = row.entity_type.upper() if row.entity_type else title
        if group != last_group:
            rows.extend((group, ""))
            last_group = group
        rows.extend((
            f"[{index}] {row.display_value}",
            f"Investigations {len(row.investigation_ids)} | "
            f"Observations {row.observation_count} | "
            f"[MACHINE] {row.machine_observation_count} | "
            f"[ANALYST] {row.analyst_observation_count}",
            "",
        ))
    if not rows:
        rows = render_message_block("empty", EMPTY, width=resolved - 4, ansi=ansi).splitlines()
    return _screen((render_panel(rows, title=title, width=resolved, ansi=ansi,
                                 unicode=unicode),),
                   width=resolved, ansi=ansi, unicode=unicode)



def render_relationship_index(summary, *, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    rows = tuple(
        f"[{index}] {row.display_value} | {row.relationship_type.replace('_', ' ')}"
        for index, row in enumerate(summary.relationships, 1)
    ) or tuple(render_message_block("empty", EMPTY, width=resolved - 4, ansi=ansi).splitlines())
    return _screen((render_panel(rows, title="ALL RELATIONSHIPS", width=resolved,
                                 ansi=ansi, unicode=unicode),),
                   width=resolved, ansi=ansi, unicode=unicode)

def render_relationship_detail(relationship: CrossInvestigationRelationship, *,
                               width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    detail = render_panel(render_metadata((
        ("Type", relationship.relationship_type.replace("_", " ").title()),
        ("Value", relationship.display_value),
        ("Relationship ID", relationship.relationship_id),
        ("Investigations", len(relationship.investigation_ids)),
        ("Observations", relationship.observation_count),
        ("Machine", relationship.machine_observation_count),
        ("Analyst", relationship.analyst_observation_count),
    ), width=resolved - 4, ansi=ansi), title="RELATIONSHIP DETAIL",
        width=resolved, ansi=ansi, unicode=unicode)
    investigations = render_panel(
        relationship.investigation_ids, title="INVESTIGATIONS",
        width=resolved, ansi=ansi, unicode=unicode,
    )
    observations = tuple(
        f"{row.timestamp or 'Timestamp unavailable'} "
        f"[{row.attribution.upper()}] {row.source_type.upper()} {row.source_id} | "
        f"{row.investigation_id} | {row.title}"
        for row in relationship.recent_observations
    ) or (render_empty_state("No supporting observations.",
                             width=resolved - 4, ansi=ansi),)
    limitation_rows = (
        *render_message_block("info", relationship.explanation, width=resolved - 4, ansi=ansi).splitlines(),
        *render_message_block("warning", " ".join(relationship.limitations), width=resolved - 4, ansi=ansi).splitlines(),
    )
    limitation = render_panel(limitation_rows, title="EXPLANATION AND LIMITATION",
                              width=resolved, ansi=ansi, unicode=unicode)
    return _screen((detail, investigations, render_panel(
        observations, title="RECENT SUPPORTING OBSERVATIONS", width=resolved,
        ansi=ansi, unicode=unicode), limitation),
        width=resolved, ansi=ansi, unicode=unicode)


class CrossInvestigationConsoleController:
    def __init__(self, service, *, input_func=input, output_func=print) -> None:
        self.service = service
        self.input_func = input_func
        self.output_func = output_func
        self.screen_output = screen_output(output_func)

    def run(self) -> None:
        while True:
            self.screen_output(render_cross_investigation_menu())
            choice = self.input_func("\nSelect option: ").strip()
            if choice == "0":
                return
            summary = self.service.summarize()
            if choice == "1":
                self.screen_output(render_overview(summary))
                self.input_func("\nPress Enter to go back...")
            elif choice in ("2", "3", "4"):
                kinds = {
                    "2": ("shared_entity", "SHARED ENTITIES"),
                    "3": ("shared_attack_tactic", "SHARED ATT&CK TACTICS"),
                    "4": ("shared_attack_technique", "SHARED ATT&CK TECHNIQUES"),
                }
                kind, title = kinds[choice]
                self.screen_output(render_relationships(summary, kind, title))
                self._select(summary, kind)
            elif choice == "5":
                self._show_detail(summary)
            else:
                self.output_func("ERROR: Invalid option.")

    def _select(self, summary, kind):
        rows = tuple(row for row in summary.relationships
                     if row.relationship_type == kind)
        value = self.input_func(
            "\nRelationship number for detail, or Enter to go back: "
        ).strip()
        if value.isdigit() and 1 <= int(value) <= len(rows):
            self.screen_output(render_relationship_detail(rows[int(value) - 1]))
            self.input_func("\nPress Enter to go back...")

    def _show_detail(self, summary):
        self.screen_output(render_relationship_index(summary))
        value = self.input_func(
            "\nRelationship number for detail, or Enter to go back: "
        ).strip()
        if value.isdigit() and 1 <= int(value) <= len(summary.relationships):
            self.screen_output(render_relationship_detail(
                summary.relationships[int(value) - 1]
            ))
            self.input_func("\nPress Enter to go back...")
