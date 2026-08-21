from __future__ import annotations

from soc_forge.menus.entity_explorer import render_entity_result
from soc_forge.menus.temporal_analysis import render_temporal
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb,
    render_message_block, render_metadata, render_panel, resolve_terminal_width,
)

CAUTION = (
    "Hunt result overlap across Investigations does not establish a shared "
    "attacker, campaign, incident, or cause."
)


def _screen(panels, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=width, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "HUNT WORKSPACE"),
                          width=width, ansi=ansi, unicode=unicode), *panels,
    ))


def render_hunt_menu(summary, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    state = render_panel(render_metadata((
        ("Mode", render_badge("summary_mode", summary.mode, ansi=ansi)),
        ("Existing Hunts", summary.hunt_count if summary.hunt_count is not None else "Unavailable"),
        ("Existing Hunt Evidence", summary.result_count if summary.result_count is not None else "Unavailable"),
        ("Current Machine Context", "Available" if summary.machine_context_available else "Unavailable"),
    ), width=width - 4, ansi=ansi), title="HUNT STATE",
        width=width, ansi=ansi, unicode=unicode)
    menu = render_panel((
        "[1] Existing Hunts", "[2] Hunt by Entity",
        "[3] Hunt by ATT&CK Technique", "[4] Hunt by Investigation", "[0] Back",
    ), title="HUNT SOURCES", width=width, ansi=ansi, unicode=unicode)
    return _screen((state, menu), width=width, ansi=ansi, unicode=unicode)


def render_existing_hunts(summary, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    if not summary.machine_context_available:
        rows = render_message_block(
            "empty", "Hunt machine context unavailable in OFFLINE mode.",
            width=width - 4, ansi=ansi,
        ).splitlines()
    elif not summary.hunts:
        rows = render_message_block(
            "empty", "No existing Hunt findings in current machine analysis.",
            width=width - 4, ansi=ansi,
        ).splitlines()
    else:
        rows = []
        for index, hunt in enumerate(summary.hunts, 1):
            rows.extend((
                f"[{index}] {hunt.hunt_id} | {hunt.title}",
                f"{hunt.category or 'No category'} | {hunt.severity or 'No severity'} | "
                f"Evidence {hunt.evidence_count} | {hunt.first_seen or 'Untimed'}",
                "",
            ))
    return _screen((render_panel(rows, title="EXISTING HUNTS", width=width,
                                 ansi=ansi, unicode=unicode),),
                   width=width, ansi=ansi, unicode=unicode)


def render_hunt_detail(hunt, *, width=None, ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    detail = render_panel(render_metadata((
        ("Hunt ID", hunt.hunt_id), ("Title", hunt.title),
        ("Category", hunt.category or "Unavailable"),
        ("Severity", hunt.severity or "Unavailable"),
        ("Confidence", hunt.confidence or "Unavailable"),
        ("Summary", hunt.summary), ("Evidence", hunt.evidence_count),
        ("First Seen", hunt.first_seen or "Untimed"),
        ("Last Seen", hunt.last_seen or "Untimed"),
        ("ATT&CK", ", ".join(hunt.techniques) or "None explicit"),
    ), width=width - 4, ansi=ansi), title="HUNT DETAIL",
        width=width, ansi=ansi, unicode=unicode)
    entities = tuple(f"{key}: {value}" for key, value in hunt.entities) or (
        "No structured entities.",)
    return _screen((detail, render_panel(entities, title="STRUCTURED ENTITIES",
                                         width=width, ansi=ansi,
                                         unicode=unicode)),
                   width=width, ansi=ansi, unicode=unicode)


def render_technique_hunt(mode, techniques, query, *, width=None,
                          ansi=None, unicode=True):
    width = resolve_terminal_width(width)
    rows = []
    for row in techniques:
        rows.extend((
            f"{row.technique_key} | Observations {row.observation_count}",
            f"[MACHINE] {row.machine_observation_count} | "
            f"[ANALYST] {row.analyst_observation_count} | "
            f"Investigations {row.investigation_count}",
            "Investigations: " + (", ".join(row.investigation_ids) or "None"),
        ))
    if not rows:
        rows = render_message_block(
            "empty", f"No explicit ATT&CK observations for {query}.",
            width=width - 4, ansi=ansi,
        ).splitlines()
    caution = render_message_block("warning", CAUTION, width=width - 4,
                                   ansi=ansi).splitlines()
    return _screen((
        render_panel((f"Mode: [{mode.upper()}]", *rows),
                     title="ATT&CK TECHNIQUE HUNT", width=width,
                     ansi=ansi, unicode=unicode),
        render_panel(caution, title="INTERPRETATION", width=width,
                     ansi=ansi, unicode=unicode),
    ), width=width, ansi=ansi, unicode=unicode)


class HuntWorkspaceConsoleController:
    def __init__(self, service, *, input_func=input, output_func=print) -> None:
        self.service, self.input_func, self.output_func = service, input_func, output_func

    def run(self):
        while True:
            summary = self.service.summarize()
            self.output_func(render_hunt_menu(summary))
            choice = self.input_func("\nSelect option: ").strip()
            if choice == "0":
                return
            if choice == "1":
                self.output_func(render_existing_hunts(summary))
                value = self.input_func("\nHunt number for detail, or Enter to go back: ").strip()
                if value.isdigit() and 1 <= int(value) <= len(summary.hunts):
                    self.output_func(render_hunt_detail(summary.hunts[int(value) - 1]))
                    self.input_func("\nPress Enter to go back...")
            elif choice == "2":
                kind = self.input_func("\nEntity type (host/user/ip/process): ").strip()
                value = self.input_func("\nExact entity value: ").strip()
                self.output_func(render_entity_result(
                    self.service.entity_hunt(kind, value)
                ))
                self.input_func("\nPress Enter to go back...")
            elif choice == "3":
                value = self.input_func("\nTechnique ID: ").strip()
                mode, rows = self.service.technique_hunt(value)
                self.output_func(render_technique_hunt(mode, rows, value))
                self.input_func("\nPress Enter to go back...")
            elif choice == "4":
                value = self.input_func("\nInvestigation ID: ").strip()
                self.output_func(render_temporal(
                    self.service.investigation_hunt(value),
                    label=f"Hunt view filtered to {value}",
                ))
                self.input_func("\nPress Enter to go back...")
            else:
                self.output_func("ERROR: Invalid option.")
