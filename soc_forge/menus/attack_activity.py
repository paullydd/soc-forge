from __future__ import annotations

from soc_forge.ui.screen import screen_output
from soc_forge.attack_activity import (
    AttackActivitySummary, AttackTacticActivity, AttackTechniqueActivity,
)
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb, render_empty_state,
    render_metadata, render_panel, resolve_terminal_width,
)


def _screen(panels, *, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return "\n".join((
        render_application_header(width=resolved, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "ATT&CK ACTIVITY"),
                          width=resolved, ansi=ansi, unicode=unicode),
        *panels,
    ))


def render_attack_activity_menu(*, width=None, ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return _screen((render_panel((
        "[1] Activity Summary", "[2] View by Tactic",
        "[3] View by Technique", "[4] Recent ATT&CK Observations", "[0] Back",
    ), title="ATT&CK ACTIVITY", width=resolved, ansi=ansi, unicode=unicode),),
        width=resolved, ansi=ansi, unicode=unicode)


def render_attack_activity_summary(summary: AttackActivitySummary, *, width=None,
                                   ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    state = render_panel(render_metadata((
        ("Mode", render_badge("summary_mode", summary.mode, ansi=ansi)),
        ("Observations", summary.observation_count),
        ("Tactics", summary.tactic_count),
        ("Techniques", summary.technique_count),
        ("Machine Observations", summary.machine_observation_count),
        ("Analyst Observations", summary.analyst_observation_count),
        ("Investigations Represented", summary.investigations_represented),
    ), width=resolved - 4, ansi=ansi), title="ATT&CK ACTIVITY STATE",
        width=resolved, ansi=ansi, unicode=unicode)
    tactics = render_panel(
        tuple(f"{row.tactic} | Observations {row.observation_count}"
              for row in summary.tactics)
        or (render_empty_state("No explicit observed tactics.",
                               width=resolved - 4, ansi=ansi),),
        title="MOST OBSERVED TACTICS", width=resolved, ansi=ansi, unicode=unicode)
    techniques = render_panel(
        tuple(f"{row.technique_key} | Observations {row.observation_count}"
              for row in summary.techniques)
        or (render_empty_state("No explicit observed techniques.",
                               width=resolved - 4, ansi=ansi),),
        title="MOST OBSERVED TECHNIQUES", width=resolved,
        ansi=ansi, unicode=unicode)
    scope = render_panel((
        "Observed or recorded explicit ATT&CK mappings only.",
        "This is not Detection Coverage and no completeness percentage is calculated.",
    ), title="SCOPE", width=resolved, ansi=ansi, unicode=unicode)
    return _screen((state, tactics, techniques, scope), width=resolved,
                   ansi=ansi, unicode=unicode)


def render_tactics(summary: AttackActivitySummary, *, width=None,
                   ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    rows = []
    for index, tactic in enumerate(summary.tactics, 1):
        rows.extend((
            f"[{index}] {tactic.tactic.upper()}",
            f"Observations {tactic.observation_count} | "
            f"[MACHINE] {tactic.machine_observation_count} | "
            f"[ANALYST] {tactic.analyst_observation_count}",
            "Techniques: " + (", ".join(tactic.technique_keys) or "None explicit"),
            "Investigations: " + (", ".join(tactic.investigation_ids) or "None"),
            "",
        ))
    return _screen((render_panel(
        rows or (render_empty_state("No explicit observed tactics.",
                                    width=resolved - 4, ansi=ansi),),
        title="ACTIVITY BY TACTIC", width=resolved, ansi=ansi, unicode=unicode,
    ),), width=resolved, ansi=ansi, unicode=unicode)


def render_techniques(summary: AttackActivitySummary, *, width=None,
                      ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    rows = tuple(
        f"[{index}] {row.technique_key} | Observations {row.observation_count}"
        for index, row in enumerate(summary.techniques, 1)
    ) or (render_empty_state("No explicit observed techniques.",
                             width=resolved - 4, ansi=ansi),)
    return _screen((render_panel(rows, title="ACTIVITY BY TECHNIQUE",
                                 width=resolved, ansi=ansi, unicode=unicode),),
                   width=resolved, ansi=ansi, unicode=unicode)


def render_technique_detail(technique: AttackTechniqueActivity, *, width=None,
                            ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    detail = render_panel(render_metadata((
        ("Technique", technique.technique_key),
        ("Tactics", ", ".join(technique.tactics) or "Not explicitly paired"),
        ("Observations", technique.observation_count),
        ("Machine", technique.machine_observation_count),
        ("Analyst", technique.analyst_observation_count),
        ("Alerts", technique.alert_count),
        ("Findings", technique.finding_count),
        ("Cases", technique.case_count),
        ("Reconstructions", technique.reconstruction_count),
        ("Investigations", technique.investigation_count),
    ), width=resolved - 4, ansi=ansi), title="TECHNIQUE ACTIVITY",
        width=resolved, ansi=ansi, unicode=unicode)
    investigations = render_panel((
        *(technique.investigation_ids or (
            render_empty_state("No durable Investigation membership.",
                               width=resolved - 4, ansi=ansi),)),
        "Shared ATT&CK techniques across Investigations do not establish that "
        "those Investigations are part of the same attack.",
    ), title="INVESTIGATIONS", width=resolved, ansi=ansi, unicode=unicode)
    recent = _recent_panel(technique.recent_observations, resolved, ansi, unicode)
    return _screen((detail, investigations, recent), width=resolved,
                   ansi=ansi, unicode=unicode)


def render_recent(summary: AttackActivitySummary, *, width=None,
                  ansi=None, unicode=True):
    resolved = resolve_terminal_width(width)
    return _screen((_recent_panel(summary.recent_observations, resolved,
                                  ansi, unicode),), width=resolved,
                   ansi=ansi, unicode=unicode)


def _recent_panel(observations, width, ansi, unicode):
    rows = tuple(
        f"{row.timestamp or 'Timestamp unavailable'} "
        f"[{row.attribution.upper()}] {row.source_type.upper()} {row.source_id} | "
        f"{row.tactic or 'No tactic'} | {row.technique_key or 'No technique'} | "
        f"{row.title}"
        for row in observations
    ) or (render_empty_state("No explicit ATT&CK observations.",
                             width=width - 4, ansi=ansi),)
    return render_panel(rows, title="RECENT ATT&CK OBSERVATIONS",
                        width=width, ansi=ansi, unicode=unicode)


class AttackActivityConsoleController:
    def __init__(self, service, *, input_func=input, output_func=print) -> None:
        self.service = service
        self.input_func = input_func
        self.output_func = output_func
        self.screen_output = screen_output(output_func)

    def run(self) -> None:
        while True:
            self.screen_output(render_attack_activity_menu())
            choice = self.input_func("\nSelect option: ").strip()
            if choice == "0":
                return
            summary = self.service.summarize()
            if choice == "1":
                self.screen_output(render_attack_activity_summary(summary))
                self.input_func("\nPress Enter to go back...")
            elif choice == "2":
                self.screen_output(render_tactics(summary))
                self._select_technique(summary)
            elif choice == "3":
                self.screen_output(render_techniques(summary))
                self._select_technique(summary)
            elif choice == "4":
                self.screen_output(render_recent(summary))
                self.input_func("\nPress Enter to go back...")
            else:
                self.output_func("ERROR: Invalid option.")

    def _select_technique(self, summary):
        value = self.input_func(
            "\nTechnique number for detail, or Enter to go back: "
        ).strip()
        if value.isdigit() and 1 <= int(value) <= len(summary.techniques):
            self.screen_output(render_technique_detail(
                summary.techniques[int(value) - 1]
            ))
            self.input_func("\nPress Enter to go back...")
