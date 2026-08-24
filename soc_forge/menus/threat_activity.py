from __future__ import annotations

from soc_forge.ui.screen import screen_output
from soc_forge.threat_activity import ThreatActivityOverview, ThreatActivityOverviewService
from soc_forge.ui.terminal import (
    render_application_header, render_badge, render_breadcrumb, render_empty_state,
    render_metadata, render_panel, resolve_terminal_width,
)


def render_threat_activity_overview(
    overview: ThreatActivityOverview, *, width: int | None = None,
    ansi: bool | None = None, unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    unavailable = "Unavailable"
    state = render_panel(render_metadata((
        ("Mode", render_badge("summary_mode", overview.mode, ansi=ansi)),
        ("Investigations", overview.investigation_count),
        ("Investigations with activity", overview.investigations_with_activity),
        ("Active Findings", overview.active_finding_count),
        ("Historical Findings", overview.historical_finding_count),
        ("Open Response Actions", overview.open_response_action_count),
        ("Alerts", overview.alert_count if overview.alert_count is not None else unavailable),
        ("Cases", overview.case_count if overview.case_count is not None else unavailable),
        ("Hunts", overview.hunt_count if overview.hunt_count is not None else unavailable),
        ("Reconstructions", overview.reconstruction_count if overview.reconstruction_count is not None else unavailable),
    ), width=resolved - 4, ansi=ansi), title="ACTIVITY STATE", width=resolved,
        ansi=ansi, unicode=unicode)
    attack_rows = []
    for heading, rows in (("TACTICS", overview.tactics), ("TECHNIQUES", overview.techniques)):
        attack_rows.append(heading)
        attack_rows.extend(
            f"{row.value} | Observations {row.observation_count} "
            f"([MACHINE] {row.machine_observations}, [ANALYST] {row.analyst_observations})"
            for row in rows
        )
    if len(attack_rows) == 2:
        attack_rows = [render_empty_state("No explicit observed ATT&CK mappings.",
                                          width=resolved - 4, ansi=ansi)]
    attack = render_panel(attack_rows, title="OBSERVED ATT&CK ACTIVITY",
                          width=resolved, ansi=ansi, unicode=unicode)
    recent_rows = tuple(
        f"[{item.origin.upper()}] {item.timestamp} | {item.description}"
        for item in overview.recent_activity
    ) or (render_empty_state("No timestamped security activity.",
                             width=resolved - 4, ansi=ansi),)
    recent = render_panel(recent_rows, title="RECENT SECURITY ACTIVITY",
                          width=resolved, ansi=ansi, unicode=unicode)
    source = ("Current machine analysis context is available."
              if overview.mode == "full"
              else "Machine analysis context unavailable. Durable analyst state remains available.")
    note = render_panel((
        source,
        "Observed activity is descriptive; it is not queue ranking, risk scoring, or detection coverage.",
    ), title="SOURCE SCOPE", width=resolved, ansi=ansi, unicode=unicode)
    return "\n".join((
        render_application_header(width=resolved, ansi=ansi, unicode=unicode),
        render_breadcrumb(("SOC-FORGE", "ANALYSIS", "THREAT ACTIVITY"),
                          width=resolved, ansi=ansi, unicode=unicode),
        state, attack, recent, note,
    ))


class ThreatActivityConsoleController:
    def __init__(self, service: ThreatActivityOverviewService, *,
                 input_func=input, output_func=print) -> None:
        self.service = service
        self.input_func = input_func
        self.output_func = output_func
        self.screen_output = screen_output(output_func)

    def run(self) -> None:
        self.screen_output(render_threat_activity_overview(self.service.summarize()))
        self.input_func("\nPress Enter to go back...")
