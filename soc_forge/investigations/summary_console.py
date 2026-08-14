from __future__ import annotations

from typing import Callable

from soc_forge.investigations.summary import (
    InvestigationSummary,
    InvestigationSummaryService,
)
from soc_forge.investigations.summary_view import render_investigation_summary
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.screen import begin_screen


class InvestigationSummaryConsoleController:
    """Terminal presentation for the shared read-only investigation summary."""

    def __init__(
        self,
        *,
        summary_service: InvestigationSummaryService,
        analysis_provider: Callable[[], object | None],
        evidence_controller: object,
        reasoning_controller: object,
        query_controller: object,
        handoff_controller: object,
        finding_controller: object | None = None,
        snapshot_loader: Callable[[WorkspaceResult], object | None],
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ) -> None:
        self.summary_service = summary_service
        self.analysis_provider = analysis_provider
        self.evidence_controller = evidence_controller
        self.reasoning_controller = reasoning_controller
        self.query_controller = query_controller
        self.handoff_controller = handoff_controller
        self.finding_controller = finding_controller
        self.snapshot_loader = snapshot_loader
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to continue..."))

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            summary = self.summary_service.summarize(
                current.investigation.investigation_id,
                self.analysis_provider(),
            )
            self.render(summary)
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self.evidence_controller.run(current)
            elif choice == "2":
                current = self.reasoning_controller.run(current)
            elif choice == "3":
                current = self.query_controller.run(current)
            elif choice == "4":
                current = self.handoff_controller.run(current)
            elif choice == "5" and self.finding_controller is not None:
                current = self.finding_controller.run(current)
            elif choice == "6":
                self.snapshot_loader(current)
                self.pause()
            else:
                self.output("Invalid option.")
                self.pause()

    def render(self, summary: InvestigationSummary) -> None:
        self.screen("INVESTIGATION SUMMARY")
        for line in render_investigation_summary(summary).splitlines():
            self.output(line)
