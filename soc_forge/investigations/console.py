from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from soc_forge.investigations.bootstrap import (
    InvestigationBootstrapAdapter,
    InvestigationBootstrapError,
)
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.evidence_console import EvidenceConsoleController
from soc_forge.investigations.evidence_service import InvestigationEvidenceService
from soc_forge.investigations.finding_console import InvestigationFindingConsoleController
from soc_forge.investigations.finding_service import InvestigationFindingService
from soc_forge.investigations.handoff import InvestigationHandoffService
from soc_forge.investigations.handoff_console import (
    InvestigationHandoffConsoleController,
)
from soc_forge.investigations.reasoning_console import ReasoningConsoleController
from soc_forge.investigations.reasoning_service import InvestigationReasoningService
from soc_forge.investigations.query_console import InvestigationQueryConsoleController
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.query_models import InvestigationQueryError
from soc_forge.investigations.summary import InvestigationSummaryService
from soc_forge.investigations.summary_console import (
    InvestigationSummaryConsoleController,
)
from soc_forge.investigations.snapshots import (
    CompletedAnalysisSnapshotError,
    CompletedAnalysisSnapshotStore,
)
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepositoryError,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceError,
    InvestigationWorkspaceService,
    WorkspaceResult,
)
from soc_forge.investigations.workspace_view import render_investigation_workspace
from soc_forge.ui.screen import begin_screen


class InvestigationConsoleController:
    def __init__(
        self,
        *,
        bootstrap_adapter: InvestigationBootstrapAdapter,
        workspace_service: InvestigationWorkspaceService,
        analysis_provider: Callable[[], object | None],
        workspace_root: Path | str,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
        evidence_controller: EvidenceConsoleController | None = None,
        reasoning_controller: ReasoningConsoleController | None = None,
        query_controller: InvestigationQueryConsoleController | None = None,
        handoff_controller: InvestigationHandoffConsoleController | None = None,
        summary_controller: InvestigationSummaryConsoleController | None = None,
        finding_controller: InvestigationFindingConsoleController | None = None,
        snapshot_store: CompletedAnalysisSnapshotStore | None = None,
        analysis_activator: Callable[[object], None] | None = None,
    ):
        self.bootstrap_adapter = bootstrap_adapter
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider
        self.workspace_root = Path(workspace_root)
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to return..."))
        self.snapshot_store = snapshot_store
        self.analysis_activator = analysis_activator
        self.evidence_controller = evidence_controller or EvidenceConsoleController(
            catalog=AnalysisEvidenceCatalog(),
            evidence_service=InvestigationEvidenceService(workspace_service),
            analysis_provider=analysis_provider,
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )

        self.reasoning_controller = reasoning_controller or ReasoningConsoleController(
            reasoning_service=InvestigationReasoningService(workspace_service),
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )
        self.query_controller = query_controller or InvestigationQueryConsoleController(
            workspace_service=workspace_service,
            analysis_provider=analysis_provider,
            evidence_controller=self.evidence_controller,
            reasoning_controller=self.reasoning_controller,
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )
        self.handoff_controller = handoff_controller or InvestigationHandoffConsoleController(
            handoff_service=InvestigationHandoffService(workspace_service.repository),
            analysis_provider=analysis_provider,
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )
        self.finding_controller = finding_controller or InvestigationFindingConsoleController(
            finding_service=InvestigationFindingService(workspace_service),
            evidence_controller=self.evidence_controller,
            reasoning_controller=self.reasoning_controller,
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )
        self.summary_controller = summary_controller or InvestigationSummaryConsoleController(
            summary_service=InvestigationSummaryService(workspace_service),
            analysis_provider=analysis_provider,
            evidence_controller=self.evidence_controller,
            reasoning_controller=self.reasoning_controller,
            query_controller=self.query_controller,
            handoff_controller=self.handoff_controller,
            finding_controller=self.finding_controller,
            snapshot_loader=self.load_source_analysis,
            input_func=input_func,
            output_func=output_func,
            screen_func=screen_func,
            pause_func=self.pause,
        )
    def run(self) -> None:
        while True:
            self.screen("INVESTIGATION WORKSPACES")
            self.output(f"Storage: {self.workspace_root}")
            self.output("")
            self.output("[1] Create investigation from case")
            self.output("[2] List investigations")
            self.output("[3] Open investigation")
            self.output("[4] Delete investigation")
            self.output("[0] Back")

            choice = self.input("\nSelect option: ").strip()
            if choice == "1":
                self.create_flow()
                self.pause()
            elif choice == "2":
                self.list_screen()
                self.pause()
            elif choice == "3":
                self.open_flow()
                self.pause()
            elif choice == "4":
                self.delete_flow()
                self.pause()
            elif choice == "0":
                return
            else:
                self.output("Invalid option.")

    def create_flow(self) -> WorkspaceResult | None:
        analysis_result = self.analysis_provider()
        if analysis_result is None:
            self.output("No completed analysis is available. Run or load analysis first.")
            return None

        cases = getattr(analysis_result, "cases", None)
        if not isinstance(cases, list) or not cases:
            self.output("The completed analysis has no cases available for selection.")
            return None

        self.screen("CREATE INVESTIGATION")
        for index, case in enumerate(cases, start=1):
            case_id = self._case_id(case)
            title = self._case_title(case)
            self.output(f"[{index}] {case_id} | {title}")

        selection = self.input("\nSelect one case, or 0 to cancel: ").strip()
        if selection in {"", "0"}:
            self.output("Creation cancelled.")
            return None
        if not selection.isdigit() or not 1 <= int(selection) <= len(cases):
            self.output("Invalid case selection.")
            return None

        selected_case = cases[int(selection) - 1]
        case_id = self._case_id(selected_case)
        investigation_id = self.input("Investigation ID: ").strip()
        title = self.input("Title override (blank for case title): ").strip() or None
        owner = self.input("Owner (blank for Unassigned): ").strip() or None
        confirmation = self.input("Create investigation? (y/N): ").strip().lower()
        if confirmation not in {"y", "yes"}:
            self.output("Creation cancelled.")
            return None

        try:
            result = self.bootstrap_adapter.bootstrap_investigation(
                analysis_result,
                investigation_id,
                [case_id],
                title=title,
                owner=owner,
            )
        except self._display_errors() as exc:
            self.output(f"Unable to create investigation: {exc}")
            return None

        self.output(
            f"Created {result.investigation.investigation_id} at revision "
            f"{result.revision}."
        )
        self.output(f"Storage: {self.workspace_root}")
        return result

    def list_screen(self) -> list:
        self.screen("INVESTIGATION WORKSPACES")
        try:
            summaries = self.workspace_service.list_investigations()
        except InvestigationRepositoryError as exc:
            self.output(f"Unable to list investigations: {exc}")
            return []

        if not summaries:
            self.output("No durable investigations found.")
            return []

        for summary in summaries:
            owner = summary.owner or "Unassigned"
            self.output(
                f"{summary.investigation_id} | {summary.title} | "
                f"{summary.status} | {owner} | {summary.updated_at} | "
                f"Revision {summary.revision}"
            )
        return summaries

    def open_flow(self) -> WorkspaceResult | None:
        investigation_id = self.input("Investigation ID (blank to cancel): ").strip()
        if not investigation_id:
            return None
        try:
            result = self.workspace_service.get_investigation(investigation_id)
        except InvestigationRepositoryError as exc:
            self.output(f"Unable to open investigation: {exc}")
            return None
        return self.workspace_loop(result)

    def workspace_loop(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            self._render_workspace(current)
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self.summary_controller.run(current)
            elif choice == "2":
                current = self._assign_owner(current)
            elif choice == "3":
                current = self._change_status(current)
            elif choice == "4":
                current = self._reopen(current)
            elif choice == "5":
                self._view_annotations(current)
            elif choice == "6":
                current = self._add_annotation(current)
            elif choice == "7":
                current = self._edit_annotation(current)
            elif choice == "8":
                current = self._remove_annotation(current)
            elif choice == "9":
                self._view_decisions(current)
            elif choice == "10":
                current = self.evidence_controller.run(current)
            elif choice == "11":
                current = self.reasoning_controller.run(current)
            elif choice == "12":
                current = self.finding_controller.run(current)
            elif choice == "13":
                current = self.query_controller.run(current)
            elif choice == "14":
                current = self.handoff_controller.run(current)
            elif choice == "15":
                self.load_source_analysis(current)
            else:
                self.output("Invalid option.")
            if choice in {"2", "3", "4", "5", "6", "7", "8", "9", "15"}:
                self.pause()

    def load_source_analysis(self, current: WorkspaceResult) -> object | None:
        if self.snapshot_store is None or self.analysis_activator is None:
            self.output("Completed analysis snapshot recovery is unavailable.")
            return None
        try:
            analysis = self.snapshot_store.load(current.investigation.analysis_id)
            InvestigationQueryContext(analysis, current.investigation)
        except CompletedAnalysisSnapshotError:
            self.output(
                "The exact completed analysis snapshot is unavailable or failed validation."
            )
            return None
        except (InvestigationQueryError, ValueError, TypeError):
            self.output(
                "The completed analysis snapshot does not satisfy this investigation's "
                "provenance and source references."
            )
            return None
        self.analysis_activator(analysis)
        self.output(
            f"Loaded completed analysis snapshot {current.investigation.analysis_id}."
        )
        self.output("The investigation workspace was not modified.")
        return analysis

    def delete_flow(self) -> bool:
        investigation_id = self.input("Investigation ID (blank to cancel): ").strip()
        if not investigation_id:
            self.output("Deletion cancelled.")
            return False
        try:
            current = self.workspace_service.get_investigation(investigation_id)
        except InvestigationRepositoryError as exc:
            self.output(f"Unable to delete investigation: {exc}")
            return False
        confirmation = self.input(
            f"Delete {investigation_id}? This keeps analysis artifacts. (y/N): "
        ).strip().lower()
        if confirmation not in {"y", "yes"}:
            self.output("Deletion cancelled.")
            return False
        try:
            self.workspace_service.delete_investigation(
                investigation_id,
                expected_revision=current.revision,
            )
        except self._display_errors() as exc:
            self.output(f"Unable to delete investigation: {exc}")
            return False
        self.output(f"Deleted investigation workspace {investigation_id}.")
        return True

    def _assign_owner(self, current: WorkspaceResult) -> WorkspaceResult:
        value = self.input("Owner (blank clears ownership): ")
        return self._modify(
            current,
            lambda: self.workspace_service.assign_owner(
                current.investigation.investigation_id,
                value if value.strip() else None,
                expected_revision=current.revision,
            ),
        )

    def _change_status(self, current: WorkspaceResult) -> WorkspaceResult:
        status = current.investigation.metadata.status
        options = self.workspace_service.available_status_transitions(status)
        if not options:
            self.output("Closed investigations must use the explicit reopen action.")
            return current
        for index, target in enumerate(options, start=1):
            self.output(f"[{index}] {target}")
        choice = self.input("Target status (blank to cancel): ").strip()
        if not choice:
            return current
        if not choice.isdigit() or not 1 <= int(choice) <= len(options):
            self.output("Invalid status selection.")
            return current
        target = options[int(choice) - 1]
        return self._modify(
            current,
            lambda: self.workspace_service.change_status(
                current.investigation.investigation_id,
                target,
                expected_revision=current.revision,
            ),
        )

    def _reopen(self, current: WorkspaceResult) -> WorkspaceResult:
        return self._modify(
            current,
            lambda: self.workspace_service.reopen_investigation(
                current.investigation.investigation_id,
                expected_revision=current.revision,
            ),
        )

    def _view_annotations(self, current: WorkspaceResult) -> None:
        annotations = current.investigation.annotations
        if not annotations:
            self.output("No annotations.")
            return
        for annotation in annotations:
            updated = annotation.updated_at or annotation.created_at
            self.output(
                f"{annotation.annotation_id} | {annotation.created_by or 'Unknown'} | "
                f"{annotation.target_type}:{annotation.target_id} | "
                f"Created {annotation.created_at} | Updated {updated}"
            )
            self.output(f"  {annotation.body}")

    def _add_annotation(self, current: WorkspaceResult) -> WorkspaceResult:
        annotation_id = self.input("Annotation ID: ").strip()
        author = self.input("Author label: ")
        body = self.input("Annotation text: ")
        return self._modify(
            current,
            lambda: self.workspace_service.add_annotation(
                current.investigation.investigation_id,
                annotation_id=annotation_id,
                body=body,
                author=author,
                expected_revision=current.revision,
            ),
        )

    def _edit_annotation(self, current: WorkspaceResult) -> WorkspaceResult:
        self._view_annotations(current)
        annotation_id = self.input("Annotation ID to edit: ").strip()
        body = self.input("New annotation text: ")
        return self._modify(
            current,
            lambda: self.workspace_service.update_annotation(
                current.investigation.investigation_id,
                annotation_id,
                body,
                expected_revision=current.revision,
            ),
        )

    def _remove_annotation(self, current: WorkspaceResult) -> WorkspaceResult:
        self._view_annotations(current)
        annotation_id = self.input("Annotation ID to remove: ").strip()
        confirmation = self.input(f"Delete annotation {annotation_id}? (y/N): ")
        if confirmation.strip().lower() not in {"y", "yes"}:
            self.output("Annotation deletion cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.workspace_service.remove_annotation(
                current.investigation.investigation_id,
                annotation_id,
                expected_revision=current.revision,
            ),
        )

    def _view_decisions(self, current: WorkspaceResult) -> None:
        decisions = current.investigation.decisions
        if not decisions:
            self.output("No analyst decisions.")
            return
        for decision in decisions:
            self.output(
                f"{decision.decision_id} | {decision.decided_by or 'Unknown'} | "
                f"{decision.decision_type}:{decision.outcome} | "
                f"{decision.decided_at or 'Unknown time'}"
            )
            self.output(f"  Rationale: {decision.rationale}")
            self.output(
                "  Evidence IDs: "
                + (", ".join(decision.evidence_reference_ids) or "None")
            )
            self.output(
                "  Hypothesis IDs: "
                + (", ".join(decision.hypothesis_ids) or "None")
            )

    def _modify(
        self,
        current: WorkspaceResult,
        operation: Callable[[], WorkspaceResult],
    ) -> WorkspaceResult:
        try:
            updated = operation()
        except InvestigationConflictError:
            self.output(
                "This investigation changed elsewhere. No overwrite was attempted."
            )
            try:
                latest = self.workspace_service.get_investigation(
                    current.investigation.investigation_id
                )
            except InvestigationRepositoryError as exc:
                self.output(f"Unable to reload the investigation: {exc}")
                return current
            self.output(f"Reloaded latest revision {latest.revision}.")
            return latest
        except self._display_errors() as exc:
            self.output(f"Workspace update failed: {exc}")
            return current
        self.output(f"Workspace updated to revision {updated.revision}.")
        return updated

    def _render_workspace(self, current: WorkspaceResult) -> None:
        self.screen("INVESTIGATION WORKSPACE")
        for line in render_investigation_workspace(current).splitlines():
            self.output(line)

    @staticmethod
    def _display_errors() -> tuple[type[Exception], ...]:
        return (
            InvestigationBootstrapError,
            InvestigationWorkspaceError,
            InvestigationRepositoryError,
            ValueError,
        )

    @staticmethod
    def _case_id(case: object) -> str:
        if isinstance(case, dict):
            return str(case.get("case_id") or case.get("id") or "Unknown")
        return "Unknown"

    @staticmethod
    def _case_title(case: object) -> str:
        if not isinstance(case, dict):
            return "Untitled Case"
        header = case.get("header")
        header_title = header.get("title") if isinstance(header, dict) else None
        return str(case.get("title") or header_title or "Untitled Case")

    @staticmethod
    def _comma_ids(value: str) -> Iterable[str]:
        return tuple(item.strip() for item in value.split(",") if item.strip())
