from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from soc_forge.investigations.bootstrap import (
    InvestigationBootstrapAdapter,
    InvestigationBootstrapError,
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
    ):
        self.bootstrap_adapter = bootstrap_adapter
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider
        self.workspace_root = Path(workspace_root)
        self.input = input_func
        self.output = output_func
        self.screen = screen_func

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
            elif choice == "2":
                self.list_screen()
            elif choice == "3":
                self.open_flow()
            elif choice == "4":
                self.delete_flow()
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
            self.output("[1] Assign or clear owner")
            self.output("[2] Change status")
            self.output("[3] Reopen investigation")
            self.output("[4] View annotations")
            self.output("[5] Add annotation")
            self.output("[6] Edit annotation")
            self.output("[7] Remove annotation")
            self.output("[8] View decisions")
            self.output("[9] Record decision")
            self.output("[0] Back")

            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self._assign_owner(current)
            elif choice == "2":
                current = self._change_status(current)
            elif choice == "3":
                current = self._reopen(current)
            elif choice == "4":
                self._view_annotations(current)
            elif choice == "5":
                current = self._add_annotation(current)
            elif choice == "6":
                current = self._edit_annotation(current)
            elif choice == "7":
                current = self._remove_annotation(current)
            elif choice == "8":
                self._view_decisions(current)
            elif choice == "9":
                current = self._record_decision(current)
            else:
                self.output("Invalid option.")

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

    def _record_decision(self, current: WorkspaceResult) -> WorkspaceResult:
        decision_id = self.input("Decision ID: ").strip()
        decision_type = self.input("Decision type/disposition: ")
        outcome = self.input("Outcome: ")
        rationale = self.input("Rationale: ")
        author = self.input("Author label: ")
        evidence_ids = self._comma_ids(
            self.input("Related evidence IDs (comma-separated, optional): ")
        )
        hypothesis_ids = self._comma_ids(
            self.input("Related hypothesis IDs (comma-separated, optional): ")
        )
        return self._modify(
            current,
            lambda: self.workspace_service.record_decision(
                current.investigation.investigation_id,
                decision_id=decision_id,
                decision_type=decision_type,
                outcome=outcome,
                rationale=rationale,
                author=author,
                evidence_reference_ids=evidence_ids,
                hypothesis_ids=hypothesis_ids,
                expected_revision=current.revision,
            ),
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
        investigation = current.investigation
        metadata = investigation.metadata
        case_ids = [
            reference.source_id
            for reference in investigation.evidence_references
            if reference.source_type == "case"
        ]
        self.screen("INVESTIGATION WORKSPACE")
        self.output(f"Investigation ID: {investigation.investigation_id}")
        self.output(f"Title: {metadata.title}")
        self.output(f"Status: {metadata.status}")
        self.output(f"Owner: {metadata.owner or 'Unassigned'}")
        self.output(f"Created: {metadata.created_at}")
        self.output(f"Updated: {metadata.updated_at}")
        self.output(f"Revision: {current.revision}")
        self.output(f"Source analysis ID: {investigation.analysis_id}")
        self.output(f"Selected case IDs: {', '.join(case_ids) or 'None'}")
        self.output(f"Annotations: {len(investigation.annotations)}")
        self.output(f"Decisions: {len(investigation.decisions)}")
        self.output("")

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
