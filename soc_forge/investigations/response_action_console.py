from __future__ import annotations

from typing import Callable

from soc_forge.investigations.repository import InvestigationRepositoryError
from soc_forge.investigations.response_action_service import (
    RESPONSE_ACTION_TRANSITIONS,
    InvestigationResponseActionService,
    ResponseActionError,
)
from soc_forge.investigations.response_action_view import (
    render_response_action_detail,
    render_response_action_list,
    render_response_actions_workspace,
)
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.screen import begin_screen


TRANSITION_LABELS = {
    "approved": "Approve",
    "in_progress": "Start Work",
    "completed": "Complete",
    "dismissed": "Dismiss",
}


class InvestigationResponseActionConsoleController:
    """Terminal adapter for durable analyst-controlled response actions."""

    def __init__(
        self,
        *,
        response_action_service: InvestigationResponseActionService,
        finding_controller: object,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ) -> None:
        self.response_action_service = response_action_service
        self.finding_controller = finding_controller
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to continue..."))

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        investigation_id = current.investigation.investigation_id
        while True:
            current = self.response_action_service.workspace_service.get_investigation(
                investigation_id
            )
            self.screen("RESPONSE ACTIONS")
            for line in render_response_actions_workspace(current).splitlines():
                self.output(line)
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                self.list_actions(current)
            elif choice == "2":
                current = self.create_action(current)
            elif choice == "3":
                current = self.open_action(current)
            else:
                self.output("Invalid option.")
            self.pause()

    def list_actions(self, current: WorkspaceResult) -> None:
        actions = self.response_action_service.list_actions(
            current.investigation.investigation_id
        )
        for line in render_response_action_list(actions).splitlines():
            self.output(line)

    def create_action(self, current: WorkspaceResult) -> WorkspaceResult:
        active_findings = tuple(
            item
            for item in current.investigation.findings
            if item.lifecycle_state == "active"
        )
        if not active_findings:
            self.output("No ACTIVE Findings are available for a response action.")
            return current
        self.screen("CREATE RESPONSE ACTION")
        self.output("ACTIVE FINDINGS")
        for index, finding in enumerate(active_findings, start=1):
            self.output(f"[{index}] {finding.finding_id} | {finding.title}")
        try:
            finding_ids = self._select_findings(active_findings)
            action_id = self.input("Action ID (blank to generate): ").strip() or None
            result = self.response_action_service.create_action(
                current.investigation.investigation_id,
                action_id=action_id,
                finding_ids=finding_ids,
                title=self.input("Title: "),
                description=self.input("Description: "),
                action_type=self._choice(
                    "Action type",
                    (
                        "containment", "credential_action", "host_action",
                        "network_action", "collection", "validation",
                        "monitoring", "communication", "other",
                    ),
                ),
                priority=self._choice(
                    "Priority", ("low", "medium", "high", "critical")
                ),
                rationale=self.input("Rationale: "),
                owner=self.input("Owner: "),
                created_by=self.input("Created by: "),
                expected_revision=current.revision,
            )
        except (ResponseActionError, InvestigationRepositoryError, ValueError) as exc:
            self.output(f"Unable to create response action: {exc}")
            return current
        action = result.investigation.response_actions[-1]
        self.output("Action created.")
        self.output(f"Action ID: {action.action_id}")
        self.output(f"Current status: {action.status}")
        self.output(f"Investigation revision: {result.revision}")
        return result

    def open_action(
        self, current: WorkspaceResult, action_id: str | None = None
    ) -> WorkspaceResult:
        if action_id is None:
            self.list_actions(current)
            action_id = self.input("Action ID (blank to cancel): ").strip()
        if not action_id:
            return current
        while True:
            try:
                action = self.response_action_service.get_action(
                    current.investigation.investigation_id, action_id
                )
            except (ResponseActionError, InvestigationRepositoryError, ValueError) as exc:
                self.output(f"Unable to open response action: {exc}")
                return current
            self.screen("RESPONSE ACTION DETAIL")
            for line in render_response_action_detail(action).splitlines():
                self.output(line)
            transitions = tuple(sorted(RESPONSE_ACTION_TRANSITIONS[action.status]))
            for index, target in enumerate(transitions, start=1):
                self.output(f"[{index}] {TRANSITION_LABELS[target]}")
            finding_option = len(transitions) + 1
            self.output(f"[{finding_option}] View Related Findings")
            if not transitions:
                self.output("Lifecycle is read-only for this terminal action.")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice.isdigit() and 1 <= int(choice) <= len(transitions):
                current = self.transition_action(
                    current, action, transitions[int(choice) - 1]
                )
            elif choice == str(finding_option):
                self.view_related_findings(current, action.finding_ids)
            else:
                self.output("Invalid option.")
            self.pause()

    def transition_action(self, current, action, target_status):
        author = self.input("Analyst/author: ")
        rationale = self.input("Transition rationale: ")
        try:
            result = self.response_action_service.transition_action(
                current.investigation.investigation_id,
                action.action_id,
                target_status=target_status,
                author=author,
                rationale=rationale,
                expected_revision=current.revision,
            )
        except (ResponseActionError, InvestigationRepositoryError, ValueError) as exc:
            self.output(f"Unable to transition response action: {exc}")
            return current
        transition = result.investigation.response_actions[
            current.investigation.response_actions.index(action)
        ].transition_history[-1]
        self.output("Response action updated.")
        self.output(f"Previous status: {transition.from_status}")
        self.output(f"New status: {transition.to_status}")
        self.output(f"Transition ID: {transition.transition_id}")
        self.output(f"Investigation revision: {result.revision}")
        return result

    def view_related_findings(
        self, current: WorkspaceResult, finding_ids: tuple[str, ...]
    ) -> None:
        for finding_id in finding_ids:
            finding = self.finding_controller.finding_service.get_finding(
                current.investigation.investigation_id, finding_id
            )
            self.finding_controller.render_finding(finding)

    def _select_findings(self, findings) -> tuple[str, ...]:
        raw = self.input("Select Finding numbers (comma-separated): ")
        values = tuple(item.strip() for item in raw.split(",") if item.strip())
        if not values:
            raise ValueError("At least one ACTIVE Finding must be selected")
        if len(values) != len(set(values)):
            raise ValueError("Duplicate Finding selection")
        if any(not item.isdigit() or not 1 <= int(item) <= len(findings) for item in values):
            raise ValueError("Invalid Finding selection")
        return tuple(findings[int(item) - 1].finding_id for item in values)

    def _choice(self, label: str, options: tuple[str, ...]) -> str:
        for index, value in enumerate(options, start=1):
            self.output(f"[{index}] {value}")
        selected = self.input(f"{label}: ").strip()
        if not selected.isdigit() or not 1 <= int(selected) <= len(options):
            raise ValueError(f"Invalid {label.lower()} selection")
        return options[int(selected) - 1]