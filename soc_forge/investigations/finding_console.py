from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.investigations.finding_service import (
    InvestigationFindingError,
    InvestigationFindingService,
)
from soc_forge.investigations.models import InvestigationFinding
from soc_forge.investigations.repository import InvestigationRepositoryError
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.investigations.analyst_workspace_view import (
    render_finding_detail,
    render_finding_list,
    render_findings_workspace,
)
from soc_forge.ui.screen import begin_screen


class InvestigationFindingConsoleController:
    """Terminal presentation for durable analyst-authored findings."""

    def __init__(
        self,
        *,
        finding_service: InvestigationFindingService,
        evidence_controller: object,
        reasoning_controller: object,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ) -> None:
        self.finding_service = finding_service
        self.evidence_controller = evidence_controller
        self.reasoning_controller = reasoning_controller
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to continue..."))

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            current = self.finding_service.workspace_service.get_investigation(
                current.investigation.investigation_id
            )
            self.screen("INVESTIGATION FINDINGS")
            for line in render_findings_workspace(current).splitlines():
                self.output(line)
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                self.list_findings(current)
            elif choice == "2":
                current = self.create_finding(current)
            elif choice == "3":
                current = self.open_finding(current)
            else:
                self.output("Invalid option.")
            self.pause()

    def list_findings(self, current: WorkspaceResult) -> None:
        findings = self.finding_service.list_findings(
            current.investigation.investigation_id
        )
        if not findings:
            self.output("No analyst-authored findings.")
            return
        for line in render_finding_list(findings).splitlines():
            self.output(line)

    def create_finding(self, current: WorkspaceResult) -> WorkspaceResult:
        self.screen("CREATE INVESTIGATION FINDING")
        try:
            evidence_ids = self._select_ids(
                "EVIDENCE",
                tuple(
                    (
                        item.reference_id,
                        f"{item.evidence_type or item.source_type} | "
                        f"{item.classification or 'scope'} | "
                        f"{item.rationale or item.label or 'No bounded rationale'}",
                    )
                    for item in current.investigation.evidence_references
                    if item.origin == "analyst_selection"
                ),
            )
            hypothesis_ids = self._select_ids(
                "HYPOTHESES",
                tuple(
                    (item.hypothesis_id, f"{item.state} | {item.statement}")
                    for item in current.investigation.hypotheses
                ),
            )
            decision_ids = self._select_ids(
                "DECISIONS",
                tuple(
                    (item.decision_id, f"{item.decision_type} | {item.outcome}")
                    for item in current.investigation.decisions
                ),
            )
            result = self.finding_service.create_finding(
                current.investigation.investigation_id,
                finding_id=self.input("Finding ID: ").strip(),
                title=self.input("Title: "),
                conclusion=self.input("Conclusion: "),
                status=self._controlled_choice(
                    "Status", ("draft", "substantiated", "unsubstantiated", "inconclusive")
                ),
                confidence=self._controlled_choice(
                    "Confidence", ("low", "medium", "high")
                ),
                author=self.input("Author label: "),
                evidence_ids=evidence_ids,
                hypothesis_ids=hypothesis_ids,
                decision_ids=decision_ids,
                attack_tactics=self._comma_values(
                    self.input("ATT&CK tactics (comma-separated, blank for none): ")
                ),
                attack_techniques=self._comma_values(
                    self.input("ATT&CK techniques (comma-separated, blank for none): ")
                ),
                limitations=self._comma_values(
                    self.input("Limitations (comma-separated, blank for none): ")
                ),
                expected_revision=current.revision,
            )
        except (InvestigationFindingError, InvestigationRepositoryError, ValueError) as exc:
            self.output(f"Unable to create finding: {exc}")
            return current
        finding = result.investigation.findings[-1]
        self.output("Finding created.")
        self.output(f"Finding ID: {finding.finding_id}")
        self.output(f"Investigation revision: {result.revision}")
        return result

    def open_finding(self, current: WorkspaceResult) -> WorkspaceResult:
        self.list_findings(current)
        finding_id = self.input("Finding ID (blank to cancel): ").strip()
        if not finding_id:
            return current
        try:
            finding = self.finding_service.get_finding(
                current.investigation.investigation_id, finding_id
            )
        except (InvestigationFindingError, InvestigationRepositoryError) as exc:
            self.output(f"Unable to open finding: {exc}")
            return current
        while True:
            self.render_finding(finding)
            if finding.lifecycle_state == "active":
                self.output("[1] Edit finding")
                self.output("[5] Supersede finding")
            else:
                self.output("Historical findings are read-only.")
            self.output("[2] View related evidence")
            self.output("[3] View related hypotheses")
            self.output("[4] View related decisions")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1" and finding.lifecycle_state == "active":
                current = self.edit_finding(current, finding)
                finding = self.finding_service.get_finding(
                    current.investigation.investigation_id, finding_id
                )
            elif choice == "5" and finding.lifecycle_state == "active":
                current = self.supersede_finding(current, finding)
                finding = self.finding_service.get_finding(
                    current.investigation.investigation_id, finding_id
                )
            elif choice == "2":
                current = self.evidence_controller.run(current)
            elif choice in {"3", "4"}:
                current = self.reasoning_controller.run(current)
            else:
                self.output("Invalid option.")
            self.pause()

    def edit_finding(
        self, current: WorkspaceResult, finding: InvestigationFinding
    ) -> WorkspaceResult:
        self.output("Leave text blank to preserve the current value.")
        try:
            changes = {
                "title": self.input("Title: ") or None,
                "conclusion": self.input("Conclusion: ") or None,
                "status": self.input("Status: ") or None,
                "confidence": self.input("Confidence: ") or None,
                "author": self.input("Author label: ") or None,
            }
            if self.input("Edit relationships? (y/N): ").strip().lower() in {"y", "yes"}:
                changes["evidence_ids"] = self._select_ids(
                    "EVIDENCE",
                    tuple(
                        (
                            item.reference_id,
                            f"{item.evidence_type or item.source_type} | "
                            f"{item.classification or 'scope'}",
                        )
                        for item in current.investigation.evidence_references
                        if item.origin == "analyst_selection"
                    ),
                )
                changes["hypothesis_ids"] = self._select_ids(
                    "HYPOTHESES",
                    tuple(
                        (item.hypothesis_id, f"{item.state} | {item.statement}")
                        for item in current.investigation.hypotheses
                    ),
                )
                changes["decision_ids"] = self._select_ids(
                    "DECISIONS",
                    tuple(
                        (item.decision_id, f"{item.decision_type} | {item.outcome}")
                        for item in current.investigation.decisions
                    ),
                )
            tactics = self.input("ATT&CK tactics (blank preserves current): ")
            techniques = self.input("ATT&CK techniques (blank preserves current): ")
            limitations = self.input("Limitations (blank preserves current): ")
            if tactics:
                changes["attack_tactics"] = self._comma_values(tactics)
            if techniques:
                changes["attack_techniques"] = self._comma_values(techniques)
            if limitations:
                changes["limitations"] = self._comma_values(limitations)
            result = self.finding_service.update_finding(
                current.investigation.investigation_id,
                finding.finding_id,
                expected_revision=current.revision,
                **changes,
            )
        except (InvestigationFindingError, InvestigationRepositoryError, ValueError) as exc:
            self.output(f"Unable to update finding: {exc}")
            return current
        self.output(
            "Finding unchanged."
            if result.revision == current.revision
            else f"Finding updated. Investigation revision: {result.revision}"
        )
        return result

    def supersede_finding(
        self, current: WorkspaceResult, finding: InvestigationFinding
    ) -> WorkspaceResult:
        replacements = tuple(
            item
            for item in self.finding_service.list_active_findings(
                current.investigation.investigation_id
            )
            if item.finding_id != finding.finding_id
        )
        if not replacements:
            self.output("Create an active replacement finding before superseding this finding.")
            return current
        self.output("ACTIVE REPLACEMENT FINDINGS")
        for index, item in enumerate(replacements, start=1):
            self.output(f"[{index}] {item.finding_id} | {item.title}")
        selected = self.input("Replacement number (blank to cancel): ").strip()
        if not selected:
            return current
        if not selected.isdigit() or not 1 <= int(selected) <= len(replacements):
            self.output("Invalid replacement selection.")
            return current
        reason = self.input("Supersession reason: ")
        author = self.input("Author label: ")
        confirmation = self.input("Supersede this finding? (type YES): ").strip()
        if confirmation != "YES":
            self.output("Supersession cancelled.")
            return current
        try:
            result = self.finding_service.supersede_finding(
                current.investigation.investigation_id,
                finding.finding_id,
                replacement_finding_id=replacements[int(selected) - 1].finding_id,
                reason=reason,
                author=author,
                expected_revision=current.revision,
            )
        except (InvestigationFindingError, InvestigationRepositoryError, ValueError) as exc:
            self.output(f"Unable to supersede finding: {exc}")
            return current
        self.output(f"Finding superseded. Investigation revision: {result.revision}")
        return result

    def render_finding(self, finding: InvestigationFinding) -> None:
        self.screen("ANALYST-AUTHORED FINDING")
        for line in render_finding_detail(finding).splitlines():
            self.output(line)

    def _select_ids(
        self, heading: str, options: tuple[tuple[str, str], ...]
    ) -> tuple[str, ...]:
        self.output(heading)
        if not options:
            self.output("  No available references.")
            return ()
        for index, (item_id, label) in enumerate(options, start=1):
            self.output(f"[{index}] {item_id} | {label}")
        raw = self.input("Select numbers (comma-separated, blank for none): ")
        indexes = self._comma_values(raw)
        if not indexes:
            return ()
        if any(not value.isdigit() or not 1 <= int(value) <= len(options) for value in indexes):
            raise ValueError(f"Invalid {heading.lower()} selection")
        if len(indexes) != len(set(indexes)):
            raise ValueError(f"Duplicate {heading.lower()} selection")
        return tuple(options[int(value) - 1][0] for value in indexes)

    def _controlled_choice(self, label: str, options: tuple[str, ...]) -> str:
        for index, value in enumerate(options, start=1):
            self.output(f"[{index}] {value}")
        choice = self.input(f"{label}: ").strip()
        if not choice.isdigit() or not 1 <= int(choice) <= len(options):
            raise ValueError(f"Invalid {label.lower()} selection")
        return options[int(choice) - 1]

    @staticmethod
    def _comma_values(value: str) -> tuple[str, ...]:
        return tuple(item.strip() for item in value.split(",") if item.strip())
