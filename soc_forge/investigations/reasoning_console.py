from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.investigations.models import Decision, EvidenceReference, Hypothesis
from soc_forge.investigations.reasoning_service import (
    GENERAL_DECISION_TYPES,
    InvestigationReasoningError,
    InvestigationReasoningService,
)
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepositoryError,
)
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.investigations.analyst_workspace_view import (
    render_decision,
    render_hypothesis,
    render_reasoning_workspace,
)
from soc_forge.ui.screen import begin_screen


DISPLAY_VALUE_LIMIT = 160

class ReasoningConsoleController:
    """Terminal presentation for analyst-authored hypotheses and decisions."""

    def __init__(
        self,
        *,
        reasoning_service: InvestigationReasoningService,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ):
        self.reasoning_service = reasoning_service
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to return..."))

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            self.screen("HYPOTHESES AND DECISIONS")
            summary = self._summary(current)
            for line in render_reasoning_workspace(current, summary).splitlines():
                self.output(line)
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                self.render_summary(current)
            elif choice == "2":
                self.list_hypotheses(current)
            elif choice == "3":
                current = self.create_hypothesis(current)
            elif choice == "4":
                current = self.open_hypothesis(current)
            elif choice == "5":
                self.view_decisions(current)
            elif choice == "6":
                current = self.record_decision(current)
            else:
                self.output("Invalid option.")
                continue
            if choice != "4":
                self.pause()

    def render_workspace_counts(self, current: WorkspaceResult) -> None:
        summary = self._summary(current)
        if summary is None:
            return
        self.output(f"Hypotheses: {summary.total_hypotheses}")
        self.output(f"Open: {summary.open}")
        self.output(f"Supported: {summary.supported}")
        self.output(f"Rejected: {summary.rejected}")
        self.output(f"Inconclusive: {summary.inconclusive}")
        self.output(f"Reasoning decisions: {summary.decision_count}")

    def render_summary(self, current: WorkspaceResult) -> None:
        summary = self._summary(current)
        if summary is None:
            return
        self.output("Reasoning Summary")
        self.output(f"Total hypotheses: {summary.total_hypotheses}")
        self.output(f"Open: {summary.open}")
        self.output(f"Supported: {summary.supported}")
        self.output(f"Rejected: {summary.rejected}")
        self.output(f"Inconclusive: {summary.inconclusive}")
        self.output(f"Total decisions: {summary.decision_count}")
        self.output(
            "Hypotheses without evidence: "
            + (", ".join(summary.hypotheses_lacking_evidence) or "None")
        )
        self.output(
            "Hypotheses with supporting and contradicting evidence: "
            + (", ".join(summary.mixed_evidence_hypotheses) or "None")
        )
        self.output(f"Last reasoning update: {summary.last_reasoning_update or 'None'}")
        self.output(
            "Hypothesis IDs: "
            + (", ".join(item.hypothesis_id for item in summary.hypotheses) or "None")
        )
        self.output("Decision IDs: " + (", ".join(summary.decision_ids) or "None"))

    def create_hypothesis(self, current: WorkspaceResult) -> WorkspaceResult:
        hypothesis_id = self.input("Hypothesis ID (blank to cancel): ").strip()
        if not hypothesis_id:
            self.output("Hypothesis creation cancelled.")
            return current
        statement = self.input("Statement: ")
        author = self.input("Analyst author label: ")
        supporting = self._choose_optional_evidence(current, "supporting")
        contradicting = self._choose_optional_evidence(current, "contradicting")
        self.output(f"Hypothesis: {hypothesis_id}")
        self.output(f"Supporting evidence: {len(supporting)}")
        self.output(f"Contradicting evidence: {len(contradicting)}")
        if not self._confirm("Create this hypothesis? (y/N): "):
            self.output("Hypothesis creation cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.create_hypothesis(
                current.investigation.investigation_id,
                hypothesis_id=hypothesis_id,
                statement=statement,
                author=author,
                expected_revision=current.revision,
                supporting_evidence_ids=supporting,
                contradicting_evidence_ids=contradicting,
            ),
            draft=statement,
            success="Hypothesis created",
        )

    def list_hypotheses(self, current: WorkspaceResult) -> tuple[Hypothesis, ...]:
        hypotheses = tuple(
            sorted(
                current.investigation.hypotheses,
                key=lambda item: item.hypothesis_id,
            )
        )
        if not hypotheses:
            self.output("No analyst-authored hypotheses.")
            return ()
        for item in hypotheses:
            self.output(
                f"{item.hypothesis_id} | {item.state.upper()} | "
                f"{item.author or 'Unknown'} | {item.created_at or 'Unknown'} | "
                f"{item.updated_at or 'Unknown'}"
            )
            self.output(f"  Statement: {self._bounded(item.statement)}")
            self.output(
                f"  Supporting: {len(item.supporting_evidence_reference_ids)} | "
                f"Contradicting: {len(item.contradicting_evidence_reference_ids)}"
            )
        return hypotheses

    def open_hypothesis(self, current: WorkspaceResult) -> WorkspaceResult:
        selected = self._choose(
            self.list_hypotheses(current),
            "Hypothesis number (blank to return): ",
        )
        if selected is None:
            return current
        hypothesis_id = selected.hypothesis_id
        while True:
            hypothesis = self._hypothesis(current, hypothesis_id)
            if hypothesis is None:
                self.output("Hypothesis is no longer available.")
                return current
            self._render_hypothesis(current, hypothesis)
            if hypothesis.state == "open":
                self.output("[1] Edit statement")
            self.output("[2] Add supporting evidence")
            self.output("[3] Add contradicting evidence")
            self.output("[4] Remove supporting evidence")
            self.output("[5] Remove contradicting evidence")
            if hypothesis.state == "open":
                self.output("[6] Assess hypothesis")
            else:
                self.output("[7] Reopen for further investigation")
            self.output("[8] View related decisions")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self.edit_statement(current, hypothesis)
            elif choice == "2":
                current = self.add_evidence(current, hypothesis, "supporting")
            elif choice == "3":
                current = self.add_evidence(current, hypothesis, "contradicting")
            elif choice == "4":
                current = self.remove_evidence(current, hypothesis, "supporting")
            elif choice == "5":
                current = self.remove_evidence(current, hypothesis, "contradicting")
            elif choice == "6" and hypothesis.state == "open":
                current = self.assess_hypothesis(current, hypothesis)
            elif choice == "7" and hypothesis.state != "open":
                current = self.reopen_hypothesis(current, hypothesis)
            elif choice == "8":
                self.view_related_decisions(current, hypothesis_id)
            else:
                self.output("Invalid option for the current hypothesis state.")
                continue
            self.pause()

    def edit_statement(self, current: WorkspaceResult, hypothesis: Hypothesis) -> WorkspaceResult:
        statement = self.input("New statement (blank to cancel): ")
        if not statement.strip():
            self.output("Statement edit cancelled.")
            return current
        author = self.input("Analyst author label: ")
        if not self._confirm("Save statement change? (y/N): "):
            self.output("Statement edit cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.edit_hypothesis_statement(
                current.investigation.investigation_id,
                hypothesis.hypothesis_id,
                statement=statement,
                author=author,
                expected_revision=current.revision,
            ),
            draft=statement,
            success="Hypothesis statement updated",
        )

    def add_evidence(self, current: WorkspaceResult, hypothesis: Hypothesis, relationship: str) -> WorkspaceResult:
        excluded = set(hypothesis.supporting_evidence_reference_ids).union(
            hypothesis.contradicting_evidence_reference_ids
        )
        evidence = self._choose_evidence(
            self._eligible_evidence(current, relationship, excluded),
            f"{relationship.title()} evidence number (blank to cancel): ",
        )
        if evidence is None:
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.add_hypothesis_evidence(
                current.investigation.investigation_id,
                hypothesis.hypothesis_id,
                evidence.reference_id,
                relationship=relationship,
                expected_revision=current.revision,
            ),
            success=f"{relationship.title()} evidence relationship added",
        )

    def remove_evidence(self, current: WorkspaceResult, hypothesis: Hypothesis, relationship: str) -> WorkspaceResult:
        ids = (
            hypothesis.supporting_evidence_reference_ids
            if relationship == "supporting"
            else hypothesis.contradicting_evidence_reference_ids
        )
        evidence = self._choose_evidence(
            tuple(item for item in self._selected_evidence(current) if item.reference_id in ids),
            f"{relationship.title()} relationship number (blank to cancel): ",
        )
        if evidence is None:
            return current
        if not self._confirm("Remove from hypothesis only? Selected evidence will remain. (y/N): "):
            self.output("Relationship removal cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.remove_hypothesis_evidence(
                current.investigation.investigation_id,
                hypothesis.hypothesis_id,
                evidence.reference_id,
                relationship=relationship,
                expected_revision=current.revision,
            ),
            success="Evidence relationship removed",
        )

    def assess_hypothesis(self, current: WorkspaceResult, hypothesis: Hypothesis) -> WorkspaceResult:
        state = self._choose_value(
            ("supported", "rejected", "inconclusive"),
            "Assessment state number (blank to cancel): ",
        )
        if state is None:
            return current
        rationale = self.input("Assessment rationale: ")
        author = self.input("Analyst author label: ")
        decision_id = self.input("Assessment decision ID: ").strip()
        self.output(f"Hypothesis: {hypothesis.hypothesis_id}")
        self.output(f"New state: {state}")
        self.output(f"Supporting evidence: {len(hypothesis.supporting_evidence_reference_ids)}")
        self.output(f"Contradicting evidence: {len(hypothesis.contradicting_evidence_reference_ids)}")
        if not self._confirm("Record this assessment? (y/N): "):
            self.output("Assessment cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.assess_hypothesis(
                current.investigation.investigation_id,
                hypothesis.hypothesis_id,
                state=state,
                rationale=rationale,
                author=author,
                decision_id=decision_id,
                expected_revision=current.revision,
            ),
            draft=rationale,
            success="Hypothesis assessment recorded",
        )

    def reopen_hypothesis(self, current: WorkspaceResult, hypothesis: Hypothesis) -> WorkspaceResult:
        rationale = self.input("Reopening rationale: ")
        author = self.input("Analyst author label: ")
        decision_id = self.input("Reopening decision ID: ").strip()
        if not self._confirm("Reopen for further investigation? (y/N): "):
            self.output("Reopening cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.reopen_hypothesis(
                current.investigation.investigation_id,
                hypothesis.hypothesis_id,
                rationale=rationale,
                author=author,
                decision_id=decision_id,
                expected_revision=current.revision,
            ),
            draft=rationale,
            success="Hypothesis reopened",
        )

    def view_decisions(self, current: WorkspaceResult) -> tuple[Decision, ...]:
        decisions = self._ordered_decisions(current.investigation.decisions)
        if not decisions:
            self.output("No analyst decisions.")
            return ()
        for item in decisions:
            self.output(
                f"{item.decision_id} | {item.decision_type} | "
                f"{item.decided_by or 'Unknown'} | {item.decided_at or 'Unknown'}"
            )
            self.output(f"  Rationale: {self._bounded(item.rationale)}")
            self.output(
                f"  Related hypotheses: {len(item.hypothesis_ids)} | "
                f"Related evidence: {len(item.evidence_reference_ids)}"
            )
        selected = self._choose(decisions, "Decision number for details (blank to return): ")
        if selected is not None:
            self._render_decision(selected)
        return decisions

    def view_related_decisions(self, current: WorkspaceResult, hypothesis_id: str) -> tuple[Decision, ...]:
        decisions = self._ordered_decisions(
            item for item in current.investigation.decisions
            if hypothesis_id in item.hypothesis_ids
        )
        if not decisions:
            self.output("No assessment history for this hypothesis.")
            return ()
        for item in decisions:
            self._render_decision(item)
        return decisions

    def show_hypothesis_details(
        self,
        current: WorkspaceResult,
        hypothesis_id: str,
    ) -> None:
        """Render an existing hypothesis without entering its write-action loop."""
        hypothesis = self._hypothesis(current, hypothesis_id)
        if hypothesis is None:
            self.output("Hypothesis is no longer available.")
            return
        self._render_hypothesis(current, hypothesis)

    def show_decision_details(
        self,
        current: WorkspaceResult,
        decision_id: str,
    ) -> None:
        """Render an existing decision, including unknown legacy decision types."""
        decision = next(
            (
                item
                for item in current.investigation.decisions
                if item.decision_id == decision_id
            ),
            None,
        )
        if decision is None:
            self.output("Decision is no longer available.")
            return
        self._render_decision(decision)

    def record_decision(self, current: WorkspaceResult) -> WorkspaceResult:
        decision_id = self.input("Decision ID (blank to cancel): ").strip()
        if not decision_id:
            self.output("Decision recording cancelled.")
            return current
        decision_type = self._choose_value(GENERAL_DECISION_TYPES, "Decision type number: ")
        if decision_type is None:
            return current
        if decision_type == "containment_recommendation":
            self.output(
                "A containment recommendation records analyst reasoning. "
                "It does not perform containment."
            )
        outcome = self.input("Outcome or disposition: ")
        rationale = self.input("Rationale: ")
        author = self.input("Analyst author label: ")
        hypotheses = self._choose_many(current.investigation.hypotheses, "Related hypothesis")
        evidence = self._choose_many(self._selected_evidence(current), "Related evidence")
        if not self._confirm("Record this append-only decision? (y/N): "):
            self.output("Decision recording cancelled.")
            return current
        return self._modify(
            current,
            lambda: self.reasoning_service.record_investigation_decision(
                current.investigation.investigation_id,
                decision_id=decision_id,
                decision_type=decision_type,
                outcome=outcome,
                rationale=rationale,
                author=author,
                expected_revision=current.revision,
                hypothesis_ids=tuple(item.hypothesis_id for item in hypotheses),
                evidence_reference_ids=tuple(item.reference_id for item in evidence),
            ),
            draft=rationale,
            success="Investigation decision recorded",
        )


    def _render_hypothesis(self, current: WorkspaceResult, hypothesis: Hypothesis) -> None:
        self.screen("HYPOTHESIS DETAILS")
        for line in render_hypothesis(current, hypothesis).splitlines():
            self.output(line)
        self.output(
            "Underlying source details require the matching active analysis in "
            "the evidence workspace."
        )

    def _render_evidence(self, evidence: EvidenceReference) -> None:
        self.output(
            f"  {evidence.reference_id} | "
            f"{evidence.evidence_type or evidence.source_type} | "
            f"{evidence.classification}"
        )
        self.output(f"    Rationale: {self._bounded(evidence.rationale or 'None')}")
        self.output(f"    Source identifier: {evidence.source_id}")

    def _render_decision(self, decision: Decision) -> None:
        for line in render_decision(decision).splitlines():
            self.output(line)

    def _summary(self, current: WorkspaceResult):
        try:
            return self.reasoning_service.reasoning_summary(
                current.investigation.investigation_id
            )
        except (InvestigationReasoningError, InvestigationRepositoryError) as exc:
            self.output(f"Reasoning summary unavailable: {exc}")
            return None

    def _eligible_evidence(
        self,
        current: WorkspaceResult,
        relationship: str,
        excluded: Iterable[str] = (),
    ) -> tuple[EvidenceReference, ...]:
        excluded_ids = set(excluded)
        return tuple(
            item
            for item in self._selected_evidence(current)
            if item.classification == relationship
            and item.reference_id not in excluded_ids
        )

    @staticmethod
    def _selected_evidence(current: WorkspaceResult) -> tuple[EvidenceReference, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in current.investigation.evidence_references
                    if item.origin == "analyst_selection"
                ),
                key=lambda item: item.reference_id,
            )
        )

    def _choose_optional_evidence(
        self, current: WorkspaceResult, relationship: str
    ) -> tuple[str, ...]:
        selected = self._choose_evidence(
            self._eligible_evidence(current, relationship),
            f"Initial {relationship} evidence number (blank for none): ",
        )
        return () if selected is None else (selected.reference_id,)

    def _choose_evidence(
        self,
        choices: tuple[EvidenceReference, ...],
        prompt: str,
    ) -> EvidenceReference | None:
        if not choices:
            self.output("No compatible analyst-selected evidence is available.")
            return None
        for index, item in enumerate(choices, start=1):
            self.output(
                f"[{index}] {item.reference_id} | {item.evidence_type} | "
                f"{self._bounded(item.rationale or '')} | {item.source_id} | SENSITIVE"
            )
        return self._choose(choices, prompt)

    def _choose_many(
        self, items: Iterable[object], label: str
    ) -> tuple[object, ...]:
        choices = tuple(items)
        if not choices:
            return ()
        for index, item in enumerate(choices, start=1):
            identifier = getattr(
                item, "hypothesis_id", getattr(item, "reference_id", "Unknown")
            )
            self.output(f"[{index}] {identifier}")
        raw = self.input(
            f"{label} numbers (comma-separated, blank for none): "
        ).strip()
        if not raw:
            return ()
        indexes = []
        for value in raw.split(","):
            value = value.strip()
            if not value.isdigit() or not 1 <= int(value) <= len(choices):
                self.output(f"Invalid {label.lower()} selection.")
                return ()
            indexes.append(int(value) - 1)
        return tuple(choices[index] for index in dict.fromkeys(indexes))

    def _choose_value(self, values: tuple[str, ...], prompt: str) -> str | None:
        for index, value in enumerate(values, start=1):
            self.output(f"[{index}] {value}")
        return self._choose(values, prompt)

    def _choose(self, items: tuple, prompt: str):
        raw = self.input(prompt).strip()
        if not raw:
            return None
        if not raw.isdigit() or not 1 <= int(raw) <= len(items):
            self.output("Invalid selection.")
            return None
        return items[int(raw) - 1]

    def _modify(
        self,
        current: WorkspaceResult,
        operation: Callable[[], WorkspaceResult],
        *,
        draft: str = "",
        success: str,
    ) -> WorkspaceResult:
        try:
            updated = operation()
        except InvestigationConflictError:
            self.output(
                "Another session changed the reasoning state. "
                "No retry or merge was attempted."
            )
            if draft:
                self.output(f"Your drafted text: {self._bounded(draft)}")
            try:
                latest = (
                    self.reasoning_service.workspace_service.get_investigation(
                        current.investigation.investigation_id
                    )
                )
            except InvestigationRepositoryError:
                self.output("The authoritative investigation could not be reloaded.")
                return current
            self.output(f"Authoritative revision: {latest.revision}")
            return latest
        except (
            InvestigationReasoningError,
            InvestigationRepositoryError,
            ValueError,
        ) as exc:
            self.output(f"Reasoning update failed: {exc}")
            return current
        self.output(f"{success} at revision {updated.revision}.")
        return updated

    @staticmethod
    def _hypothesis(
        current: WorkspaceResult, hypothesis_id: str
    ) -> Hypothesis | None:
        return next(
            (
                item
                for item in current.investigation.hypotheses
                if item.hypothesis_id == hypothesis_id
            ),
            None,
        )

    @staticmethod
    def _ordered_decisions(
        decisions: Iterable[Decision],
    ) -> tuple[Decision, ...]:
        return tuple(
            sorted(
                decisions,
                key=lambda item: (item.decided_at or "", item.decision_id),
            )
        )

    def _confirm(self, prompt: str) -> bool:
        return self.input(prompt).strip().lower() in {"y", "yes"}

    @staticmethod
    def _bounded(value: str) -> str:
        text = str(value).replace("\r", " ").replace("\n", " ")
        if len(text) <= DISPLAY_VALUE_LIMIT:
            return text
        return text[: DISPLAY_VALUE_LIMIT - 3] + "..."
