from __future__ import annotations

from typing import Callable, Iterable

from soc_forge.investigations.evidence_catalog import (
    AnalysisEvidenceCatalog,
    EvidenceCatalogError,
)
from soc_forge.investigations.evidence_models import EvidenceCandidate
from soc_forge.investigations.evidence_service import (
    InvestigationEvidenceError,
    InvestigationEvidenceService,
)
from soc_forge.investigations.models import EvidenceReference
from soc_forge.investigations.repository import (
    InvestigationConflictError,
    InvestigationRepositoryError,
)
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.screen import begin_screen


DISPLAY_VALUE_LIMIT = 160
FILTERS = (
    ("All supported types", None),
    ("Events", ("event",)),
    ("Alerts", ("alert",)),
    ("Cases", ("case",)),
    ("Reconstruction steps", ("reconstruction_step",)),
)
CLASSIFICATIONS = ("supporting", "contradicting", "context")


class EvidenceConsoleController:
    """Terminal presentation for catalog-backed investigation evidence workflows."""

    def __init__(
        self,
        *,
        catalog: AnalysisEvidenceCatalog,
        evidence_service: InvestigationEvidenceService,
        analysis_provider: Callable[[], object | None],
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
    ):
        self.catalog = catalog
        self.evidence_service = evidence_service
        self.analysis_provider = analysis_provider
        self.input = input_func
        self.output = output_func
        self.screen = screen_func

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            self.screen("INVESTIGATION EVIDENCE")
            self.render_counts(current)
            self.output("")
            self.output("[1] Browse evidence candidates")
            self.output("[2] View selected evidence")
            self.output("[3] Inspect selected evidence")
            self.output("[4] Update selected evidence")
            self.output("[5] Remove selected evidence")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                current = self.browse(current)
            elif choice == "2":
                self.view_selected(current)
            elif choice == "3":
                self.inspect_selected(current)
            elif choice == "4":
                current = self.update_selected(current)
            elif choice == "5":
                current = self.remove_selected(current)
            else:
                self.output("Invalid option.")

    def render_counts(self, current: WorkspaceResult) -> None:
        references = current.investigation.evidence_references
        scope = [item for item in references if item.origin == "scope"]
        selected = [item for item in references if item.origin == "analyst_selection"]
        self.output(f"Scope references: {len(scope)}")
        self.output(f"Analyst-selected evidence: {len(selected)}")
        for classification, label in (
            ("supporting", "Supporting"),
            ("contradicting", "Contradicting"),
            ("context", "Context"),
        ):
            self.output(
                f"{label}: "
                f"{sum(item.classification == classification for item in selected)}"
            )

    def browse(self, current: WorkspaceResult) -> WorkspaceResult:
        analysis = self._matching_analysis(current)
        if analysis is None:
            return current
        for index, (label, _types) in enumerate(FILTERS, start=1):
            self.output(f"[{index}] {label}")
        choice = self.input("Evidence filter (blank for all): ").strip()
        if not choice:
            choice = "1"
        if not choice.isdigit() or not 1 <= int(choice) <= len(FILTERS):
            self.output("Invalid evidence filter.")
            return current
        evidence_types = FILTERS[int(choice) - 1][1]
        try:
            candidates = self.catalog.list_candidates(
                analysis,
                case_ids=self._scope_case_ids(current),
                evidence_types=evidence_types,
            )
        except EvidenceCatalogError:
            self.output("Evidence candidates could not be loaded safely.")
            return current
        if not candidates:
            self.output("No evidence candidates match this filter.")
            return current
        self._render_candidates(candidates)
        selection = self.choose_index(
            candidates, "Candidate number to inspect (blank to return): "
        )
        if selection is None:
            return current
        candidate = candidates[selection]
        self.show_candidate_details(analysis, candidate)
        if not candidate.selectable:
            self.output("This candidate cannot be selected.")
            return current
        if self.input("Select this evidence? (y/N): ").strip().lower() in {"y", "yes"}:
            return self.select_candidate(current, candidate)
        return current

    def show_candidate_details(self, analysis: object, candidate: EvidenceCandidate) -> None:
        self.screen("EVIDENCE DETAILS")
        self.output(f"Evidence ID: {candidate.evidence_id}")
        self.output(f"Evidence type: {candidate.evidence_type}")
        self.output(f"Source analysis ID: {candidate.source_analysis_id}")
        self.output(f"Source identifier: {candidate.source_id}")
        self.output(f"Title: {candidate.title}")
        self.output(f"Summary: {self._bounded(candidate.summary)}")
        self.output(f"Timestamp: {candidate.timestamp or 'Unknown'}")
        self.output(f"Related cases: {', '.join(candidate.case_ids) or 'None'}")
        self.output(f"Rule ID: {candidate.rule_id or 'None'}")
        self.output(f"ATT&CK tactic: {candidate.tactic or 'None'}")
        self.output(f"ATT&CK technique: {candidate.technique or 'None'}")
        self.output(
            f"Entities: {', '.join(candidate.entity_references) or 'None'}"
        )
        self.output(
            f"Sensitive fields: {', '.join(candidate.sensitive_fields) or 'None'}"
        )
        self.output(
            f"Provenance limitation: {candidate.limitation_reason or 'None'}"
        )
        try:
            details = self.catalog.resolve_details(analysis, candidate.evidence_id)
        except EvidenceCatalogError:
            self.output("Source details are not currently resolvable.")
            return
        show_sensitive = True
        if any(field.sensitive for field in details.fields):
            self.output(
                "Warning: sensitive values may remain in terminal scrollback."
            )
            show_sensitive = self.input(
                "Display sensitive field values? (y/N): "
            ).strip().lower() in {"y", "yes"}
        for field in details.fields:
            provenance = field.provenance
            value = (
                self._bounded(field.value)
                if show_sensitive or not field.sensitive
                else "[hidden - confirmation required]"
            )
            self.output(f"Field: {field.field_name}")
            self.output(f"  Displayed value: {value}")
            self.output(f"  Source type: {provenance.source_type}")
            self.output(f"  Source ID: {provenance.source_id}")
            self.output(f"  Source field: {provenance.source_field}")
            self.output(f"  Interpretation layer: {provenance.source_kind}")
            self.output(f"  Normalized: {'yes' if provenance.normalized else 'no'}")
            self.output(f"  Sensitive: {'yes' if field.sensitive else 'no'}")

    def show_evidence_details(
        self,
        current: WorkspaceResult,
        evidence_id: str,
    ) -> None:
        """Render one selected evidence item through the established detail path."""
        analysis = self._matching_analysis(current, explain=False)
        if analysis is None:
            self.output(
                "Source details cannot be resolved until the matching analysis is loaded or rerun."
            )
            return
        try:
            candidate = self.catalog.get_candidate(analysis, evidence_id)
        except EvidenceCatalogError:
            self.output("The selected source evidence is not currently available.")
            return
        self.show_candidate_details(analysis, candidate)

    def select_candidate(
        self,
        current: WorkspaceResult,
        candidate: EvidenceCandidate,
    ) -> WorkspaceResult:
        classification = self._choose_classification()
        if classification is None:
            self.output("Evidence selection cancelled.")
            return current
        rationale = self.input("Analyst rationale: ")
        author = self.input("Author label: ")
        if self.input("Save evidence selection? (y/N): ").strip().lower() not in {
            "y",
            "yes",
        }:
            self.output("Evidence selection cancelled.")
            return current
        try:
            updated = self.evidence_service.select_evidence(
                current.investigation.investigation_id,
                candidate,
                classification=classification,
                rationale=rationale,
                author=author,
                expected_revision=current.revision,
            )
        except InvestigationConflictError:
            return self._conflict(current, rationale)
        except InvestigationEvidenceError as exc:
            self.output(f"Evidence selection failed: {exc}")
            return current
        self.output(f"Evidence selected at revision {updated.revision}.")
        return updated

    def view_selected(self, current: WorkspaceResult) -> None:
        scope = self._scope_references(current)
        selected = self._selected_references(current)
        self.output("Investigation Scope References")
        if not scope:
            self.output("  None")
        for item in scope:
            self.output(f"  {item.reference_id} | {item.source_type}:{item.source_id}")
        self.output("Analyst-Selected Evidence")
        if not selected:
            self.output("  None")
        for item in selected:
            warning = (
                " | SENSITIVE"
                if item.provenance_fields
                and any(
                    token in item.provenance_fields
                    for token in ("command_line", "message", "raw_message")
                )
                else ""
            )
            self.output(
                f"  {item.reference_id} | {item.evidence_type} | "
                f"{item.classification} | {item.selected_by} | "
                f"{item.selected_at} | {item.source_id}{warning}"
            )
            self.output(f"    Rationale: {self._bounded(item.rationale or '')}")

    def inspect_selected(self, current: WorkspaceResult) -> None:
        reference = self._choose_selected(current, "Selection number to inspect: ")
        if reference is None:
            return
        self._render_selection_metadata(reference)
        analysis = self._matching_analysis(current, explain=False)
        if analysis is None:
            self.output(
                "Source details cannot be resolved until the matching analysis is loaded or rerun."
            )
            return
        try:
            candidate = self.catalog.get_candidate(analysis, reference.reference_id)
        except EvidenceCatalogError:
            self.output(
                "Warning: the selected source evidence no longer resolves in the active analysis."
            )
            return
        self.show_candidate_details(analysis, candidate)

    def update_selected(self, current: WorkspaceResult) -> WorkspaceResult:
        reference = self._choose_selected(current, "Selection number to update: ")
        if reference is None:
            return current
        self.output("Leave a value blank to preserve the current value.")
        classification = self.input(
            f"Classification [{reference.classification}]: "
        ).strip() or None
        rationale = self.input("Rationale [keep current]: ")
        author = self.input(f"Author [{reference.selected_by}]: ")
        rationale_value = rationale if rationale.strip() else None
        author_value = author if author.strip() else None
        if classification is None and rationale_value is None and author_value is None:
            self.output("No evidence changes requested.")
            return current
        if self.input("Update evidence selection? (y/N): ").strip().lower() not in {
            "y",
            "yes",
        }:
            self.output("Evidence update cancelled.")
            return current
        attempted = rationale_value or reference.rationale or ""
        try:
            updated = self.evidence_service.update_evidence_rationale(
                current.investigation.investigation_id,
                reference.reference_id,
                classification=classification,
                rationale=rationale_value,
                author=author_value,
                expected_revision=current.revision,
            )
        except InvestigationConflictError:
            return self._conflict(current, attempted)
        except InvestigationEvidenceError as exc:
            self.output(f"Evidence update failed: {exc}")
            return current
        self.output(f"Evidence updated at revision {updated.revision}.")
        return updated

    def remove_selected(self, current: WorkspaceResult) -> WorkspaceResult:
        reference = self._choose_selected(current, "Selection number to remove: ")
        if reference is None:
            return current
        relationships = self._relationships(current, reference.reference_id)
        if relationships:
            self.output(
                "Warning: this evidence is referenced by "
                + ", ".join(relationships)
                + ". Remove those relationships first."
            )
        if self.input(
            f"Remove selected evidence {reference.reference_id}? (y/N): "
        ).strip().lower() not in {"y", "yes"}:
            self.output("Evidence removal cancelled.")
            return current
        try:
            updated = self.evidence_service.remove_evidence(
                current.investigation.investigation_id,
                reference.reference_id,
                expected_revision=current.revision,
            )
        except InvestigationConflictError:
            return self._conflict(current, "")
        except (InvestigationEvidenceError, ValueError) as exc:
            self.output(f"Evidence removal failed: {exc}")
            return current
        self.output(f"Evidence removed at revision {updated.revision}.")
        return updated

    def _matching_analysis(
        self,
        current: WorkspaceResult,
        *,
        explain: bool = True,
    ) -> object | None:
        analysis = self.analysis_provider()
        if analysis is None:
            if explain:
                self.output(
                    "No active analysis is available. Source analysis must be loaded or rerun."
                )
            return None
        try:
            analysis_id = self.catalog.source_analysis_id(analysis)
        except (EvidenceCatalogError, ValueError, TypeError):
            if explain:
                self.output("The active analysis cannot be validated safely.")
            return None
        if analysis_id != current.investigation.analysis_id:
            if explain:
                self.output(
                    "The active analysis does not match this investigation's provenance. "
                    "Load or rerun the source analysis."
                )
            return None
        return analysis

    def _render_candidates(self, candidates: Iterable[EvidenceCandidate]) -> None:
        for index, item in enumerate(candidates, start=1):
            warning = " | SENSITIVE" if item.sensitive_fields else ""
            limitation = (
                f" | LIMITATION: {item.limitation_reason}"
                if item.limitation_reason
                else ""
            )
            self.output(
                f"[{index}] {item.evidence_id[:24]} | {item.evidence_type} | "
                f"{item.title} | {item.timestamp or 'Unknown'} | {item.source_id} | "
                f"Rule {item.rule_id or 'None'} | Cases "
                f"{','.join(item.case_ids) or 'None'}{warning}{limitation}"
            )

    def _choose_selected(
        self,
        current: WorkspaceResult,
        prompt: str,
    ) -> EvidenceReference | None:
        selected = self._selected_references(current)
        if not selected:
            self.output("No analyst-selected evidence.")
            return None
        for index, item in enumerate(selected, start=1):
            self.output(
                f"[{index}] {item.reference_id} | {item.classification} | "
                f"{item.source_id}"
            )
        index = self.choose_index(selected, prompt)
        return selected[index] if index is not None else None

    def _render_selection_metadata(self, item: EvidenceReference) -> None:
        self.output(f"Evidence ID: {item.reference_id}")
        self.output(f"Evidence type: {item.evidence_type}")
        self.output(f"Classification: {item.classification}")
        self.output(f"Author: {item.selected_by}")
        self.output(f"Selected: {item.selected_at}")
        self.output(f"Updated: {item.selection_updated_at}")
        self.output(f"Rationale: {self._bounded(item.rationale or '')}")
        self.output(f"Source identifier: {item.source_id}")

    def _conflict(self, current: WorkspaceResult, attempted_rationale: str) -> WorkspaceResult:
        self.output(
            "Another session changed this workspace. No evidence change was retried."
        )
        if attempted_rationale:
            self.output(
                "Attempted rationale (not saved): "
                + self._bounded(attempted_rationale)
            )
        try:
            latest = self.evidence_service.workspace_service.get_investigation(
                current.investigation.investigation_id
            )
        except InvestigationRepositoryError:
            self.output("The latest investigation revision could not be reloaded.")
            return current
        self.output(f"Reloaded latest revision {latest.revision}.")
        return latest

    @staticmethod
    def _scope_case_ids(current: WorkspaceResult) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    item.source_id
                    for item in current.investigation.evidence_references
                    if item.origin == "scope" and item.source_type == "case"
                }
            )
        )

    @staticmethod
    def _scope_references(current: WorkspaceResult) -> tuple[EvidenceReference, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in current.investigation.evidence_references
                    if item.origin == "scope"
                ),
                key=lambda item: item.reference_id,
            )
        )

    @staticmethod
    def _selected_references(current: WorkspaceResult) -> tuple[EvidenceReference, ...]:
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

    @staticmethod
    def _relationships(current: WorkspaceResult, evidence_id: str) -> tuple[str, ...]:
        relationships = []
        for hypothesis in current.investigation.hypotheses:
            if evidence_id in (
                hypothesis.supporting_evidence_reference_ids
                + hypothesis.contradicting_evidence_reference_ids
            ):
                relationships.append(f"hypothesis {hypothesis.hypothesis_id}")
        for decision in current.investigation.decisions:
            if evidence_id in decision.evidence_reference_ids:
                relationships.append(f"decision {decision.decision_id}")
        return tuple(relationships)

    def _choose_classification(self) -> str | None:
        for index, value in enumerate(CLASSIFICATIONS, start=1):
            self.output(f"[{index}] {value}")
        choice = self.input("Classification (blank to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(CLASSIFICATIONS):
            return CLASSIFICATIONS[int(choice) - 1]
        return choice


    def choose_index(self, items: Iterable[object], prompt: str) -> int | None:
        values = tuple(items)
        choice = self.input(prompt).strip()
        if not choice:
            return None
        if not choice.isdigit() or not 1 <= int(choice) <= len(values):
            self.output("Invalid selection.")
            return None
        return int(choice) - 1

    @staticmethod
    def _bounded(value: str) -> str:
        normalized = value.replace("\r", " ").replace("\n", " ")
        if len(normalized) <= DISPLAY_VALUE_LIMIT:
            return normalized
        return normalized[: DISPLAY_VALUE_LIMIT - 3] + "..."
