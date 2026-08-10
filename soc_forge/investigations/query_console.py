from __future__ import annotations

from dataclasses import fields, replace
from typing import Callable, Iterable

from soc_forge.investigations.evidence_catalog import EvidenceCatalogError
from soc_forge.investigations.evidence_console import EvidenceConsoleController
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.query_models import (
    ENTITY_TYPES,
    TIMELINE_ENTRY_TYPES,
    InvestigationEntity,
    InvestigationQueryError,
    InvestigationTimelineEntry,
    InvestigationTimelineFilters,
    PivotResult,
    RelatedEntitiesResult,
)
from soc_forge.investigations.reasoning_console import ReasoningConsoleController
from soc_forge.investigations.repository import InvestigationRepositoryError
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)
from soc_forge.ui.screen import begin_screen


FILTER_OPTIONS = (
    ("Start time", "start_time"),
    ("End time", "end_time"),
    ("Entry type", "entry_types"),
    ("Host", "host"),
    ("User", "user"),
    ("IP", "ip"),
    ("Process", "process"),
    ("Rule ID", "rule_id"),
    ("ATT&CK tactic", "attack_tactic"),
    ("ATT&CK technique", "attack_technique"),
    ("Severity", "severity"),
    ("Evidence classification", "evidence_classification"),
    ("Hypothesis ID", "hypothesis_id"),
    ("Case ID", "case_id"),
)
ENTITY_LABELS = {
    **{item: item.replace("_", " ").title() for item in ENTITY_TYPES},
    "attack_technique": "ATT&CK technique",
}


class InvestigationQueryConsoleController:
    """Read-only terminal adapter for canonical timeline and pivot queries."""

    def __init__(
        self,
        *,
        workspace_service: InvestigationWorkspaceService,
        analysis_provider: Callable[[], object | None],
        evidence_controller: EvidenceConsoleController,
        reasoning_controller: ReasoningConsoleController,
        timeline_service: InvestigationTimelineService | None = None,
        pivot_service: InvestigationPivotService | None = None,
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
    ) -> None:
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider
        self.evidence_controller = evidence_controller
        self.reasoning_controller = reasoning_controller
        self.timeline_service = timeline_service or InvestigationTimelineService()
        self.pivot_service = pivot_service or InvestigationPivotService()
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: None)
        self.filters = InvestigationTimelineFilters()
        self.selected_entity: InvestigationEntity | None = None

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        context = self._open_context(current)
        if context is None:
            return current
        opened_revision = current.revision
        while True:
            latest_revision = self._latest_revision(current)
            stale = latest_revision is not None and latest_revision != opened_revision
            self.screen("TIMELINE/PIVOT WORKBENCH - READ ONLY")
            self.output("Timeline/Pivot Workbench - Read Only")
            self.output(f"Investigation: {current.investigation.investigation_id}")
            self.output(f"Workspace revision: {current.revision}")
            self.output("Warning: terminal scrollback may retain displayed values.")
            if stale:
                self.output(
                    "The investigation changed. Refresh the workbench before "
                    "continuing with reasoning overlays."
                )
            self.output("")
            self.output("[1] Investigation timeline")
            self.output("[2] Filter timeline")
            self.output("[3] Browse entities")
            self.output("[4] Pivot from entity")
            self.output("[5] Inspect evidence relationship")
            self.output("[6] Inspect hypothesis relationships")
            self.output("[7] View query limitations")
            self.output("[8] Refresh workbench")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if stale and choice != "8":
                self.output("Refresh Workbench is required before running this query.")
                continue
            if not self._analysis_matches(context):
                self.output(
                    "The active analysis changed and no longer matches this workbench. "
                    "Leave and reopen it with the matching completed analysis."
                )
                return current
            if choice == "1":
                self.timeline_screen(context, current)
            elif choice == "2":
                self.filter_screen(context)
            elif choice == "3":
                self.selected_entity = self.entity_browser(context)
                if self.selected_entity is not None:
                    self.pause()
            elif choice == "4":
                self.pivot_screen(context, self.selected_entity)
            elif choice == "5":
                if self.inspect_evidence(current, context):
                    self.pause()
            elif choice == "6":
                if self.inspect_hypothesis(current):
                    self.pause()
            elif choice == "7":
                self.render_limitations(context)
                self.pause()
            elif choice == "8":
                refreshed = self._refresh(current)
                if refreshed is not None:
                    current, context = refreshed
                    opened_revision = current.revision
                self.pause()
            else:
                self.output("Invalid option.")
                self.pause()

    def timeline_screen(
        self,
        context: InvestigationQueryContext,
        current: WorkspaceResult | None = None,
    ) -> None:
        while True:
            self.screen("INVESTIGATION TIMELINE - READ ONLY")
            self.render_active_filters()
            try:
                timeline = self.timeline_service.timeline(context, filters=self.filters)
            except InvestigationQueryError:
                self.output("The timeline filters could not be applied safely.")
                self.pause()
                return
            entries = self.render_timeline(timeline)
            if not entries:
                self.pause()
                return
            selected = self._choose(
                entries,
                "Timeline entry number for details (blank to return): ",
            )
            if selected is None:
                return
            self.render_entry_detail(selected)
            if current is None:
                self.pause()
            else:
                self.entry_navigation(current, context, selected)

    def render_timeline(self, timeline) -> tuple[InvestigationTimelineEntry, ...]:
        ordered = tuple(timeline.entries) + tuple(timeline.untimed_entries)
        index = 1
        self.output("Chronological Activity")
        if not timeline.entries:
            self.output("  No timed entries.")
        for entry in timeline.entries:
            self.output(self._timeline_row(index, entry))
            index += 1
        self.output("Untimed Investigation Context")
        if not timeline.untimed_entries:
            self.output("  No untimed entries.")
        for entry in timeline.untimed_entries:
            self.output(self._timeline_row(index, entry, untimed=True))
            if entry.limitations:
                self.output(f"    Untimed reason: {entry.limitations[0]}")
            index += 1
        return ordered

    def render_entry_detail(self, entry: InvestigationTimelineEntry) -> None:
        self.screen("TIMELINE ENTRY DETAILS - READ ONLY")
        values = (
            ("Entry ID", entry.entry_id),
            ("Timestamp", entry.timestamp or "Untimed"),
            ("Entry type", entry.entry_type),
            ("Context", entry.context_kind),
            ("Source ID", entry.source_id),
            ("Source analysis ID", entry.source_analysis_id),
            ("Case IDs", ", ".join(entry.case_ids) or "None"),
            ("Title", entry.title),
            ("Summary", entry.summary),
            ("Host", entry.host or "None"),
            ("User", entry.user or "None"),
            ("IP", entry.ip or "None"),
            ("Process", entry.process or "None"),
            ("Rule ID", entry.rule_id or "None"),
            ("Severity", entry.severity or "None"),
            ("ATT&CK tactic", entry.attack_tactic or "None"),
            ("ATT&CK technique", entry.attack_technique or "None"),
            ("Evidence reference", entry.evidence_id or "None"),
            ("Evidence classification", entry.evidence_classification or "None"),
            ("Related hypothesis IDs", ", ".join(entry.related_hypothesis_ids) or "None"),
            ("Related decision IDs", ", ".join(entry.related_decision_ids) or "None"),
            ("Sensitive fields", ", ".join(entry.sensitive_fields) or "None"),
            ("Provenance fields", ", ".join(entry.provenance_fields) or "None"),
            ("Limitations", "; ".join(entry.limitations) or "None"),
        )
        for label, value in values:
            self.output(f"{label}: {value}")
        self.output(f"Why this entry is present: {entry.relationship_reason}")
        for overlay in entry.hypothesis_overlays:
            self.output(
                f"Hypothesis overlay: {overlay.hypothesis_id} | "
                f"{overlay.relationship} | {overlay.state}"
            )
        for overlay in entry.decision_overlays:
            self.output(
                f"Decision overlay: {overlay.decision_id} | {overlay.decision_type}"
            )

    def filter_screen(self, context: InvestigationQueryContext) -> None:
        while True:
            self.screen("TIMELINE FILTERS - TRANSIENT")
            self.render_active_filters()
            for index, (label, _field) in enumerate(FILTER_OPTIONS, start=1):
                self.output(f"[{index}] Set or adjust {label}")
            self.output("[15] Clear all filters")
            self.output("[16] View filtered timeline")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return
            if choice == "15":
                self.filters = InvestigationTimelineFilters()
                self.output("All timeline filters cleared.")
            elif choice == "16":
                self.timeline_screen(context)
            elif choice.isdigit() and 1 <= int(choice) <= len(FILTER_OPTIONS):
                label, field = FILTER_OPTIONS[int(choice) - 1]
                value = self.input(f"{label} (blank clears this filter): ").strip()
                self.adjust_filter(field, value)
                try:
                    self.timeline_service.timeline(context, filters=self.filters)
                except InvestigationQueryError:
                    self.filters = replace(
                        self.filters,
                        **{field: () if field == "entry_types" else None},
                    )
                    self.output("That filter value is invalid and was not retained.")
            else:
                self.output("Invalid option.")

    def adjust_filter(self, field: str, value: str) -> None:
        allowed = {item.name for item in fields(InvestigationTimelineFilters)}
        if field not in allowed:
            raise ValueError("Unsupported filter control")
        if field == "entry_types":
            rendered = (value,) if value else ()
        else:
            rendered = value or None
        self.filters = replace(self.filters, **{field: rendered})

    def render_active_filters(self) -> None:
        active = []
        labels = {field: label for label, field in FILTER_OPTIONS}
        for item in fields(self.filters):
            value = getattr(self.filters, item.name)
            if value:
                rendered = ", ".join(value) if isinstance(value, tuple) else value
                active.append((labels[item.name], rendered))
        self.output("Active Filters")
        if not active:
            self.output("  None")
        for label, value in active:
            self.output(f"  {label}: {value}")

    def entity_browser(
        self, context: InvestigationQueryContext
    ) -> InvestigationEntity | None:
        entities = self.entities(context)
        if not entities:
            self.output("No normalized entities are available.")
            self.pause()
            return None
        requested = self.input(
            "Entity type (host/user/ip/process/service/rule/attack_technique/"
            "case/evidence/hypothesis, blank for all): "
        ).strip()
        if requested and requested not in ENTITY_TYPES:
            self.output("Unsupported entity type.")
            self.pause()
            return None
        visible = tuple(item for item in entities if not requested or item.entity_type == requested)
        if not visible:
            self.output("No entities of that type were found.")
            self.pause()
            return None
        self.screen("INVESTIGATION ENTITIES - READ ONLY")
        for index, entity in enumerate(visible, start=1):
            self.output(
                f"[{index}] {ENTITY_LABELS[entity.entity_type].upper()} | "
                f"{entity.display_value}"
            )
        selected = self._choose(visible, "Entity number (blank to return): ")
        if selected is not None:
            self.render_entity_summary(context, selected)
        return selected

    def entities(self, context: InvestigationQueryContext) -> tuple[InvestigationEntity, ...]:
        return self.pivot_service.entities(context)

    def render_entity_summary(
        self, context: InvestigationQueryContext, entity: InvestigationEntity
    ) -> None:
        self.output(ENTITY_LABELS[entity.entity_type].upper())
        self.output(entity.display_value)
        self.output(f"Normalized identity: {entity.normalized_value}")
        events = self.pivot_service.events_for_entity(context, entity.entity_type, entity.value)
        alerts = self.pivot_service.alerts_for_entity(context, entity.entity_type, entity.value)
        cases = self.pivot_service.cases_for_entity(context, entity.entity_type, entity.value)
        evidence = self.pivot_service.evidence_for_entity(context, entity.entity_type, entity.value)
        self.output("Observed in:")
        self.output(f"  {len(events.matches)} events")
        self.output(f"  {len(alerts.matches)} alerts")
        self.output(f"  {len(cases.matches)} cases")
        self.output(
            f"  {sum(item.analyst_selected for item in evidence.matches)} evidence selections"
        )

    def pivot_screen(
        self,
        context: InvestigationQueryContext,
        entity: InvestigationEntity | None = None,
    ) -> None:
        selected = entity or self.entity_browser(context)
        if selected is None:
            return
        self.output(f"Pivot entity: {selected.entity_type} | {selected.display_value}")
        operations = (
            ("Events", self.pivot_service.events_for_entity),
            ("Alerts", self.pivot_service.alerts_for_entity),
            ("Cases", self.pivot_service.cases_for_entity),
            ("Evidence", self.pivot_service.evidence_for_entity),
            ("Hypotheses", self.pivot_service.hypotheses_for_entity),
        )
        for index, (label, _operation) in enumerate(operations, start=1):
            self.output(f"[{index}] {label}")
        self.output("[6] Related entities")
        self.output("[7] Timeline")
        self.output("[0] Back")
        choice = self.input("Pivot option: ").strip()
        if choice == "0":
            return
        rendered = False
        try:
            if choice.isdigit() and 1 <= int(choice) <= len(operations):
                result = operations[int(choice) - 1][1](
                    context, selected.entity_type, selected.value
                )
                self.render_pivot_result(operations[int(choice) - 1][0], result)
                rendered = True
            elif choice == "6":
                self.render_related_entities(
                    self.pivot_service.related_entities(
                        context, selected.entity_type, selected.value
                    )
                )
                rendered = True
            elif choice == "7":
                self.render_timeline(
                    self.pivot_service.timeline_for_entity(
                        context, selected.entity_type, selected.value
                    )
                )
                rendered = True
            else:
                self.output("Invalid pivot option.")
        except InvestigationQueryError:
            self.output("The requested entity pivot could not be completed safely.")
            rendered = True
        if rendered:
            self.pause()

    def render_pivot_result(self, label: str, result: PivotResult) -> None:
        self.output(label)
        if not result.matches:
            self.output("  No explicit relationships found.")
        for match in result.matches:
            self.output(
                f"{match.source_id} | {match.source_type} | "
                f"{match.first_seen or 'Untimed'} | "
                f"Cases: {', '.join(match.case_ids) or 'None'}"
            )
            self.output(f"  Relationship: {match.relationship_type}")
            self.output(f"  Why: {match.relationship_reason}")
            if match.evidence_classification:
                self.output(
                    f"  Analyst evidence: {match.evidence_classification.title()}"
                )
            for item in match.hypothesis_overlays:
                self.output(
                    f"  Hypothesis: {item.hypothesis_id} | "
                    f"{item.relationship} | {item.state}"
                )
            for item in match.decision_overlays:
                self.output(f"  Decision: {item.decision_id} | {item.decision_type}")

    def render_related_entities(self, result: RelatedEntitiesResult) -> None:
        self.output("Observed relationships")
        if not result.relationships:
            self.output("  None")
        for item in result.relationships:
            self.output(
                f"{item.entity.entity_type} | {item.entity.display_value} | "
                f"Normalized: {item.entity.normalized_value}"
            )
            self.output(
                f"  Count: {item.count} | First: {item.first_seen or 'Untimed'} | "
                f"Last: {item.last_seen or 'Untimed'}"
            )
            self.output(f"  Why: {item.relationship_reason}")
            self.output(f"  Sources: {', '.join(item.source_ids)}")

    def inspect_evidence(
        self, current: WorkspaceResult, context: InvestigationQueryContext
    ) -> bool:
        selected = tuple(
            item
            for item in current.investigation.evidence_references
            if item.origin == "analyst_selection"
        )
        for index, item in enumerate(selected, start=1):
            self.output(
                f"[{index}] {item.reference_id} | "
                f"{item.classification or 'unclassified'}"
            )
        reference = self._choose(selected, "Evidence number (blank to return): ")
        if reference is None:
            if not selected:
                self.output("No analyst-selected evidence.")
                return True
            return False
        if hasattr(self.evidence_controller, "show_evidence_details"):
            self.evidence_controller.show_evidence_details(
                current, reference.reference_id
            )
            return True
        try:
            candidate = context.evidence_catalog.get_candidate(
                context.analysis, reference.reference_id
            )
        except EvidenceCatalogError:
            self.output("The selected source evidence is not currently available.")
            return True
        self.evidence_controller.show_candidate_details(context.analysis, candidate)
        return True

    def inspect_hypothesis(self, current: WorkspaceResult) -> bool:
        hypotheses = tuple(
            sorted(current.investigation.hypotheses, key=lambda item: item.hypothesis_id)
        )
        for index, item in enumerate(hypotheses, start=1):
            self.output(f"[{index}] {item.hypothesis_id} | {item.state}")
        selected = self._choose(
            hypotheses,
            "Hypothesis number (blank to return): ",
        )
        if selected is None:
            if not current.investigation.hypotheses:
                self.output("No analyst-authored hypotheses.")
                return True
            return False
        self.reasoning_controller.show_hypothesis_details(current, selected.hypothesis_id)
        return True

    def show_decision(self, current: WorkspaceResult, decision_id: str) -> None:
        self.reasoning_controller.show_decision_details(current, decision_id)

    def entry_navigation(
        self,
        current: WorkspaceResult,
        context: InvestigationQueryContext,
        entry: InvestigationTimelineEntry,
    ) -> None:
        actions = []
        if entry.evidence_id:
            actions.append(("Evidence details", "evidence", entry.evidence_id))
        actions.extend(
            ("Hypothesis details", "hypothesis", item)
            for item in entry.related_hypothesis_ids
        )
        actions.extend(
            ("Decision details", "decision", item)
            for item in entry.related_decision_ids
        )
        source = context.sources.get(entry.evidence_id or "")
        if source is not None:
            actions.extend(
                (
                    f"Pivot from {item.entity_type}: {item.display_value}",
                    "entity",
                    item,
                )
                for item in source.entities
            )
        if not actions:
            self.pause()
            return
        for index, (label, _kind, _value) in enumerate(actions, start=1):
            self.output(f"[{index}] {label}")
        choice = self.input("Detail navigation (blank to return): ").strip()
        if not choice:
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(actions):
            self.output("Invalid selection.")
            self.pause()
            return
        _label, kind, selected = actions[int(choice) - 1]
        if kind == "evidence":
            self.evidence_controller.show_evidence_details(current, selected)
            self.pause()
        elif kind == "hypothesis":
            self.reasoning_controller.show_hypothesis_details(current, selected)
            self.pause()
        elif kind == "decision":
            self.reasoning_controller.show_decision_details(current, selected)
            self.pause()
        else:
            self.pivot_screen(context, selected)

    def render_limitations(self, context: InvestigationQueryContext) -> None:
        self.output("Query Limitations")
        self.output("Relationships are explicit observations, not causal conclusions.")
        self.output("Results are bounded and require the matching completed analysis.")
        self.output("Filters use AND semantics and are not persisted.")
        self.output(f"Source analysis ID: {context.source_analysis_id}")

    def _open_context(
        self, current: WorkspaceResult
    ) -> InvestigationQueryContext | None:
        analysis = self.analysis_provider()
        if analysis is None:
            self.output(
                "Source timeline and pivots require the matching completed analysis. "
                "The durable investigation remains available."
            )
            return None
        try:
            return InvestigationQueryContext(analysis, current.investigation)
        except (InvestigationQueryError, EvidenceCatalogError, ValueError):
            self.output(
                "The active analysis does not match this investigation or its "
                "source references cannot be queried safely."
            )
            return None

    def _refresh(
        self, current: WorkspaceResult
    ) -> tuple[WorkspaceResult, InvestigationQueryContext] | None:
        try:
            latest = self.workspace_service.get_investigation(
                current.investigation.investigation_id
            )
        except InvestigationRepositoryError:
            self.output("The latest investigation revision could not be loaded.")
            return None
        context = self._open_context(latest)
        if context is None:
            return None
        self.output(f"Workbench refreshed to revision {latest.revision}.")
        return latest, context

    def _latest_revision(self, current: WorkspaceResult) -> int | None:
        try:
            return self.workspace_service.get_investigation(
                current.investigation.investigation_id
            ).revision
        except InvestigationRepositoryError:
            return None

    def _analysis_matches(self, context: InvestigationQueryContext) -> bool:
        analysis = self.analysis_provider()
        if analysis is None:
            return False
        try:
            return (
                context.evidence_catalog.source_analysis_id(analysis)
                == context.source_analysis_id
            )
        except (EvidenceCatalogError, ValueError):
            return False

    @staticmethod
    def _timeline_row(
        index: int, entry: InvestigationTimelineEntry, *, untimed: bool = False
    ) -> str:
        indicators = []
        if entry.evidence_classification:
            indicators.append(f"Analyst evidence: {entry.evidence_classification.title()}")
        if entry.hypothesis_overlays:
            indicators.append("Hypothesis overlay")
        if entry.decision_overlays:
            indicators.append("Decision overlay")
        if entry.sensitive_fields:
            indicators.append("SENSITIVE")
        details = [
            entry.host,
            entry.user,
            entry.rule_id,
            ",".join(entry.case_ids) if entry.case_ids else None,
        ]
        suffix = " | ".join(item for item in details + indicators if item)
        timestamp = "Untimed" if untimed else entry.timestamp
        short_id = entry.entry_id if len(entry.entry_id) <= 28 else entry.entry_id[:25] + "..."
        return (
            f"[{index}] {timestamp} | {entry.context_kind.upper()} | "
            f"{entry.entry_type} | {entry.title} | {short_id}"
            + (f" | {suffix}" if suffix else "")
        )

    def _choose(self, items: Iterable[object], prompt: str):
        values = tuple(items)
        if not values:
            return None
        choice = self.input(prompt).strip()
        if not choice:
            return None
        if not choice.isdigit() or not 1 <= int(choice) <= len(values):
            self.output("Invalid selection.")
            return None
        return values[int(choice) - 1]
