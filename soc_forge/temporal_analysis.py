from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from soc_forge.attack_activity import AttackActivityService
from soc_forge.investigations.provenance import content_digest
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.pipeline import AnalysisResult


@dataclass(frozen=True)
class TemporalEntry:
    entry_id: str
    timestamp: str | None
    source_type: str
    source_id: str
    investigation_id: str | None
    attribution: str
    category: str
    title: str
    summary: str
    attack_tactics: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()
    entity_refs: tuple[str, ...] = ()
    untimed: bool = False


@dataclass(frozen=True)
class TemporalAnalysisResult:
    mode: str
    timed_entry_count: int
    untimed_entry_count: int
    first_timestamp: str | None
    last_timestamp: str | None
    investigations_represented: int
    machine_entry_count: int
    analyst_entry_count: int
    entries: tuple[TemporalEntry, ...]
    untimed_entries: tuple[TemporalEntry, ...]


class TemporalAnalysisService:
    def __init__(self, repository: InvestigationRepository,
                 analysis_provider: Callable[[], object | None] = lambda: None,
                 *, recent_limit: int = 10) -> None:
        self.repository = repository
        self.analysis_provider = analysis_provider
        self.recent_limit = max(0, recent_limit)

    def analyze(self, *, investigation_id=None, source_type=None,
                tactic=None, technique_id=None) -> TemporalAnalysisResult:
        candidate = self.analysis_provider()
        analysis = candidate if isinstance(candidate, AnalysisResult) else None
        rows = list(self._analyst_entries())
        if analysis is not None:
            rows.extend(self._machine_entries(analysis))
        rows = self._dedupe(rows)
        if investigation_id:
            rows = tuple(row for row in rows
                         if row.investigation_id == investigation_id)
        if source_type:
            rows = tuple(row for row in rows if row.source_type == source_type)
        if tactic:
            value = tactic.casefold()
            rows = tuple(row for row in rows
                         if any(item.casefold() == value
                                for item in row.attack_tactics))
        if technique_id:
            value = technique_id.casefold()
            rows = tuple(row for row in rows if any(
                (AttackActivityService._technique(item)[0] or item).casefold()
                == value for item in row.attack_techniques
            ))
        timed = tuple(sorted((row for row in rows if not row.untimed),
                            key=self._order_key))
        untimed = tuple(sorted((row for row in rows if row.untimed),
                              key=self._untimed_key))
        investigations = {row.investigation_id for row in rows
                          if row.investigation_id}
        return TemporalAnalysisResult(
            "full" if analysis is not None else "offline", len(timed),
            len(untimed), timed[0].timestamp if timed else None,
            timed[-1].timestamp if timed else None, len(investigations),
            sum(row.attribution == "machine" for row in rows),
            sum(row.attribution == "analyst" for row in rows),
            timed, untimed,
        )

    def recent(self, result: TemporalAnalysisResult):
        return tuple(reversed(result.entries[-self.recent_limit:]))

    def _analyst_entries(self):
        for summary in self.repository.list_investigations():
            inv = self.repository.load(summary.investigation_id)
            inv_id = inv.investigation_id
            for ref in inv.evidence_references:
                if ref.origin == "analyst_selection":
                    yield self._entry(
                        f"TEMP:EVIDENCE:{inv_id}:{ref.reference_id}",
                        ref.selected_at, "evidence", ref.reference_id, inv_id,
                        "analyst", ref.label or "Evidence selected",
                        f"Evidence selected as {ref.classification}.",
                    )
            for hypothesis in inv.hypotheses:
                yield self._entry(
                    f"TEMP:HYPOTHESIS:{inv_id}:{hypothesis.hypothesis_id}:created",
                    hypothesis.created_at, "hypothesis",
                    hypothesis.hypothesis_id, inv_id, "analyst",
                    f"{hypothesis.hypothesis_id} created", hypothesis.statement,
                )
            for decision in inv.decisions:
                yield self._entry(
                    f"TEMP:DECISION:{inv_id}:{decision.decision_id}",
                    decision.decided_at, "decision", decision.decision_id,
                    inv_id, "analyst", f"{decision.decision_id} recorded",
                    decision.outcome,
                )
            for finding in inv.findings:
                yield self._entry(
                    f"TEMP:FINDING:{inv_id}:{finding.finding_id}:created",
                    finding.created_at, "finding", finding.finding_id, inv_id,
                    "analyst", f"{finding.finding_id} created", finding.title,
                    finding.attack_tactics, finding.attack_techniques,
                )
                if finding.superseded_at:
                    yield self._entry(
                        f"TEMP:FINDING:{inv_id}:{finding.finding_id}:superseded",
                        finding.superseded_at, "finding", finding.finding_id,
                        inv_id, "analyst",
                        f"{finding.finding_id} superseded",
                        finding.supersession_reason or "Finding superseded.",
                        finding.attack_tactics, finding.attack_techniques,
                    )
            for action in inv.response_actions:
                yield self._entry(
                    f"TEMP:ACTION:{inv_id}:{action.action_id}:created",
                    action.created_at, "response_action", action.action_id,
                    inv_id, "analyst",
                    f"{action.action_id} {action.transition_history[0].from_status if action.transition_history else action.status}",
                    action.title,
                )
                for transition in action.transition_history:
                    yield self._entry(
                        f"TEMP:ACTION:{inv_id}:{action.action_id}:{transition.transition_id}",
                        transition.timestamp, "response_action",
                        action.action_id, inv_id, "analyst",
                        f"{action.action_id} {transition.to_status}",
                        transition.rationale,
                    )

    def _machine_entries(self, analysis):
        sources = (
            ("event", analysis.events), ("alert", analysis.alerts),
            ("case", analysis.cases),
        )
        for category, values in sources:
            for value in values:
                if not isinstance(value, Mapping):
                    continue
                source_id = self._source_id(category, value)
                tactics, techniques = self._attack(value)
                yield self._entry(
                    f"TEMP:{category.upper()}:{source_id}",
                    self._text(value.get("timestamp") or value.get("created_at"))
                    or None, category, source_id, None, "machine",
                    self._text(value.get("title"))
                    or self._text(value.get("message"))
                    or category.title(),
                    category.title(), tactics, techniques,
                )
        for reconstruction in analysis.reconstructions:
            if not isinstance(reconstruction, Mapping):
                continue
            for step in reconstruction.get("attack_path", ()):
                if not isinstance(step, Mapping):
                    continue
                source_id = self._source_id("reconstruction", {
                    "case_id": reconstruction.get("case_id"), "step": step,
                })
                tactic = self._text(step.get("tactic"))
                technique = self._text(step.get("technique"))
                yield self._entry(
                    f"TEMP:RECONSTRUCTION:{source_id}",
                    self._text(step.get("timestamp")) or None,
                    "reconstruction", source_id, None, "machine",
                    self._text(step.get("title")) or "Reconstruction step",
                    "Recorded reconstruction step.",
                    (tactic,) if tactic else (), (technique,) if technique else (),
                )

    @classmethod
    def _attack(cls, value):
        tactics, techniques = set(), set()
        rows = value.get("mitre")
        rows = rows if isinstance(rows, (list, tuple)) else ()
        for tactic, technique_id, technique_name in (
            AttackActivityService._mapping_rows(rows)
        ):
            if tactic:
                tactics.add(tactic)
            technique = " - ".join(item for item in
                (technique_id, technique_name) if item)
            if technique:
                techniques.add(technique)
        return tuple(sorted(tactics)), tuple(sorted(techniques))

    @staticmethod
    def _entry(entry_id, timestamp, category, source_id, investigation_id,
               attribution, title, summary, tactics=(), techniques=()):
        timestamp = timestamp.strip() if isinstance(timestamp, str) and timestamp.strip() else None
        return TemporalEntry(
            entry_id, timestamp, category, source_id, investigation_id,
            attribution, category, title, summary, tuple(tactics),
            tuple(techniques), (), timestamp is None,
        )

    @staticmethod
    def _source_id(category, value):
        for key in ("event_id", "alert_id", "case_id"):
            text = TemporalAnalysisService._text(value.get(key))
            if text:
                return text
        return category + "-" + content_digest(value, category)[:24]

    @staticmethod
    def _text(value):
        return str(value).strip() if value is not None else ""

    @staticmethod
    def _dedupe(rows):
        values = {row.entry_id: row for row in rows}
        return tuple(values[key] for key in sorted(values))

    @staticmethod
    def _order_key(row):
        return (row.timestamp or "", row.attribution, row.category,
                row.investigation_id or "", row.source_id, row.entry_id)

    @staticmethod
    def _untimed_key(row):
        return (row.attribution, row.category, row.investigation_id or "",
                row.source_id, row.entry_id)
