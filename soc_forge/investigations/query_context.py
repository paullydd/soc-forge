from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import ip_address
from pathlib import PureWindowsPath
from types import MappingProxyType
from typing import Mapping, Tuple

from soc_forge.investigations.evidence_catalog import (
    AnalysisEvidenceCatalog,
    EvidenceCandidateNotFoundError,
)
from soc_forge.investigations.evidence_models import EvidenceCandidate
from soc_forge.investigations.models import EvidenceReference, Investigation
from soc_forge.investigations.query_models import (
    AnalysisProvenanceMismatchError,
    InvalidEntityValueError,
    InvestigationEntity,
    QuerySourceReferenceNotFoundError,
    UnsupportedEntityTypeError,
)
from soc_forge.pipeline import AnalysisResult


@dataclass(frozen=True)
class QuerySource:
    candidate: EvidenceCandidate
    entities: Tuple[InvestigationEntity, ...]
    field_values: Mapping[str, str]


def normalize_entity(entity_type: str, value: object) -> InvestigationEntity:
    kind = str(entity_type or "").strip().lower().replace(" ", "_")
    aliases = {"ip_address": "ip", "technique": "attack_technique"}
    kind = aliases.get(kind, kind)
    text = str(value or "").strip()
    if not text:
        raise InvalidEntityValueError("Entity value must be nonblank")
    if kind in {"host", "user", "service", "rule", "case", "evidence", "hypothesis"}:
        normalized = text.casefold() if kind in {"host", "user", "service"} else text
        return InvestigationEntity(kind, text, normalized, text)
    if kind == "ip":
        try:
            normalized = ip_address(text).compressed
        except ValueError as exc:
            raise InvalidEntityValueError("IP entity must be valid IPv4 or IPv6 text") from exc
        return InvestigationEntity(kind, text, normalized, text)
    if kind == "process":
        display = text
        normalized_path = text.replace("/", "\\").casefold()
        basename = PureWindowsPath(normalized_path).name
        return InvestigationEntity(kind, text, basename, display, normalized_path)
    if kind == "attack_technique":
        return InvestigationEntity(kind, text, text.upper(), text)
    raise UnsupportedEntityTypeError(f"Unsupported entity type: {entity_type}")


class InvestigationQueryContext:
    """Validated read-only view over one analysis and one investigation."""

    def __init__(
        self,
        analysis: AnalysisResult,
        investigation: Investigation,
        *,
        evidence_catalog: AnalysisEvidenceCatalog | None = None,
    ) -> None:
        catalog = evidence_catalog or AnalysisEvidenceCatalog()
        source_analysis_id = catalog.source_analysis_id(analysis)
        if investigation.analysis_id != source_analysis_id:
            raise AnalysisProvenanceMismatchError(
                "Investigation source analysis does not match the supplied analysis"
            )
        if (
            investigation.provenance is not None
            and investigation.provenance.source_analysis_id != source_analysis_id
        ):
            raise AnalysisProvenanceMismatchError(
                "Investigation provenance does not match the supplied analysis"
            )

        case_ids = tuple(
            sorted(
                {
                    reference.source_id
                    for reference in investigation.evidence_references
                    if reference.origin == "scope" and reference.source_type == "case"
                }
            )
        )
        analysis_case_ids = {
            str(case.get("case_id") or (case.get("header") or {}).get("case_id") or "").strip()
            for case in analysis.cases
            if isinstance(case, Mapping)
        }
        missing_cases = sorted(set(case_ids).difference(analysis_case_ids))
        if missing_cases:
            raise QuerySourceReferenceNotFoundError(
                f"Selected case {missing_cases[0]!r} is not present in the analysis"
            )

        candidates = catalog.list_candidates(analysis)
        alert_payloads = {
            str(alert.get("alert_id") or alert.get("id") or "").strip(): alert
            for alert in analysis.alerts
            if isinstance(alert, Mapping)
        }
        sources = {}
        for candidate in candidates:
            if candidate.evidence_type == "alert":
                payload = alert_payloads.get(candidate.source_id)
                if payload is not None:
                    tactic, technique = self._attack_fields(payload)
                    candidate = replace(
                        candidate,
                        tactic=candidate.tactic or tactic,
                        technique=candidate.technique or technique,
                    )
            details = catalog.resolve_details(analysis, candidate.evidence_id)
            values = {
                field.field_name: field.value
                for field in details.fields
                if field.field_name
                in {"host", "user", "source_ip", "process", "service", "severity"}
            }
            entities = list(self._candidate_entities(candidate, values))
            if candidate.rule_id:
                entities.append(normalize_entity("rule", candidate.rule_id))
            if candidate.technique:
                technique = self._technique_id(candidate.technique)
                if technique:
                    entities.append(normalize_entity("attack_technique", technique))
            for case_id in candidate.case_ids:
                entities.append(normalize_entity("case", case_id))
            entities.append(normalize_entity("evidence", candidate.evidence_id))
            sources[candidate.evidence_id] = QuerySource(
                candidate=candidate,
                entities=tuple(
                    sorted(
                        {entity for entity in entities},
                        key=lambda item: (
                            item.entity_type,
                            item.normalized_value,
                            item.secondary_key or "",
                        ),
                    )
                ),
                field_values=MappingProxyType(values),
            )

        resolved_references = {}
        for reference in investigation.evidence_references:
            if reference.origin != "analyst_selection":
                continue
            try:
                candidate = catalog.get_candidate(analysis, reference.reference_id)
            except EvidenceCandidateNotFoundError as exc:
                raise QuerySourceReferenceNotFoundError(
                    f"Evidence reference {reference.reference_id!r} could not be resolved"
                ) from exc
            resolved_references[candidate.evidence_id] = reference

        self.analysis = analysis
        self.investigation = investigation
        self.evidence_catalog = catalog
        self.source_analysis_id = source_analysis_id
        self.selected_case_ids = case_ids
        self.sources = MappingProxyType(sources)
        self.analyst_evidence_by_candidate = MappingProxyType(resolved_references)
        self.hypotheses = tuple(investigation.hypotheses)
        self.decisions = tuple(investigation.decisions)
        self.evidence_references_by_id = MappingProxyType(
            {item.reference_id: item for item in investigation.evidence_references}
        )
        self._sealed = True

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("InvestigationQueryContext is read-only")
        object.__setattr__(self, name, value)

    @property
    def scoped_sources(self) -> Tuple[QuerySource, ...]:
        selected = set(self.selected_case_ids)
        return tuple(
            source
            for source in self.sources.values()
            if selected.intersection(source.candidate.case_ids)
        )

    @staticmethod
    def _candidate_entities(
        candidate: EvidenceCandidate,
        values: Mapping[str, str],
    ) -> Tuple[InvestigationEntity, ...]:
        entities = []
        field_types = {
            "host": "host",
            "user": "user",
            "source_ip": "ip",
            "process": "process",
            "service": "service",
        }
        for field_name, entity_type in field_types.items():
            value = values.get(field_name)
            if value:
                try:
                    entities.append(normalize_entity(entity_type, value))
                except InvalidEntityValueError:
                    continue
        for value in candidate.entity_references:
            kind, separator, display = value.partition(":")
            if not separator:
                continue
            try:
                entities.append(normalize_entity(kind, display))
            except (InvalidEntityValueError, UnsupportedEntityTypeError):
                continue
        return tuple(entities)

    @staticmethod
    def _technique_id(value: str) -> str | None:
        rendered = str(value).strip()
        if not rendered:
            return None
        if rendered.upper().startswith("T") and rendered[1:5].isdigit():
            return rendered.split()[0].upper()
        return rendered

    @classmethod
    def _attack_fields(cls, payload: Mapping) -> tuple[str | None, str | None]:
        mitre = payload.get("mitre")
        rows = mitre if isinstance(mitre, (list, tuple)) else (mitre,)
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            technique = cls._technique_id(str(row.get("id") or ""))
            tactic = str(row.get("tactic") or "").strip() or None
            if technique or tactic:
                return tactic, technique
        return None, None

    def selected_reference(self, evidence_id: str) -> EvidenceReference | None:
        return self.analyst_evidence_by_candidate.get(evidence_id)
