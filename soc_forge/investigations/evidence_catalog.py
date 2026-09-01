from __future__ import annotations
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Dict, Iterable, Mapping, Sequence, Tuple

from soc_forge.pipeline import AnalysisResult
from soc_forge.investigations.evidence_models import (
    MAX_DETAIL_VALUE_LENGTH,
    SUPPORTED_EVIDENCE_TYPES,
    EvidenceCandidate,
    EvidenceDetailField,
    EvidenceDetails,
    EvidenceFieldProvenance,
)
from soc_forge.investigations.provenance import (
    canonical_json,
    content_digest,
    derive_analysis_provenance,
    derive_legacy_analysis_provenance,
)


EVENT_NATIVE_ID_FIELDS = ("event_record_id", "record_id", "event_uid", "id")
ALERT_NATIVE_ID_FIELDS = ("alert_id", "id")
EVENT_REFERENCE_FIELDS = (
    "source_event_id",
    "source_event_record_id",
    "event_reference_id",
)


class EvidenceCatalogError(Exception):
    pass


class EvidenceIdentityCollisionError(EvidenceCatalogError):
    pass


class AmbiguousLegacyEvidenceIdentityError(EvidenceCatalogError):
    pass


class EvidenceCandidateNotFoundError(EvidenceCatalogError):
    pass


class UnsupportedEvidenceTypeError(EvidenceCatalogError):
    pass


class InvalidEvidenceScopeError(EvidenceCatalogError):
    pass


@dataclass(frozen=True)
class _CatalogEntry:
    candidate: EvidenceCandidate
    payload: Mapping


class AnalysisEvidenceCatalog:
    def analysis_provenance(self, analysis_result: AnalysisResult):
        """Return the canonical provenance manifest for a completed analysis."""
        return self._analysis_provenance(analysis_result)

    def source_analysis_id(self, analysis_result: AnalysisResult) -> str:
        """Return the stable provenance identity owned by the catalog."""
        return self.analysis_provenance(analysis_result).source_analysis_id

    def list_candidates(
        self,
        analysis_result: AnalysisResult,
        *,
        case_ids: Iterable[str] | None = None,
        evidence_types: Iterable[str] | None = None,
    ) -> Tuple[EvidenceCandidate, ...]:
        entries = self._catalog_entries(analysis_result)
        requested_types = self._evidence_types(evidence_types)
        requested_cases = self._case_ids(case_ids)

        candidates = []
        for entry in entries:
            candidate = entry.candidate
            if candidate.evidence_type not in requested_types:
                continue
            if requested_cases is not None and not set(candidate.case_ids).intersection(
                requested_cases
            ):
                continue
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                item.timestamp is None,
                item.timestamp or "",
                item.evidence_type,
                item.evidence_id,
            )
        )
        return tuple(candidates)

    def get_candidate(
        self,
        analysis_result: AnalysisResult,
        evidence_id: str,
    ) -> EvidenceCandidate:
        for entry in self._catalog_entries(analysis_result):
            if entry.candidate.evidence_id == evidence_id:
                return entry.candidate
        return self._legacy_candidate(analysis_result, evidence_id)

    def resolve_details(
        self,
        analysis_result: AnalysisResult,
        evidence_id: str,
    ) -> EvidenceDetails:
        resolved_id = self.get_candidate(analysis_result, evidence_id).evidence_id
        for entry in self._catalog_entries(analysis_result):
            if entry.candidate.evidence_id != resolved_id:
                continue
            details = []
            for provenance in entry.candidate.field_provenance:
                value = self._field_value(entry.payload, provenance.source_field)
                if value is None:
                    continue
                rendered = (
                    self._render_mitre_value(value)
                    if provenance.field_name == "attack_technique"
                    else None
                ) or self._render_value(value)
                truncated = len(rendered) > MAX_DETAIL_VALUE_LENGTH
                details.append(
                    EvidenceDetailField(
                        field_name=provenance.field_name,
                        value=rendered[:MAX_DETAIL_VALUE_LENGTH],
                        provenance=provenance,
                        sensitive=provenance.sensitive,
                        truncated=truncated,
                    )
                )
            return EvidenceDetails(evidence_id=resolved_id, fields=tuple(details))
        raise EvidenceCandidateNotFoundError(
            f"Evidence candidate {evidence_id!r} was not found"
        )

    def _catalog_entries(self, analysis_result: AnalysisResult) -> Tuple[_CatalogEntry, ...]:
        self._validate_analysis_result(analysis_result)
        analysis_id = self._analysis_provenance(analysis_result).source_analysis_id
        return self._entries_for_analysis(analysis_result, analysis_id)

    def _analysis_provenance(self, analysis_result: AnalysisResult):
        self._validate_analysis_result(analysis_result)
        artifact_keys = tuple(
            sorted(
                {
                    str(key).strip()
                    for key, path in analysis_result.artifacts.items()
                    if str(key).strip() and path is not None
                }
            )
        )
        input_name = str(analysis_result.input_name).replace("\\", "/").rsplit("/", 1)[-1]
        provenance = derive_analysis_provenance(
            normalized_input_name=input_name,
            events=analysis_result.events,
            alerts=analysis_result.alerts,
            cases=analysis_result.cases,
            reconstructions=analysis_result.reconstructions,
            artifact_keys=artifact_keys,
        )
        return provenance

    def _legacy_candidate(
        self,
        analysis_result: AnalysisResult,
        evidence_id: str,
    ) -> EvidenceCandidate:
        artifact_keys = tuple(
            sorted(
                str(key).strip()
                for key, path in analysis_result.artifacts.items()
                if str(key).strip() and path is not None
            )
        )
        input_name = (
            str(analysis_result.input_name).replace("\\", "/").rsplit("/", 1)[-1]
        )
        legacy = derive_legacy_analysis_provenance(
            normalized_input_name=input_name,
            events=analysis_result.events,
            alerts=analysis_result.alerts,
            cases=analysis_result.cases,
            reconstructions=analysis_result.reconstructions,
            artifact_keys=artifact_keys,
        )
        matches = [
            entry.candidate
            for entry in self._catalog_entries(analysis_result)
            if self._legacy_evidence_id(
                legacy.source_analysis_id,
                entry.candidate.evidence_type,
                entry.candidate.source_id,
            )
            == evidence_id
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise AmbiguousLegacyEvidenceIdentityError(
                f"Legacy evidence identity {evidence_id!r} is ambiguous"
            )
        raise EvidenceCandidateNotFoundError(
            f"Evidence candidate {evidence_id!r} was not found"
        )

    def _entries_for_analysis(
        self,
        analysis_result: AnalysisResult,
        analysis_id: str,
    ) -> Tuple[_CatalogEntry, ...]:
        event_entries, event_by_source = self._event_entries(
            analysis_result.events, analysis_id
        )
        alert_entries, alert_by_signature = self._alert_entries(
            analysis_result.alerts, analysis_id
        )
        case_entries, alert_cases, event_cases, unresolved = self._case_entries(
            analysis_result.cases,
            analysis_id,
            alert_by_signature,
            event_by_source,
        )
        reconstruction_entries = self._reconstruction_entries(
            analysis_result.reconstructions, analysis_id
        )

        entries_by_id: Dict[str, _CatalogEntry] = {}
        for entry in (
            tuple(event_entries)
            + tuple(alert_entries)
            + tuple(case_entries)
            + tuple(reconstruction_entries)
            + tuple(unresolved)
        ):
            candidate = entry.candidate
            related_cases = set(candidate.case_ids)
            if candidate.evidence_type == "alert":
                related_cases.update(alert_cases.get(candidate.source_id, ()))
            elif candidate.evidence_type == "event":
                related_cases.update(event_cases.get(candidate.source_id, ()))
            if related_cases != set(candidate.case_ids):
                candidate = replace(
                    candidate,
                    case_ids=tuple(sorted(related_cases)),
                    relationship=(
                        "traceable_source"
                        if candidate.evidence_type == "event"
                        else "case_member"
                    ),
                )
                entry = _CatalogEntry(candidate=candidate, payload=entry.payload)
            previous = entries_by_id.get(candidate.evidence_id)
            if previous is None:
                entries_by_id[candidate.evidence_id] = entry
            else:
                if canonical_json(previous.payload) != canonical_json(entry.payload):
                    raise EvidenceIdentityCollisionError(
                        "Materially different evidence candidates derived the same "
                        f"identity {candidate.evidence_id!r}"
                    )
                entries_by_id[candidate.evidence_id] = _CatalogEntry(
                    candidate=replace(
                        previous.candidate,
                        case_ids=tuple(
                            sorted(
                                set(previous.candidate.case_ids).union(
                                    candidate.case_ids
                                )
                            )
                        ),
                    ),
                    payload=previous.payload,
                )
        return tuple(entries_by_id[key] for key in sorted(entries_by_id))

    def _event_entries(
        self,
        events: Sequence[Mapping],
        analysis_id: str,
    ) -> tuple[list[_CatalogEntry], Dict[str, _CatalogEntry]]:
        entries = []
        by_source = {}
        for event in events:
            if not isinstance(event, Mapping):
                continue
            source_id = self._event_source_id(event)
            candidate = self._candidate(
                analysis_id=analysis_id,
                evidence_type="event",
                source_id=source_id,
                payload=event,
                title=self._event_title(event),
                summary=self._event_summary(event),
                timestamp=self._text(event.get("timestamp")),
                relationship="direct",
                source_kind="normalized_event",
            )
            entry = _CatalogEntry(candidate=candidate, payload=event)
            entries.append(entry)
            by_source[source_id] = entry
            for field_name in EVENT_NATIVE_ID_FIELDS:
                native = self._text(event.get(field_name))
                if native:
                    by_source[native] = entry
        return entries, by_source

    def _alert_entries(
        self,
        alerts: Sequence[Mapping],
        analysis_id: str,
    ) -> tuple[list[_CatalogEntry], Dict[str, list[_CatalogEntry]]]:
        entries = []
        by_signature: Dict[str, list[_CatalogEntry]] = {}
        for alert in alerts:
            if not isinstance(alert, Mapping):
                continue
            source_id = self._alert_source_id(alert)
            candidate = self._candidate(
                analysis_id=analysis_id,
                evidence_type="alert",
                source_id=source_id,
                payload=alert,
                title=self._text(alert.get("title")) or "Detection alert",
                summary=self._alert_summary(alert),
                timestamp=self._text(alert.get("timestamp")),
                relationship="direct",
                source_kind="rule_interpretation",
                rule_id=self._text(alert.get("rule_id")),
            )
            if not self._explicit_event_references(alert):
                candidate = replace(
                    candidate,
                    limitation_reason="Source event relationship is not explicitly available.",
                )
            entry = _CatalogEntry(candidate=candidate, payload=alert)
            entries.append(entry)
            by_signature.setdefault(self._alert_signature(alert), []).append(entry)
        return entries, by_signature

    def _case_entries(
        self,
        cases: Sequence[Mapping],
        analysis_id: str,
        alert_by_signature: Mapping[str, list[_CatalogEntry]],
        event_by_source: Mapping[str, _CatalogEntry],
    ) -> tuple[
        list[_CatalogEntry],
        Dict[str, set[str]],
        Dict[str, set[str]],
        list[_CatalogEntry],
    ]:
        entries = []
        alert_case_ids: Dict[str, set[str]] = {}
        event_case_ids: Dict[str, set[str]] = {}
        unresolved = []
        for case in cases:
            if not isinstance(case, Mapping):
                continue
            case_id = self._case_id(case)
            if not case_id:
                continue
            candidate = self._candidate(
                analysis_id=analysis_id,
                evidence_type="case",
                source_id=case_id,
                payload=case,
                title=self._case_title(case),
                summary=self._case_summary(case),
                timestamp=self._case_timestamp(case),
                case_ids=(case_id,),
                relationship="direct",
                source_kind="case_context",
            )
            entries.append(_CatalogEntry(candidate=candidate, payload=case))
            for item in case.get("items", ()):
                if not isinstance(item, Mapping):
                    continue
                matches = alert_by_signature.get(self._alert_signature(item), ())
                if not matches:
                    unresolved.append(
                        _CatalogEntry(
                            candidate=replace(
                                self._candidate(
                                    analysis_id=analysis_id,
                                    evidence_type="alert",
                                    source_id=self._alert_source_id(item),
                                    payload=item,
                                    title=(
                                        self._text(item.get("title"))
                                        or "Unresolved case alert"
                                    ),
                                    summary=self._alert_summary(item),
                                    timestamp=self._text(item.get("timestamp")),
                                    case_ids=(case_id,),
                                    relationship="case_member",
                                    source_kind="case_context",
                                    rule_id=self._text(item.get("rule_id")),
                                ),
                                selectable=False,
                                limitation_reason=(
                                    "Case alert could not be resolved to "
                                    "completed-analysis alerts."
                                ),
                            ),
                            payload=item,
                        )
                    )
                    continue
                for match in matches:
                    alert_case_ids.setdefault(
                        match.candidate.source_id, set()
                    ).add(case_id)
                    for source_event_id in self._explicit_event_references(
                        match.payload
                    ):
                        event_entry = event_by_source.get(source_event_id)
                        if event_entry is not None:
                            event_case_ids.setdefault(
                                event_entry.candidate.source_id,
                                set(),
                            ).add(case_id)
        return entries, alert_case_ids, event_case_ids, unresolved

    def _reconstruction_entries(
        self,
        reconstructions: Sequence[Mapping],
        analysis_id: str,
    ) -> list[_CatalogEntry]:
        entries = []
        for reconstruction in reconstructions:
            if not isinstance(reconstruction, Mapping):
                continue
            case_id = self._text(reconstruction.get("case_id"))
            if not case_id:
                continue
            for step in reconstruction.get("attack_path", ()):
                if not isinstance(step, Mapping):
                    continue
                source_id = "reconstruction-" + content_digest(
                    {"case_id": case_id, "step": step},
                    "reconstruction step",
                )[:24]
                candidate = self._candidate(
                    analysis_id=analysis_id,
                    evidence_type="reconstruction_step",
                    source_id=source_id,
                    payload=step,
                    title=self._text(step.get("title")) or "Reconstruction step",
                    summary=(
                        self._text(step.get("stage"))
                        or "Reconstructed attack step"
                    ),
                    timestamp=self._text(step.get("timestamp")),
                    case_ids=(case_id,),
                    relationship="reconstruction_member",
                    source_kind="reconstruction_context",
                    tactic=self._text(step.get("tactic")),
                    technique=self._text(step.get("technique")),
                )
                entries.append(_CatalogEntry(candidate=candidate, payload=step))
        return entries

    def _candidate(
        self,
        *,
        analysis_id: str,
        evidence_type: str,
        source_id: str,
        payload: Mapping,
        title: str,
        summary: str,
        timestamp: str | None,
        relationship: str,
        source_kind: str,
        case_ids: tuple[str, ...] = (),
        rule_id: str | None = None,
        tactic: str | None = None,
        technique: str | None = None,
    ) -> EvidenceCandidate:
        evidence_id = self._evidence_id(
            analysis_id,
            evidence_type,
            source_id,
            content_digest(payload, f"{evidence_type} identity content"),
        )
        field_provenance = self._field_provenance(
            payload,
            evidence_type=evidence_type,
            source_id=source_id,
            source_kind=source_kind,
        )
        return EvidenceCandidate(
            evidence_id=evidence_id,
            source_analysis_id=analysis_id,
            evidence_type=evidence_type,
            source_id=source_id,
            title=title.strip(),
            summary=summary.strip()[:320],
            timestamp=timestamp,
            entity_references=self._entity_references(payload),
            rule_id=rule_id,
            case_ids=tuple(sorted(set(case_ids))),
            tactic=tactic,
            technique=technique,
            relationship=relationship,
            field_provenance=field_provenance,
            sensitive_fields=tuple(
                sorted(
                    {
                        item.field_name
                        for item in field_provenance
                        if item.sensitive
                    }
                )
            ),
        )

    def _field_provenance(
        self,
        payload: Mapping,
        *,
        evidence_type: str,
        source_id: str,
        source_kind: str,
    ) -> Tuple[EvidenceFieldProvenance, ...]:
        fields = []
        raw_fields = (
            ("raw_timestamp", "raw.timestamp"),
            ("raw_host", "raw.host"),
            ("raw_user", "raw.username"),
            ("raw_command_line", "raw.command_line"),
        )
        for field_name, source_field in raw_fields:
            if self._field_value(payload, source_field) is None:
                continue
            fields.append(
                EvidenceFieldProvenance(
                    field_name=field_name,
                    source_type=evidence_type,
                    source_id=source_id,
                    source_field=source_field,
                    source_kind="raw_source",
                    sensitive=field_name != "raw_timestamp",
                )
            )

        field_paths = (
            ("timestamp", "timestamp"),
            ("host", "details.host"),
            ("host", "host"),
            ("user", "details.username"),
            ("user", "username"),
            ("source_ip", "details.ip"),
            ("source_ip", "src_ip"),
            ("process", "details.process_name"),
            ("process", "process_name"),
            ("command_line", "details.command_line"),
            ("command_line", "command_line"),
            ("service", "details.service_name"),
            ("service", "service_name"),
            ("rule_id", "rule_id"),
            ("severity", "severity"),
            ("attack_technique", "mitre"),
            ("case_membership", "case_id"),
            ("tactic", "tactic"),
            ("technique", "technique"),
        )
        seen = set()
        for field_name, source_field in field_paths:
            if field_name in seen or self._field_value(payload, source_field) is None:
                continue
            seen.add(field_name)
            sensitive = field_name in {
                "host",
                "user",
                "source_ip",
                "command_line",
                "service",
            }
            kind = source_kind
            if evidence_type == "alert" and field_name in {
                "rule_id",
                "severity",
                "attack_technique",
            }:
                kind = "rule_interpretation"
            fields.append(
                EvidenceFieldProvenance(
                    field_name=field_name,
                    source_type=evidence_type,
                    source_id=source_id,
                    source_field=source_field,
                    source_kind=kind,
                    normalized=(kind == "normalized_event"),
                    sensitive=sensitive,
                )
            )
        return tuple(fields)

    @staticmethod
    def _field_value(payload: Mapping, source_field: str):
        value = payload
        for part in source_field.split("."):
            if not isinstance(value, Mapping) or part not in value:
                return None
            value = value[part]
        return value

    @staticmethod
    def _render_value(value: object) -> str:
        if isinstance(value, str):
            return value
        return canonical_json(value)

    @staticmethod
    def _render_mitre_value(value: object) -> str | None:
        if not isinstance(value, (list, tuple)):
            return None
        labels = []
        for mapping in value:
            if not isinstance(mapping, Mapping):
                continue
            technique_id = mapping.get("technique_id") or mapping.get("id")
            technique_name = mapping.get("technique")
            tactic = mapping.get("tactic")
            label = " - ".join(
                str(part) for part in (technique_id, technique_name) if part
            )
            if tactic:
                label = f"{label} ({tactic})" if label else str(tactic)
            if label and label not in labels:
                labels.append(label)
        return "; ".join(labels) if labels else None

    @classmethod
    def _event_source_id(cls, event: Mapping) -> str:
        for field_name in EVENT_NATIVE_ID_FIELDS:
            value = cls._text(event.get(field_name))
            if value:
                return value
        return "event-" + content_digest(event, "event")[:24]

    @classmethod
    def _alert_source_id(cls, alert: Mapping) -> str:
        for field_name in ALERT_NATIVE_ID_FIELDS:
            value = cls._text(alert.get(field_name))
            if value:
                return value
        return "alert-" + content_digest(alert, "alert")[:24]
    @staticmethod

    def _evidence_id(
        analysis_id: str,
        evidence_type: str,
        source_id: str,
        identity_qualifier: str,
    ) -> str:
        manifest = {
            "source_analysis_id": analysis_id,
            "evidence_type": evidence_type,
            "source_id": source_id,
            "identity_qualifier": identity_qualifier,
        }
        return "evidence-" + sha256(
            canonical_json(manifest).encode("utf-8")
        ).hexdigest()[:24]

    @staticmethod
    def _legacy_evidence_id(
        analysis_id: str,
        evidence_type: str,
        source_id: str,
    ) -> str:
        manifest = {
            "source_analysis_id": analysis_id,
            "evidence_type": evidence_type,
            "source_id": source_id,
        }
        return "evidence-" + sha256(
            canonical_json(manifest).encode("utf-8")
        ).hexdigest()[:24]
    @classmethod
    def _alert_signature(cls, alert: Mapping) -> str:

        return content_digest(
            {
                "rule_id": alert.get("rule_id"),
                "timestamp": alert.get("timestamp"),
                "title": alert.get("title"),
                "correlation_id": alert.get("correlation_id"),
                "details": alert.get("details"),
            },
            "alert membership",
        )

    @classmethod
    def _explicit_event_references(cls, alert: Mapping) -> Tuple[str, ...]:
        references = []
        details = alert.get("details")
        sources = (alert, details) if isinstance(details, Mapping) else (alert,)
        for source in sources:
            for field_name in EVENT_REFERENCE_FIELDS:
                value = cls._text(source.get(field_name))
                if value:
                    references.append(value)
        return tuple(sorted(set(references)))

    @classmethod
    def _case_id(cls, case: Mapping) -> str | None:
        header = case.get("header")
        header_id = header.get("case_id") if isinstance(header, Mapping) else None
        return cls._text(case.get("case_id") or case.get("id") or header_id)

    @classmethod
    def _case_title(cls, case: Mapping) -> str:
        header = case.get("header")
        title = header.get("title") if isinstance(header, Mapping) else None
        return cls._text(case.get("title") or title) or "Investigation case"

    @classmethod
    def _case_timestamp(cls, case: Mapping) -> str | None:
        header = case.get("header")
        timestamp = header.get("timestamp") if isinstance(header, Mapping) else None
        return cls._text(case.get("timestamp") or timestamp)

    @classmethod
    def _case_summary(cls, case: Mapping) -> str:
        header = case.get("header")
        details = header.get("details") if isinstance(header, Mapping) else None
        quality = details.get("case_quality") if isinstance(details, Mapping) else None
        summary = quality.get("executive_summary") if isinstance(quality, Mapping) else None
        return cls._text(summary) or cls._case_title(case)

    @classmethod
    def _event_title(cls, event: Mapping) -> str:
        process = cls._text(event.get("process_name") or event.get("image"))
        event_id = cls._text(event.get("event_id"))
        if process:
            return f"Source event: {process}"
        if event_id:
            return f"Source event {event_id}"
        return "Source event"

    @classmethod
    def _event_summary(cls, event: Mapping) -> str:
        return (
            cls._text(event.get("action"))
            or "Normalized source telemetry"
        )

    @classmethod
    def _alert_summary(cls, alert: Mapping) -> str:
        return cls._text(alert.get("title")) or "Detection result"

    @classmethod
    def _entity_references(cls, payload: Mapping) -> Tuple[str, ...]:
        details = payload.get("details")
        sources = (payload, details) if isinstance(details, Mapping) else (payload,)
        entities = set()
        for source in sources:
            for prefix, fields in (
                ("host", ("host", "hostname")),
                ("user", ("username", "user")),
                ("ip", ("src_ip", "source_ip", "ip")),
            ):
                for field_name in fields:
                    value = cls._text(source.get(field_name))
                    if value:
                        entities.add(f"{prefix}:{value}")
        return tuple(sorted(entities))

    @staticmethod
    def _text(value: object) -> str | None:
        if value is None:
            return None
        rendered = str(value).strip()
        return rendered or None

    @staticmethod
    def _case_ids(case_ids: Iterable[str] | None) -> set[str] | None:
        if case_ids is None:
            return None
        if isinstance(case_ids, (str, bytes)):
            raise InvalidEvidenceScopeError("case_ids must be an iterable of IDs")
        normalized = {str(value).strip() for value in case_ids if str(value).strip()}
        if not normalized:
            raise InvalidEvidenceScopeError("case_ids must not be empty")
        return normalized

    @staticmethod
    def _evidence_types(evidence_types: Iterable[str] | None) -> set[str]:
        if evidence_types is None:
            return set(SUPPORTED_EVIDENCE_TYPES)
        if isinstance(evidence_types, (str, bytes)):
            values = {str(evidence_types)}
        else:
            values = {str(value) for value in evidence_types}
        unsupported = sorted(values.difference(SUPPORTED_EVIDENCE_TYPES))
        if unsupported:
            raise UnsupportedEvidenceTypeError(
                "Unsupported evidence type(s): " + ", ".join(unsupported)
            )
        return values

    @staticmethod
    def _validate_analysis_result(analysis_result: AnalysisResult) -> None:
        if not isinstance(analysis_result, AnalysisResult):
            raise EvidenceCatalogError(
                "Evidence catalog requires one completed AnalysisResult"
            )
        for field_name in ("events", "alerts", "cases", "reconstructions"):
            if not isinstance(getattr(analysis_result, field_name), list):
                raise EvidenceCatalogError(
                    f"Completed analysis {field_name} must be a list"
                )
        if not isinstance(analysis_result.artifacts, Mapping):
            raise EvidenceCatalogError(
                "Completed analysis artifacts must be a mapping"
            )
