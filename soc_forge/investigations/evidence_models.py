from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from soc_forge.investigations.models import (
    INVESTIGATION_SCHEMA_VERSION,
    SerializableModel,
    _id_tuple,
    _require_fields,
    _require_text,
    _tuple_copy,
    _validate_schema_version,
)


SUPPORTED_EVIDENCE_TYPES = frozenset(
    {"event", "alert", "case", "reconstruction_step"}
)
PROVENANCE_SOURCE_KINDS = frozenset(
    {
        "raw_source",
        "normalized_event",
        "rule_interpretation",
        "case_context",
        "reconstruction_context",
    }
)
EVIDENCE_RELATIONSHIPS = frozenset(
    {"direct", "case_member", "traceable_source", "reconstruction_member"}
)
MAX_EVIDENCE_SUMMARY_LENGTH = 320
MAX_DETAIL_VALUE_LENGTH = 2048


@dataclass(frozen=True)
class EvidenceFieldProvenance(SerializableModel):
    field_name: str
    source_type: str
    source_id: str
    source_field: str
    source_kind: str
    normalized: bool = False
    sensitive: bool = False
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        for field_name in ("field_name", "source_type", "source_id", "source_field"):
            _require_text(
                getattr(self, field_name),
                f"EvidenceFieldProvenance.{field_name}",
            )
        if self.source_kind not in PROVENANCE_SOURCE_KINDS:
            raise ValueError(
                "EvidenceFieldProvenance.source_kind must be one of: "
                + ", ".join(sorted(PROVENANCE_SOURCE_KINDS))
            )

    @classmethod
    def from_dict(cls, data):
        _require_fields(
            data,
            cls.__name__,
            "field_name",
            "source_type",
            "source_id",
            "source_field",
            "source_kind",
        )
        return cls(**dict(data))


@dataclass(frozen=True)
class EvidenceCandidate(SerializableModel):
    evidence_id: str
    source_analysis_id: str
    evidence_type: str
    source_id: str
    title: str
    summary: str
    timestamp: str | None = None
    entity_references: Tuple[str, ...] = ()
    rule_id: str | None = None
    case_ids: Tuple[str, ...] = ()
    tactic: str | None = None
    technique: str | None = None
    relationship: str = "direct"
    field_provenance: Tuple[EvidenceFieldProvenance, ...] = ()
    sensitive_fields: Tuple[str, ...] = ()
    selectable: bool = True
    limitation_reason: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        for field_name in (
            "evidence_id",
            "source_analysis_id",
            "source_id",
            "title",
            "summary",
        ):
            _require_text(getattr(self, field_name), f"EvidenceCandidate.{field_name}")
        if self.evidence_type not in SUPPORTED_EVIDENCE_TYPES:
            raise ValueError(
                "EvidenceCandidate.evidence_type must be one of: "
                + ", ".join(sorted(SUPPORTED_EVIDENCE_TYPES))
            )
        if self.relationship not in EVIDENCE_RELATIONSHIPS:
            raise ValueError(
                "EvidenceCandidate.relationship must be one of: "
                + ", ".join(sorted(EVIDENCE_RELATIONSHIPS))
            )
        if len(self.summary) > MAX_EVIDENCE_SUMMARY_LENGTH:
            raise ValueError(
                f"EvidenceCandidate.summary exceeds {MAX_EVIDENCE_SUMMARY_LENGTH} characters"
            )
        object.__setattr__(
            self,
            "entity_references",
            _id_tuple(self.entity_references, "EvidenceCandidate.entity_references"),
        )
        object.__setattr__(
            self,
            "case_ids",
            _id_tuple(self.case_ids, "EvidenceCandidate.case_ids"),
        )
        object.__setattr__(
            self,
            "sensitive_fields",
            _id_tuple(self.sensitive_fields, "EvidenceCandidate.sensitive_fields"),
        )
        provenance = _tuple_copy(
            self.field_provenance,
            "EvidenceCandidate.field_provenance",
        )
        if any(not isinstance(item, EvidenceFieldProvenance) for item in provenance):
            raise ValueError(
                "EvidenceCandidate.field_provenance must contain "
                "EvidenceFieldProvenance objects"
            )
        object.__setattr__(self, "field_provenance", provenance)
        if not self.selectable and not (
            isinstance(self.limitation_reason, str) and self.limitation_reason.strip()
        ):
            raise ValueError(
                "EvidenceCandidate.limitation_reason is required when not selectable"
            )

    @classmethod
    def from_dict(cls, data):
        _require_fields(
            data,
            cls.__name__,
            "evidence_id",
            "source_analysis_id",
            "evidence_type",
            "source_id",
            "title",
            "summary",
        )
        values = dict(data)
        for key in ("entity_references", "case_ids", "sensitive_fields"):
            values[key] = tuple(values.get(key, ()))
        values["field_provenance"] = tuple(
            EvidenceFieldProvenance.from_dict(item)
            for item in values.get("field_provenance", ())
        )
        return cls(**values)


@dataclass(frozen=True)
class EvidenceDetailField(SerializableModel):
    field_name: str
    value: str
    provenance: EvidenceFieldProvenance
    sensitive: bool = False
    truncated: bool = False
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.field_name, "EvidenceDetailField.field_name")
        if not isinstance(self.value, str):
            raise ValueError("EvidenceDetailField.value must be a string")
        if len(self.value) > MAX_DETAIL_VALUE_LENGTH:
            raise ValueError(
                f"EvidenceDetailField.value exceeds {MAX_DETAIL_VALUE_LENGTH} characters"
            )
        if not isinstance(self.provenance, EvidenceFieldProvenance):
            raise ValueError(
                "EvidenceDetailField.provenance must be EvidenceFieldProvenance"
            )

    @classmethod
    def from_dict(cls, data):
        _require_fields(data, cls.__name__, "field_name", "value", "provenance")
        values = dict(data)
        values["provenance"] = EvidenceFieldProvenance.from_dict(values["provenance"])
        return cls(**values)


@dataclass(frozen=True)
class EvidenceDetails(SerializableModel):
    evidence_id: str
    fields: Tuple[EvidenceDetailField, ...] = ()
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.evidence_id, "EvidenceDetails.evidence_id")
        fields = _tuple_copy(self.fields, "EvidenceDetails.fields")
        if any(not isinstance(item, EvidenceDetailField) for item in fields):
            raise ValueError(
                "EvidenceDetails.fields must contain EvidenceDetailField objects"
            )
        object.__setattr__(self, "fields", fields)

    @classmethod
    def from_dict(cls, data):
        _require_fields(data, cls.__name__, "evidence_id")
        values = dict(data)
        values["fields"] = tuple(
            EvidenceDetailField.from_dict(item) for item in values.get("fields", ())
        )
        return cls(**values)
