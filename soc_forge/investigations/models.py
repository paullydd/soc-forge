from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
import re
from typing import Any, Dict, Mapping, Tuple, Type, TypeVar


INVESTIGATION_SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_MAJOR = 1

EVIDENCE_SOURCE_TYPES = frozenset(
    {"event", "alert", "case", "hunt", "correlation", "reconstruction", "artifact"}
)
HYPOTHESIS_STATES = frozenset({"open", "supported", "rejected", "inconclusive"})
ANNOTATION_TARGET_TYPES = frozenset(
    {"investigation", "evidence", "hypothesis", "decision", "timeline_selection"}
)

T = TypeVar("T", bound="SerializableModel")


def _validate_schema_version(value: str, model_name: str) -> None:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)", value or "")
    if not match:
        raise ValueError(f"{model_name}.schema_version must use '<major>.<minor>' format")
    if int(match.group(1)) != SUPPORTED_SCHEMA_MAJOR:
        raise ValueError(
            f"{model_name}.schema_version has unsupported major version {match.group(1)}"
        )


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_fields(data: Mapping[str, Any], model_name: str, *field_names: str) -> None:
    missing = [field_name for field_name in field_names if field_name not in data]
    if missing:
        raise ValueError(f"{model_name} is missing required field(s): {', '.join(missing)}")


def _tuple_copy(value: Any, field_name: str) -> tuple:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError(f"{field_name} must be a list or tuple")
    return tuple(value)


def _id_tuple(value: Any, field_name: str) -> Tuple[str, ...]:
    normalized = _tuple_copy(value, field_name)
    for item in normalized:
        _require_text(item, f"{field_name} item")
    return normalized


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _serialize(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_serialize(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _serialize(item) for key, item in value.items()}
    return value


class SerializableModel:
    def to_dict(self) -> Dict[str, Any]:
        return _serialize(self)

    @classmethod
    def from_dict(cls: Type[T], data: Mapping[str, Any]) -> T:
        return cls(**dict(data))


@dataclass(frozen=True)
class WorkspaceMetadata(SerializableModel):
    title: str
    created_at: str
    updated_at: str
    owner: str | None = None
    status: str = "open"
    labels: Tuple[str, ...] = ()
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.title, "WorkspaceMetadata.title")
        _require_text(self.status, "WorkspaceMetadata.status")
        _require_text(self.created_at, "WorkspaceMetadata.created_at")
        _require_text(self.updated_at, "WorkspaceMetadata.updated_at")
        object.__setattr__(self, "labels", _id_tuple(self.labels, "WorkspaceMetadata.labels"))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkspaceMetadata":
        _require_fields(data, cls.__name__, "title", "created_at", "updated_at")
        values = dict(data)
        values["labels"] = tuple(values.get("labels", ()))
        return cls(**values)


@dataclass(frozen=True)
class EvidenceReference(SerializableModel):
    reference_id: str
    source_type: str
    source_id: str
    artifact_key: str | None = None
    case_id: str | None = None
    timestamp: str | None = None
    label: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.reference_id, "EvidenceReference.reference_id")
        _require_text(self.source_id, "EvidenceReference.source_id")
        if self.source_type not in EVIDENCE_SOURCE_TYPES:
            raise ValueError(
                "EvidenceReference.source_type must be one of: "
                + ", ".join(sorted(EVIDENCE_SOURCE_TYPES))
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceReference":
        _require_fields(data, cls.__name__, "reference_id", "source_type", "source_id")
        return cls(**dict(data))


@dataclass(frozen=True)
class Hypothesis(SerializableModel):
    hypothesis_id: str
    statement: str
    state: str = "open"
    supporting_evidence_reference_ids: Tuple[str, ...] = ()
    contradicting_evidence_reference_ids: Tuple[str, ...] = ()
    created_at: str | None = None
    updated_at: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.hypothesis_id, "Hypothesis.hypothesis_id")
        _require_text(self.statement, "Hypothesis.statement")
        if self.state not in HYPOTHESIS_STATES:
            raise ValueError(
                "Hypothesis.state must be one of: " + ", ".join(sorted(HYPOTHESIS_STATES))
            )
        object.__setattr__(
            self,
            "supporting_evidence_reference_ids",
            _id_tuple(
                self.supporting_evidence_reference_ids,
                "Hypothesis.supporting_evidence_reference_ids",
            ),
        )
        object.__setattr__(
            self,
            "contradicting_evidence_reference_ids",
            _id_tuple(
                self.contradicting_evidence_reference_ids,
                "Hypothesis.contradicting_evidence_reference_ids",
            ),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Hypothesis":
        _require_fields(data, cls.__name__, "hypothesis_id", "statement")
        values = dict(data)
        values["supporting_evidence_reference_ids"] = tuple(
            values.get("supporting_evidence_reference_ids", ())
        )
        values["contradicting_evidence_reference_ids"] = tuple(
            values.get("contradicting_evidence_reference_ids", ())
        )
        return cls(**values)


@dataclass(frozen=True)
class Decision(SerializableModel):
    decision_id: str
    decision_type: str
    outcome: str
    rationale: str = ""
    evidence_reference_ids: Tuple[str, ...] = ()
    hypothesis_ids: Tuple[str, ...] = ()
    decided_at: str | None = None
    decided_by: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.decision_id, "Decision.decision_id")
        _require_text(self.decision_type, "Decision.decision_type")
        _require_text(self.outcome, "Decision.outcome")
        object.__setattr__(
            self,
            "evidence_reference_ids",
            _id_tuple(self.evidence_reference_ids, "Decision.evidence_reference_ids"),
        )
        object.__setattr__(
            self,
            "hypothesis_ids",
            _id_tuple(self.hypothesis_ids, "Decision.hypothesis_ids"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Decision":
        _require_fields(data, cls.__name__, "decision_id", "decision_type", "outcome")
        values = dict(data)
        values["evidence_reference_ids"] = tuple(values.get("evidence_reference_ids", ()))
        values["hypothesis_ids"] = tuple(values.get("hypothesis_ids", ()))
        return cls(**values)


@dataclass(frozen=True)
class TimelineSelection(SerializableModel):
    selection_id: str
    evidence_reference_ids: Tuple[str, ...] = ()
    start_time: str | None = None
    end_time: str | None = None
    entity_ids: Tuple[str, ...] = ()
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.selection_id, "TimelineSelection.selection_id")
        object.__setattr__(
            self,
            "evidence_reference_ids",
            _id_tuple(
                self.evidence_reference_ids,
                "TimelineSelection.evidence_reference_ids",
            ),
        )
        object.__setattr__(
            self,
            "entity_ids",
            _id_tuple(self.entity_ids, "TimelineSelection.entity_ids"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TimelineSelection":
        _require_fields(data, cls.__name__, "selection_id")
        values = dict(data)
        values["evidence_reference_ids"] = tuple(values.get("evidence_reference_ids", ()))
        values["entity_ids"] = tuple(values.get("entity_ids", ()))
        return cls(**values)


@dataclass(frozen=True)
class Annotation(SerializableModel):
    annotation_id: str
    target_type: str
    target_id: str
    body: str
    created_at: str
    updated_at: str | None = None
    created_by: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.updated_at is not None:
            _require_text(self.updated_at, "Annotation.updated_at")
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.annotation_id, "Annotation.annotation_id")
        _require_text(self.target_id, "Annotation.target_id")
        _require_text(self.body, "Annotation.body")
        _require_text(self.created_at, "Annotation.created_at")
        if self.target_type not in ANNOTATION_TARGET_TYPES:
            raise ValueError(
                "Annotation.target_type must be one of: "
                + ", ".join(sorted(ANNOTATION_TARGET_TYPES))
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Annotation":
        _require_fields(
            data,
            cls.__name__,
            "annotation_id",
            "target_type",
            "target_id",
            "body",
            "created_at",
        )
        return cls(**dict(data))


@dataclass(frozen=True)
class HandoffManifest(SerializableModel):
    manifest_id: str
    investigation_id: str
    evidence_reference_ids: Tuple[str, ...] = ()
    hypothesis_ids: Tuple[str, ...] = ()
    decision_ids: Tuple[str, ...] = ()
    annotation_ids: Tuple[str, ...] = ()
    artifact_keys: Tuple[str, ...] = ()
    created_at: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.manifest_id, "HandoffManifest.manifest_id")
        _require_text(self.investigation_id, "HandoffManifest.investigation_id")
        for field_name in (
            "evidence_reference_ids",
            "hypothesis_ids",
            "decision_ids",
            "annotation_ids",
            "artifact_keys",
        ):
            object.__setattr__(
                self,
                field_name,
                _id_tuple(getattr(self, field_name), f"HandoffManifest.{field_name}"),
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HandoffManifest":
        _require_fields(data, cls.__name__, "manifest_id", "investigation_id")
        values = dict(data)
        for key in (
            "evidence_reference_ids",
            "hypothesis_ids",
            "decision_ids",
            "annotation_ids",
            "artifact_keys",
        ):
            values[key] = tuple(values.get(key, ()))
        return cls(**values)


@dataclass(frozen=True)
class Investigation(SerializableModel):
    investigation_id: str
    analysis_id: str
    metadata: WorkspaceMetadata
    analysis_artifact_keys: Tuple[str, ...] = ()
    evidence_references: Tuple[EvidenceReference, ...] = ()
    hypotheses: Tuple[Hypothesis, ...] = ()
    decisions: Tuple[Decision, ...] = ()
    timeline_selections: Tuple[TimelineSelection, ...] = ()
    annotations: Tuple[Annotation, ...] = ()
    handoff_manifest: HandoffManifest | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.investigation_id, "Investigation.investigation_id")
        _require_text(self.analysis_id, "Investigation.analysis_id")
        if not isinstance(self.metadata, WorkspaceMetadata):
            raise ValueError("Investigation.metadata must be WorkspaceMetadata")
        object.__setattr__(
            self,
            "analysis_artifact_keys",
            _id_tuple(self.analysis_artifact_keys, "Investigation.analysis_artifact_keys"),
        )
        for field_name, item_type in (
            ("evidence_references", EvidenceReference),
            ("hypotheses", Hypothesis),
            ("decisions", Decision),
            ("timeline_selections", TimelineSelection),
            ("annotations", Annotation),
        ):
            normalized = _tuple_copy(getattr(self, field_name), f"Investigation.{field_name}")
            if any(not isinstance(item, item_type) for item in normalized):
                raise ValueError(
                    f"Investigation.{field_name} must contain only {item_type.__name__} objects"
                )
            object.__setattr__(self, field_name, normalized)
        if self.handoff_manifest is not None and not isinstance(
            self.handoff_manifest, HandoffManifest
        ):
            raise ValueError("Investigation.handoff_manifest must be HandoffManifest or None")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Investigation":
        _require_fields(data, cls.__name__, "investigation_id", "analysis_id", "metadata")
        values = dict(data)
        values["metadata"] = WorkspaceMetadata.from_dict(values["metadata"])
        values["analysis_artifact_keys"] = tuple(values.get("analysis_artifact_keys", ()))
        values["evidence_references"] = tuple(
            EvidenceReference.from_dict(item) for item in values.get("evidence_references", ())
        )
        values["hypotheses"] = tuple(Hypothesis.from_dict(item) for item in values.get("hypotheses", ()))
        values["decisions"] = tuple(Decision.from_dict(item) for item in values.get("decisions", ()))
        values["timeline_selections"] = tuple(
            TimelineSelection.from_dict(item) for item in values.get("timeline_selections", ())
        )
        values["annotations"] = tuple(Annotation.from_dict(item) for item in values.get("annotations", ()))
        manifest = values.get("handoff_manifest")
        values["handoff_manifest"] = HandoffManifest.from_dict(manifest) if manifest else None
        return cls(**values)
