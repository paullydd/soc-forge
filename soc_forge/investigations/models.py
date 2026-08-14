from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
import re
from typing import Any, Dict, Mapping, Tuple, Type, TypeVar


INVESTIGATION_SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_MAJOR = 1

EVIDENCE_SOURCE_TYPES = frozenset(
    {"event", "alert", "case", "hunt", "correlation", "reconstruction", "artifact"}
)
EVIDENCE_REFERENCE_ORIGINS = frozenset({"scope", "analyst_selection"})
EVIDENCE_CLASSIFICATIONS = frozenset({"supporting", "contradicting", "context"})
SELECTABLE_EVIDENCE_TYPES = frozenset({"event", "alert", "case", "reconstruction_step"})
HYPOTHESIS_STATES = frozenset({"open", "supported", "rejected", "inconclusive"})
ANNOTATION_TARGET_TYPES = frozenset(
    {"investigation", "evidence", "hypothesis", "decision", "timeline_selection", "case", "analysis"}
)
INTERNAL_ANNOTATION_TARGET_TYPES = frozenset(
    {"investigation", "evidence", "hypothesis", "decision", "timeline_selection"}
)
EXTERNAL_ANNOTATION_TARGET_TYPES = ANNOTATION_TARGET_TYPES.difference(
    INTERNAL_ANNOTATION_TARGET_TYPES
)


class InvestigationIntegrityError(ValueError):
    """Base error for an internally inconsistent investigation aggregate."""


class DuplicateChildIdError(InvestigationIntegrityError):
    pass


class MissingInvestigationReferenceError(InvestigationIntegrityError):
    pass


class InvalidAnnotationTargetError(InvestigationIntegrityError):
    pass


class MismatchedHandoffInvestigationError(InvestigationIntegrityError):
    pass


class ContradictoryEvidenceAssignmentError(InvestigationIntegrityError):
    pass

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
class AnalysisProvenance(SerializableModel):
    source_analysis_id: str
    normalized_input_name: str
    event_digest: str
    alert_digest: str
    case_digest: str
    reconstruction_digest: str
    rule_set_digest: str
    artifact_keys: Tuple[str, ...] = ()
    derivation_algorithm: str = "sha256-canonical-json-v1"
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        for field_name in (
            "source_analysis_id",
            "normalized_input_name",
            "event_digest",
            "alert_digest",
            "case_digest",
            "reconstruction_digest",
            "rule_set_digest",
            "derivation_algorithm",
        ):
            _require_text(getattr(self, field_name), f"AnalysisProvenance.{field_name}")
        object.__setattr__(
            self,
            "artifact_keys",
            _id_tuple(self.artifact_keys, "AnalysisProvenance.artifact_keys"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AnalysisProvenance":
        _require_fields(
            data,
            cls.__name__,
            "source_analysis_id",
            "normalized_input_name",
            "event_digest",
            "alert_digest",
            "case_digest",
            "reconstruction_digest",
            "rule_set_digest",
        )
        values = dict(data)
        values["artifact_keys"] = tuple(values.get("artifact_keys", ()))
        return cls(**values)


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
    origin: str = "scope"
    classification: str | None = None
    rationale: str | None = None
    selected_by: str | None = None
    selected_at: str | None = None
    selection_updated_at: str | None = None
    source_analysis_id: str | None = None
    evidence_type: str | None = None
    scope_case_ids: Tuple[str, ...] = ()
    provenance_fields: Tuple[str, ...] = ()
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
        if self.origin not in EVIDENCE_REFERENCE_ORIGINS:
            raise ValueError(
                "EvidenceReference.origin must be one of: "
                + ", ".join(sorted(EVIDENCE_REFERENCE_ORIGINS))
            )
        object.__setattr__(
            self,
            "scope_case_ids",
            _id_tuple(self.scope_case_ids, "EvidenceReference.scope_case_ids"),
        )
        object.__setattr__(
            self,
            "provenance_fields",
            _id_tuple(self.provenance_fields, "EvidenceReference.provenance_fields"),
        )
        if self.origin == "analyst_selection":
            if self.classification not in EVIDENCE_CLASSIFICATIONS:
                raise ValueError(
                    "EvidenceReference.classification must be one of: "
                    + ", ".join(sorted(EVIDENCE_CLASSIFICATIONS))
                )
            for field_name in (
                "rationale",
                "selected_by",
                "selected_at",
                "source_analysis_id",
                "evidence_type",
            ):
                _require_text(
                    getattr(self, field_name),
                    f"EvidenceReference.{field_name}",
                )
            if self.evidence_type not in SELECTABLE_EVIDENCE_TYPES:
                raise ValueError(
                    "EvidenceReference.evidence_type must be one of: "
                    + ", ".join(sorted(SELECTABLE_EVIDENCE_TYPES))
                )
        elif self.classification is not None:
            raise ValueError(
                "Scope EvidenceReference objects cannot carry analyst classification"
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceReference":
        _require_fields(data, cls.__name__, "reference_id", "source_type", "source_id")
        values = dict(data)
        values["scope_case_ids"] = tuple(values.get("scope_case_ids", ()))
        values["provenance_fields"] = tuple(values.get("provenance_fields", ()))
        return cls(**values)


@dataclass(frozen=True)
class Hypothesis(SerializableModel):
    hypothesis_id: str
    statement: str
    state: str = "open"
    supporting_evidence_reference_ids: Tuple[str, ...] = ()
    contradicting_evidence_reference_ids: Tuple[str, ...] = ()
    created_at: str | None = None
    updated_at: str | None = None
    author: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        _require_text(self.hypothesis_id, "Hypothesis.hypothesis_id")
        _require_text(self.statement, "Hypothesis.statement")
        if self.state not in HYPOTHESIS_STATES:
            raise ValueError(
                "Hypothesis.state must be one of: " + ", ".join(sorted(HYPOTHESIS_STATES))
            )
        if self.author is not None:
            _require_text(self.author, "Hypothesis.author")
        if self.created_at is not None:
            _require_text(self.created_at, "Hypothesis.created_at")
        if self.updated_at is not None:
            _require_text(self.updated_at, "Hypothesis.updated_at")
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




FINDING_STATUSES = frozenset(
    {"draft", "substantiated", "unsubstantiated", "inconclusive"}
)
FINDING_CONFIDENCES = frozenset({"low", "medium", "high"})
FINDING_LIFECYCLE_STATES = frozenset({"active", "superseded"})
RESPONSE_ACTION_TYPES = frozenset(
    {
        "containment",
        "credential_action",
        "host_action",
        "network_action",
        "collection",
        "validation",
        "monitoring",
        "communication",
        "other",
    }
)
RESPONSE_ACTION_PRIORITIES = frozenset({"low", "medium", "high", "critical"})
RESPONSE_ACTION_STATUSES = frozenset(
    {"proposed", "approved", "in_progress", "completed", "dismissed"}
)
FINDING_TITLE_LIMIT = 160
FINDING_CONCLUSION_LIMIT = 4000
FINDING_LIMITATION_LIMIT = 1000
DURABLE_MANUAL_ID_LIMIT = 128


def _bounded_text(value: Any, field_name: str, limit: int) -> str:
    _require_text(value, field_name)
    normalized = value.strip()
    if len(normalized) > limit:
        raise ValueError(f"{field_name} must be at most {limit} characters")
    return normalized


def _manual_id(value: Any, field_name: str) -> str:
    normalized = _bounded_text(value, field_name, DURABLE_MANUAL_ID_LIMIT)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", normalized):
        raise ValueError(
            f"{field_name} must use letters, numbers, '.', '_', or '-'"
        )
    return normalized


@dataclass(frozen=True)
class InvestigationFinding(SerializableModel):
    finding_id: str
    investigation_id: str
    title: str
    conclusion: str
    status: str
    confidence: str
    author: str
    created_at: str
    updated_at: str
    evidence_ids: Tuple[str, ...] = ()
    hypothesis_ids: Tuple[str, ...] = ()
    decision_ids: Tuple[str, ...] = ()
    attack_tactics: Tuple[str, ...] = ()
    attack_techniques: Tuple[str, ...] = ()
    limitations: Tuple[str, ...] = ()
    lifecycle_state: str = "active"
    supersedes_finding_id: str | None = None
    superseded_by_finding_id: str | None = None
    supersession_reason: str | None = None
    supersession_author: str | None = None
    superseded_at: str | None = None
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        object.__setattr__(
            self, "finding_id", _manual_id(
                self.finding_id, "InvestigationFinding.finding_id"
            )
        )
        object.__setattr__(
            self,
            "investigation_id",
            _bounded_text(
                self.investigation_id,
                "InvestigationFinding.investigation_id",
                DURABLE_MANUAL_ID_LIMIT,
            ),
        )
        for field_name, limit in (
            ("title", FINDING_TITLE_LIMIT),
            ("conclusion", FINDING_CONCLUSION_LIMIT),
            ("author", FINDING_TITLE_LIMIT),
            ("created_at", FINDING_TITLE_LIMIT),
            ("updated_at", FINDING_TITLE_LIMIT),
        ):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(
                    getattr(self, field_name),
                    f"InvestigationFinding.{field_name}",
                    limit,
                ),
            )
        if self.status not in FINDING_STATUSES:
            raise ValueError(
                "InvestigationFinding.status must be one of: "
                + ", ".join(sorted(FINDING_STATUSES))
            )
        if self.confidence not in FINDING_CONFIDENCES:
            raise ValueError(
                "InvestigationFinding.confidence must be one of: "
                + ", ".join(sorted(FINDING_CONFIDENCES))
            )
        if self.lifecycle_state not in FINDING_LIFECYCLE_STATES:
            raise ValueError("Invalid InvestigationFinding.lifecycle_state")
        for field_name in ("supersedes_finding_id", "superseded_by_finding_id"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _manual_id(value, f"InvestigationFinding.{field_name}"))
        for field_name, limit in (("supersession_reason", FINDING_LIMITATION_LIMIT), ("supersession_author", FINDING_TITLE_LIMIT), ("superseded_at", FINDING_TITLE_LIMIT)):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _bounded_text(value, f"InvestigationFinding.{field_name}", limit))
        if self.finding_id in {self.supersedes_finding_id, self.superseded_by_finding_id}:
            raise ValueError("InvestigationFinding cannot supersede itself")
        metadata = (self.supersession_reason, self.supersession_author, self.superseded_at)
        if self.lifecycle_state == "active" and (self.superseded_by_finding_id is not None or any(metadata)):
            raise ValueError("Active InvestigationFinding cannot carry superseded metadata")
        if self.lifecycle_state == "superseded" and (self.superseded_by_finding_id is None or not all(metadata)):
            raise ValueError("Superseded InvestigationFinding requires replacement, reason, author, and timestamp")
        for field_name in (
            "evidence_ids",
            "hypothesis_ids",
            "decision_ids",
            "attack_tactics",
            "attack_techniques",
        ):
            values = _id_tuple(
                getattr(self, field_name),
                f"InvestigationFinding.{field_name}",
            )
            if len(values) != len(set(values)):
                raise ValueError(
                    f"InvestigationFinding.{field_name} cannot contain duplicates"
                )
            object.__setattr__(self, field_name, values)
        limitations = _tuple_copy(
            self.limitations, "InvestigationFinding.limitations"
        )
        normalized_limitations = tuple(
            _bounded_text(
                item,
                "InvestigationFinding.limitations item",
                FINDING_LIMITATION_LIMIT,
            )
            for item in limitations
        )
        if len(normalized_limitations) != len(set(normalized_limitations)):
            raise ValueError(
                "InvestigationFinding.limitations cannot contain duplicates"
            )
        object.__setattr__(self, "limitations", normalized_limitations)
        if not (self.evidence_ids or self.hypothesis_ids or self.decision_ids):
            raise ValueError(
                "InvestigationFinding requires at least one evidence, "
                "hypothesis, or decision reference"
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InvestigationFinding":
        _require_fields(
            data,
            cls.__name__,
            "finding_id",
            "investigation_id",
            "title",
            "conclusion",
            "status",
            "confidence",
            "author",
            "created_at",
            "updated_at",
        )
        values = dict(data)
        for field_name in (
            "evidence_ids",
            "hypothesis_ids",
            "decision_ids",
            "attack_tactics",
            "attack_techniques",
            "limitations",
        ):
            values[field_name] = tuple(values.get(field_name, ()))
        return cls(**values)

@dataclass(frozen=True)
class ResponseActionTransition(SerializableModel):
    transition_id: str
    from_status: str
    to_status: str
    author: str
    rationale: str
    timestamp: str
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        object.__setattr__(
            self,
            "transition_id",
            _manual_id(self.transition_id, "ResponseActionTransition.transition_id"),
        )
        for field_name in ("from_status", "to_status"):
            if getattr(self, field_name) not in RESPONSE_ACTION_STATUSES:
                raise ValueError(
                    f"ResponseActionTransition.{field_name} must be one of: "
                    + ", ".join(sorted(RESPONSE_ACTION_STATUSES))
                )
        for field_name, limit in (
            ("author", FINDING_TITLE_LIMIT),
            ("rationale", FINDING_CONCLUSION_LIMIT),
            ("timestamp", FINDING_TITLE_LIMIT),
        ):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(
                    getattr(self, field_name),
                    f"ResponseActionTransition.{field_name}",
                    limit,
                ),
            )
        if self.from_status == self.to_status:
            raise ValueError("ResponseActionTransition must change status")


@dataclass(frozen=True)
class ResponseAction(SerializableModel):
    action_id: str
    investigation_id: str
    finding_ids: Tuple[str, ...]
    title: str
    description: str
    action_type: str
    priority: str
    status: str
    rationale: str
    owner: str
    created_by: str
    created_at: str
    updated_at: str
    transition_history: Tuple[ResponseActionTransition, ...] = ()
    schema_version: str = INVESTIGATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_schema_version(self.schema_version, type(self).__name__)
        action_id = _manual_id(self.action_id, "ResponseAction.action_id")
        if not action_id.startswith("ACT-"):
            raise ValueError("ResponseAction.action_id must use the ACT- prefix")
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(
            self,
            "investigation_id",
            _bounded_text(
                self.investigation_id,
                "ResponseAction.investigation_id",
                DURABLE_MANUAL_ID_LIMIT,
            ),
        )
        finding_ids = _id_tuple(self.finding_ids, "ResponseAction.finding_ids")
        if not finding_ids:
            raise ValueError("ResponseAction requires at least one Finding")
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("ResponseAction.finding_ids cannot contain duplicates")
        object.__setattr__(self, "finding_ids", finding_ids)
        for field_name, limit in (
            ("title", FINDING_TITLE_LIMIT),
            ("description", FINDING_CONCLUSION_LIMIT),
            ("rationale", FINDING_CONCLUSION_LIMIT),
            ("owner", FINDING_TITLE_LIMIT),
            ("created_by", FINDING_TITLE_LIMIT),
            ("created_at", FINDING_TITLE_LIMIT),
            ("updated_at", FINDING_TITLE_LIMIT),
        ):
            object.__setattr__(
                self,
                field_name,
                _bounded_text(
                    getattr(self, field_name),
                    f"ResponseAction.{field_name}",
                    limit,
                ),
            )
        history = _tuple_copy(
            self.transition_history, "ResponseAction.transition_history"
        )
        if any(not isinstance(item, ResponseActionTransition) for item in history):
            raise ValueError(
                "ResponseAction.transition_history must contain only "
                "ResponseActionTransition objects"
            )
        transition_ids = [item.transition_id for item in history]
        if len(transition_ids) != len(set(transition_ids)):
            raise ValueError("ResponseAction.transition_history has duplicate IDs")
        for previous, current in zip(history, history[1:]):
            if previous.to_status != current.from_status:
                raise ValueError("ResponseAction.transition_history is not contiguous")
        if history and history[-1].to_status != self.status:
            raise ValueError(
                "ResponseAction.status must match the final transition state"
            )
        object.__setattr__(self, "transition_history", history)

        for field_name, allowed in (
            ("action_type", RESPONSE_ACTION_TYPES),
            ("priority", RESPONSE_ACTION_PRIORITIES),
            ("status", RESPONSE_ACTION_STATUSES),
        ):
            if getattr(self, field_name) not in allowed:
                raise ValueError(
                    f"ResponseAction.{field_name} must be one of: "
                    + ", ".join(sorted(allowed))
                )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResponseAction":
        _require_fields(
            data,
            cls.__name__,
            "action_id",
            "investigation_id",
            "finding_ids",
            "title",
            "description",
            "action_type",
            "priority",
            "status",
            "rationale",
            "owner",
            "created_by",
            "created_at",
            "updated_at",
        )
        values = dict(data)
        values["finding_ids"] = tuple(values["finding_ids"])
        values["transition_history"] = tuple(
            ResponseActionTransition.from_dict(item)
            for item in values.get("transition_history", ())
        )
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
    findings: Tuple[InvestigationFinding, ...] = ()
    response_actions: Tuple[ResponseAction, ...] = ()
    timeline_selections: Tuple[TimelineSelection, ...] = ()
    annotations: Tuple[Annotation, ...] = ()
    handoff_manifest: HandoffManifest | None = None
    provenance: AnalysisProvenance | None = None
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
            ("findings", InvestigationFinding),
            ("response_actions", ResponseAction),
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
        if self.provenance is not None and not isinstance(self.provenance, AnalysisProvenance):
            raise ValueError("Investigation.provenance must be AnalysisProvenance or None")
        if self.provenance is not None and self.provenance.source_analysis_id != self.analysis_id:
            raise MissingInvestigationReferenceError(
                f"Investigation {self.investigation_id!r} provenance source analysis ID "
                f"{self.provenance.source_analysis_id!r} does not match analysis_id"
            )
        self._validate_integrity()

    def _validate_integrity(self) -> None:
        child_ids = {
            "evidence reference": self._unique_child_ids(
                "evidence reference", self.evidence_references, "reference_id"
            ),
            "hypothesis": self._unique_child_ids(
                "hypothesis", self.hypotheses, "hypothesis_id"
            ),
            "decision": self._unique_child_ids("decision", self.decisions, "decision_id"),
            "finding": self._unique_child_ids("finding", self.findings, "finding_id"),
            "response action": self._unique_child_ids(
                "response action", self.response_actions, "action_id"
            ),
            "timeline selection": self._unique_child_ids(
                "timeline selection", self.timeline_selections, "selection_id"
            ),
            "annotation": self._unique_child_ids(
                "annotation", self.annotations, "annotation_id"
            ),
        }
        evidence_ids = child_ids["evidence reference"]
        selected_evidence_ids = {
            item.reference_id for item in self.evidence_references
            if item.origin == "analyst_selection"
        }
        hypothesis_ids = child_ids["hypothesis"]
        decision_ids = child_ids["decision"]
        finding_ids = child_ids["finding"]
        timeline_ids = child_ids["timeline selection"]
        annotation_ids = child_ids["annotation"]
        for evidence in self.evidence_references:
            if (
                evidence.origin == "analyst_selection"
                and evidence.source_analysis_id != self.analysis_id
            ):
                raise MissingInvestigationReferenceError(
                    f"Investigation {self.investigation_id!r} evidence reference "
                    f"{evidence.reference_id!r} belongs to source analysis "
                    f"{evidence.source_analysis_id!r}, not {self.analysis_id!r}"
                )


        for hypothesis in self.hypotheses:
            overlap = sorted(
                set(hypothesis.supporting_evidence_reference_ids).intersection(
                    hypothesis.contradicting_evidence_reference_ids
                )
            )
            if overlap:
                raise ContradictoryEvidenceAssignmentError(
                    f"Investigation {self.investigation_id!r} hypothesis "
                    f"{hypothesis.hypothesis_id!r} assigns evidence {overlap[0]!r} "
                    "as both supporting and contradicting"
                )
            self._require_references(
                "hypothesis", hypothesis.hypothesis_id, "supporting evidence",
                hypothesis.supporting_evidence_reference_ids, evidence_ids,
            )
            self._require_references(
                "hypothesis", hypothesis.hypothesis_id, "contradicting evidence",
                hypothesis.contradicting_evidence_reference_ids, evidence_ids,
            )

        for decision in self.decisions:
            self._require_references(
                "decision", decision.decision_id, "evidence",
                decision.evidence_reference_ids, evidence_ids,
            )
            self._require_references(
                "decision", decision.decision_id, "hypothesis",
                decision.hypothesis_ids, hypothesis_ids,
            )


        for finding in self.findings:
            if finding.investigation_id != self.investigation_id:
                raise MissingInvestigationReferenceError(
                    f"Investigation {self.investigation_id!r} finding "
                    f"{finding.finding_id!r} names investigation "
                    f"{finding.investigation_id!r}"
                )
            self._require_references(
                "finding", finding.finding_id, "evidence",
                finding.evidence_ids, selected_evidence_ids,
            )
            self._require_references(
                "finding", finding.finding_id, "hypothesis",
                finding.hypothesis_ids, hypothesis_ids,
            )
            self._require_references(
                "finding", finding.finding_id, "decision",
                finding.decision_ids, decision_ids,
            )
        findings_by_id = {item.finding_id: item for item in self.findings}
        for finding in self.findings:
            if finding.supersedes_finding_id is not None:
                prior = findings_by_id.get(finding.supersedes_finding_id)
                if prior is None or prior.superseded_by_finding_id != finding.finding_id:
                    raise MissingInvestigationReferenceError(f"Finding {finding.finding_id!r} has inconsistent supersession")
            if finding.superseded_by_finding_id is not None:
                replacement = findings_by_id.get(finding.superseded_by_finding_id)
                if replacement is None or replacement.supersedes_finding_id != finding.finding_id:
                    raise MissingInvestigationReferenceError(f"Finding {finding.finding_id!r} has inconsistent supersession")
        for origin in self.findings:
            seen = set()
            current = origin
            while current.superseded_by_finding_id is not None:
                if current.finding_id in seen:
                    raise MissingInvestigationReferenceError("Finding supersession graph contains a cycle")
                seen.add(current.finding_id)
                current = findings_by_id[current.superseded_by_finding_id]

        for action in self.response_actions:
            if action.investigation_id != self.investigation_id:
                raise MissingInvestigationReferenceError(
                    f"Investigation {self.investigation_id!r} response action "
                    f"{action.action_id!r} names investigation {action.investigation_id!r}"
                )
            self._require_references(
                "response action", action.action_id, "finding",
                action.finding_ids, finding_ids,
            )

        for selection in self.timeline_selections:
            self._require_references(
                "timeline selection", selection.selection_id, "evidence",
                selection.evidence_reference_ids, evidence_ids,
            )

        target_ids = {
            "investigation": {self.investigation_id},
            "evidence": evidence_ids,
            "hypothesis": hypothesis_ids,
            "decision": decision_ids,
            "timeline_selection": timeline_ids,
        }
        for annotation in self.annotations:
            if annotation.target_type in INTERNAL_ANNOTATION_TARGET_TYPES:
                if annotation.target_id not in target_ids[annotation.target_type]:
                    raise InvalidAnnotationTargetError(
                        f"Investigation {self.investigation_id!r} annotation "
                        f"{annotation.annotation_id!r} targets missing "
                        f"{annotation.target_type} {annotation.target_id!r}"
                    )

        manifest = self.handoff_manifest
        if manifest is not None:
            if manifest.investigation_id != self.investigation_id:
                raise MismatchedHandoffInvestigationError(
                    f"Investigation {self.investigation_id!r} handoff manifest "
                    f"{manifest.manifest_id!r} names investigation "
                    f"{manifest.investigation_id!r}"
                )
            for relationship, references, known in (
                ("evidence", manifest.evidence_reference_ids, evidence_ids),
                ("hypothesis", manifest.hypothesis_ids, hypothesis_ids),
                ("decision", manifest.decision_ids, decision_ids),
                ("annotation", manifest.annotation_ids, annotation_ids),
                ("artifact", manifest.artifact_keys, set(self.analysis_artifact_keys)),
            ):
                self._require_references(
                    "handoff manifest", manifest.manifest_id, relationship,
                    references, known,
                )

    def _unique_child_ids(self, child_type: str, children: tuple, id_field: str) -> set[str]:
        seen: set[str] = set()
        for child in children:
            child_id = getattr(child, id_field)
            if child_id in seen:
                raise DuplicateChildIdError(
                    f"Investigation {self.investigation_id!r} has duplicate "
                    f"{child_type} ID {child_id!r}"
                )
            seen.add(child_id)
        return seen

    def _require_references(
        self,
        child_type: str,
        child_id: str,
        relationship: str,
        references: Tuple[str, ...],
        known_ids: set[str],
    ) -> None:
        missing = sorted(set(references).difference(known_ids))
        if missing:
            raise MissingInvestigationReferenceError(
                f"Investigation {self.investigation_id!r} {child_type} {child_id!r} "
                f"references missing {relationship} ID {missing[0]!r}"
            )

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
        values["findings"] = tuple(
            InvestigationFinding.from_dict(item) for item in values.get("findings", ())
        )
        values["response_actions"] = tuple(
            ResponseAction.from_dict(item) for item in values.get("response_actions", ())
        )
        values["timeline_selections"] = tuple(
            TimelineSelection.from_dict(item) for item in values.get("timeline_selections", ())
        )
        values["annotations"] = tuple(Annotation.from_dict(item) for item in values.get("annotations", ()))
        manifest = values.get("handoff_manifest")
        values["handoff_manifest"] = HandoffManifest.from_dict(manifest) if manifest else None
        provenance = values.get("provenance")
        values["provenance"] = AnalysisProvenance.from_dict(provenance) if provenance else None
        return cls(**values)
