from __future__ import annotations

from dataclasses import asdict, is_dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping

from soc_forge.investigations.models import AnalysisProvenance


DERIVATION_ALGORITHM = "sha256-canonical-json-v1"


class ProvenanceDerivationError(ValueError):
    pass


def canonical_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        raise TypeError("filesystem paths are not provenance content")
    if is_dataclass(value):
        return canonical_value(asdict(value))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("mapping keys must be strings")
        return {key: canonical_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [canonical_value(item) for item in value]
        return sorted(normalized, key=canonical_json)
    raise TypeError(f"unsupported value type {type(value).__name__}")


def canonical_json(value: object) -> str:
    return json.dumps(
        canonical_value(value),
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )


def content_digest(value: object, field_name: str) -> str:
    try:
        return sha256(canonical_json(value).encode("utf-8")).hexdigest()
    except (TypeError, ValueError) as exc:
        raise ProvenanceDerivationError(
            f"Completed analysis {field_name} cannot be canonicalized: {exc}"
        ) from exc


def derive_analysis_provenance(
    *,
    normalized_input_name: str,
    events: object,
    alerts: object,
    cases: object,
    reconstructions: object,
    artifact_keys: tuple[str, ...],
) -> AnalysisProvenance:
    event_digest = content_digest(events, "events")
    alert_digest = content_digest(alerts, "alerts")
    case_digest = content_digest(cases, "cases")
    reconstruction_digest = content_digest(reconstructions, "reconstructions")
    rule_ids = sorted(
        {
            str(alert["rule_id"]).strip()
            for alert in alerts
            if isinstance(alert, Mapping) and str(alert.get("rule_id") or "").strip()
        }
    )
    rule_set_digest = content_digest(rule_ids, "rule IDs")
    manifest = {
        "provenance_schema_version": "1.0",
        "derivation_algorithm": DERIVATION_ALGORITHM,
        "normalized_input_name": normalized_input_name,
        "event_digest": event_digest,
        "alert_digest": alert_digest,
        "case_digest": case_digest,
        "reconstruction_digest": reconstruction_digest,
        "rule_set_digest": rule_set_digest,
        "artifact_keys": artifact_keys,
    }
    source_analysis_id = "analysis-" + sha256(
        canonical_json(manifest).encode("utf-8")
    ).hexdigest()[:20]
    return AnalysisProvenance(
        source_analysis_id=source_analysis_id,
        normalized_input_name=normalized_input_name,
        event_digest=event_digest,
        alert_digest=alert_digest,
        case_digest=case_digest,
        reconstruction_digest=reconstruction_digest,
        rule_set_digest=rule_set_digest,
        artifact_keys=artifact_keys,
        derivation_algorithm=DERIVATION_ALGORITHM,
    )
