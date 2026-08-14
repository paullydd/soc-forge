from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Dict, Mapping, Tuple

from soc_forge import __version__
from soc_forge.investigations.models import (
    HandoffManifest,
    Investigation,
    InvestigationFinding,
    ResponseAction,
)
from soc_forge.investigations.query_context import InvestigationQueryContext
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.pipeline import AnalysisResult


HANDOFF_SCHEMA_VERSION = "1.3"
LEGACY_HANDOFF_SCHEMA_VERSION = "1.0"
FINDINGS_HANDOFF_SCHEMA_VERSION = "1.1"
FINDING_LIFECYCLE_HANDOFF_SCHEMA_VERSION = "1.2"
HANDOFF_TOOL = "SOC-Forge"
HANDOFF_PREVIEW_TEXT_LIMIT = 240
SENSITIVE_DATA_WARNING = (
    "This handoff may contain sensitive security telemetry and analyst-authored "
    "content. Review and redact before external sharing."
)
LEGACY_REQUIRED_COMPONENTS = frozenset(
    {
        "investigation.json",
        "evidence_index.json",
        "hypotheses.json",
        "decisions.json",
        "annotations.json",
        "timeline.json",
        "limitations.json",
    }
)
REQUIRED_COMPONENTS = LEGACY_REQUIRED_COMPONENTS | {"findings.json"}
CURRENT_REQUIRED_COMPONENTS = REQUIRED_COMPONENTS | {"response_actions.json"}
SUPPORTED_HANDOFF_SCHEMA_VERSIONS = frozenset(
    {LEGACY_HANDOFF_SCHEMA_VERSION, FINDINGS_HANDOFF_SCHEMA_VERSION, FINDING_LIFECYCLE_HANDOFF_SCHEMA_VERSION, HANDOFF_SCHEMA_VERSION}
)
ARTIFACT_FILENAMES = {
    "alerts": "alerts.json",
    "cases": "cases.json",
    "events": "events.json",
    "hunts": "hunts.json",
    "reconstructions": "reconstructions.json",
    "report": "report.html",
}
REQUIRED_ARTIFACT_KEYS = frozenset({"cases"})


class HandoffError(Exception):
    """Base error for deterministic investigation handoff operations."""


class HandoffProvenanceMismatchError(HandoffError):
    pass


class InvestigationChangedDuringHandoffError(HandoffError):
    pass


class UnsafeHandoffOutputPathError(HandoffError):
    pass


class UnsafeHandoffArtifactPathError(HandoffError):
    pass


class RequiredHandoffArtifactMissingError(HandoffError):
    pass


class HandoffBundleValidationError(HandoffError):
    pass


class UnsupportedHandoffSchemaError(HandoffBundleValidationError):
    pass


class HandoffArtifactDigestMismatchError(HandoffBundleValidationError):
    pass


class HandoffReferenceIntegrityError(HandoffBundleValidationError):
    pass


@dataclass(frozen=True)
class HandoffFile:
    filename: str
    logical_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class HandoffResult:
    handoff_id: str
    investigation_id: str
    revision: int
    output_path: Path
    manifest_path: Path
    files: Tuple[HandoffFile, ...]
    warnings: Tuple[str, ...]
    validation_status: str


@dataclass(frozen=True)
class HandoffFindingPreview:
    finding_id: str
    title: str
    conclusion: str
    status: str
    confidence: str
    author: str
    updated_at: str
    evidence_count: int
    hypothesis_count: int
    decision_count: int
    evidence_ids: Tuple[str, ...]
    hypothesis_ids: Tuple[str, ...]
    decision_ids: Tuple[str, ...]
    attack_tactics: Tuple[str, ...]
    attack_techniques: Tuple[str, ...]
    limitations: Tuple[str, ...]
    lifecycle_state: str
    supersedes_finding_id: str | None
    superseded_by_finding_id: str | None
    supersession_reason: str | None
    supersession_author: str | None
    superseded_at: str | None
    attribution: str = "analyst"


@dataclass(frozen=True)
class HandoffResponseActionPreview:
    action_id: str
    title: str
    action_type: str
    priority: str
    status: str
    owner: str
    finding_ids: Tuple[str, ...]
    transition_count: int


@dataclass(frozen=True)
class HandoffPreview:
    investigation_id: str
    title: str
    owner: str | None
    status: str
    revision: int
    source_analysis_id: str
    selected_case_count: int
    analyst_evidence_count: int
    hypothesis_count: int
    decision_count: int
    finding_count: int
    findings: Tuple[HandoffFindingPreview, ...]
    response_action_count: int
    response_actions: Tuple[HandoffResponseActionPreview, ...]
    annotation_count: int
    timed_entry_count: int
    untimed_entry_count: int
    available_artifact_keys: Tuple[str, ...]
    required_artifacts_available: bool
    missing_required_artifact_keys: Tuple[str, ...]
    missing_optional_artifact_keys: Tuple[str, ...]
    mode: str
    source_analysis_available: bool
    sensitive_data_warning: str = SENSITIVE_DATA_WARNING


@dataclass(frozen=True)
class HandoffManifestSummary:
    schema_version: str
    handoff_id: str
    investigation_id: str
    source_analysis_id: str
    revision: int
    owner: str | None
    status: str
    selected_case_ids: Tuple[str, ...]
    files: Tuple[HandoffFile, ...]
    limitations: Tuple[str, ...]
    sensitive_data_warning: str


def _preview_text(value: object) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= HANDOFF_PREVIEW_TEXT_LIMIT:
        return text
    return text[: HANDOFF_PREVIEW_TEXT_LIMIT - 3].rstrip() + "..."


def _json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _digest_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _safe_segment(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value in {".", ".."}
        or Path(value).is_absolute()
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise UnsafeHandoffOutputPathError(f"{label} is not a safe path segment")
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _write_component(root: Path, filename: str, payload: Any) -> None:
    destination = root / filename
    if destination.parent != root:
        raise UnsafeHandoffOutputPathError("Handoff component path is unsafe")
    destination.write_bytes(_json_bytes(payload))


def _serialize_evidence(investigation: Investigation) -> Dict[str, Any]:
    selected = []
    scope = []
    for reference in sorted(
        investigation.evidence_references,
        key=lambda item: (item.origin, item.reference_id),
    ):
        if reference.origin == "analyst_selection":
            selected.append(
                {
                    "evidence_id": reference.reference_id,
                    "evidence_type": reference.evidence_type,
                    "source_id": reference.source_id,
                    "source_type": reference.source_type,
                    "classification": reference.classification,
                    "rationale": reference.rationale,
                    "author": reference.selected_by,
                    "selected_at": reference.selected_at,
                    "selection_updated_at": reference.selection_updated_at,
                    "related_case_ids": sorted(reference.scope_case_ids),
                    "sensitive_field_indicators": sorted(reference.provenance_fields),
                    "provenance": {
                        "source_analysis_id": reference.source_analysis_id,
                        "artifact_key": reference.artifact_key,
                    },
                }
            )
        else:
            scope.append(
                {
                    "reference_id": reference.reference_id,
                    "source_type": reference.source_type,
                    "source_id": reference.source_id,
                    "case_id": reference.case_id,
                    "artifact_key": reference.artifact_key,
                }
            )
    return {"analyst_selected_evidence": selected, "scope_references": scope}


def _serialize_hypotheses(investigation: Investigation) -> Dict[str, Any]:
    assessments = {
        hypothesis.hypothesis_id: sorted(
            decision.decision_id
            for decision in investigation.decisions
            if decision.decision_type == "hypothesis_assessment"
            and hypothesis.hypothesis_id in decision.hypothesis_ids
        )
        for hypothesis in investigation.hypotheses
    }
    return {
        "hypotheses": [
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "statement": hypothesis.statement,
                "state": hypothesis.state,
                "author": hypothesis.author,
                "created_at": hypothesis.created_at,
                "updated_at": hypothesis.updated_at,
                "supporting_evidence_ids": sorted(
                    hypothesis.supporting_evidence_reference_ids
                ),
                "contradicting_evidence_ids": sorted(
                    hypothesis.contradicting_evidence_reference_ids
                ),
                "assessment_history_ids": assessments[hypothesis.hypothesis_id],
            }
            for hypothesis in sorted(
                investigation.hypotheses, key=lambda item: item.hypothesis_id
            )
        ]
    }


def _serialize_decisions(investigation: Investigation) -> Dict[str, Any]:
    return {
        "decisions": [
            {
                "decision_id": decision.decision_id,
                "decision_type": decision.decision_type,
                "outcome": decision.outcome,
                "rationale": decision.rationale,
                "author": decision.decided_by,
                "timestamp": decision.decided_at,
                "related_evidence_ids": sorted(decision.evidence_reference_ids),
                "related_hypothesis_ids": sorted(decision.hypothesis_ids),
            }
            for decision in sorted(
                investigation.decisions, key=lambda item: item.decision_id
            )
        ]
    }


def _serialize_findings(investigation: Investigation) -> Dict[str, Any]:
    return {
        "findings": [
            finding.to_dict()
            for finding in sorted(
                investigation.findings, key=lambda item: item.finding_id
            )
        ]
    }


def _serialize_response_actions(investigation: Investigation) -> Dict[str, Any]:
    return {"response_actions": [action.to_dict() for action in sorted(investigation.response_actions, key=lambda item: item.action_id)]}


def _serialize_annotations(investigation: Investigation) -> Dict[str, Any]:
    return {
        "annotations": [
            {
                "annotation_id": annotation.annotation_id,
                "target_type": annotation.target_type,
                "target_id": annotation.target_id,
                "author": annotation.created_by,
                "text": annotation.body,
                "created_at": annotation.created_at,
                "updated_at": annotation.updated_at,
                "sensitive": True,
            }
            for annotation in sorted(
                investigation.annotations, key=lambda item: item.annotation_id
            )
        ]
    }


def _serialize_timeline_entry(entry: Any) -> Dict[str, Any]:
    payload = asdict(entry)
    payload["case_ids"] = sorted(payload.get("case_ids") or [])
    payload["related_hypothesis_ids"] = sorted(
        payload.get("related_hypothesis_ids") or []
    )
    payload["related_decision_ids"] = sorted(
        payload.get("related_decision_ids") or []
    )
    payload["sensitive_fields"] = sorted(payload.get("sensitive_fields") or [])
    payload["hypothesis_overlays"] = sorted(
        payload.get("hypothesis_overlays") or [],
        key=lambda item: (item.get("hypothesis_id") or "", item.get("relationship") or ""),
    )
    payload["decision_overlays"] = sorted(
        payload.get("decision_overlays") or [],
        key=lambda item: item.get("decision_id") or "",
    )
    return payload


def _serialize_timeline(
    context: InvestigationQueryContext,
    timeline_service: InvestigationTimelineService,
) -> Dict[str, Any]:
    timeline = timeline_service.timeline(context)
    selections = [
        {
            "selection_id": selection.selection_id,
            "evidence_reference_ids": sorted(selection.evidence_reference_ids),
            "start_time": selection.start_time,
            "end_time": selection.end_time,
        }
        for selection in sorted(
            context.investigation.timeline_selections,
            key=lambda item: item.selection_id,
        )
    ]
    return {
        "investigation_id": timeline.investigation_id,
        "source_analysis_id": timeline.source_analysis_id,
        "timed_entries": [_serialize_timeline_entry(item) for item in timeline.entries],
        "untimed_entries": [
            _serialize_timeline_entry(item) for item in timeline.untimed_entries
        ],
        "timeline_selections": selections,
        "limitations": sorted(timeline.limitations),
    }


def _identity_payload(investigation: Investigation, revision: int) -> Dict[str, Any]:
    return {
        "schema_version": HANDOFF_SCHEMA_VERSION,
        "investigation_id": investigation.investigation_id,
        "source_analysis_id": investigation.analysis_id,
        "investigation_revision": revision,
        "selected_case_ids": sorted(
            reference.source_id
            for reference in investigation.evidence_references
            if reference.origin == "scope" and reference.source_type == "case"
        ),
        "evidence": [
            {
                "id": item.reference_id,
                "classification": item.classification,
                "rationale": item.rationale,
            }
            for item in sorted(
                (
                    item
                    for item in investigation.evidence_references
                    if item.origin == "analyst_selection"
                ),
                key=lambda item: item.reference_id,
            )
        ],
        "hypotheses": [
            {"id": item.hypothesis_id, "state": item.state}
            for item in sorted(
                investigation.hypotheses, key=lambda item: item.hypothesis_id
            )
        ],
        "decision_ids": sorted(item.decision_id for item in investigation.decisions),
        "finding_ids": sorted(item.finding_id for item in investigation.findings),
        "response_action_ids": sorted(item.action_id for item in investigation.response_actions),
        "annotation_ids": sorted(item.annotation_id for item in investigation.annotations),
        "timeline_selection_ids": sorted(
            item.selection_id for item in investigation.timeline_selections
        ),
    }


class InvestigationHandoffService:
    def __init__(
        self,
        repository: InvestigationRepository,
        *,
        timeline_service: InvestigationTimelineService | None = None,
        before_finalize: Callable[[], None] | None = None,
    ) -> None:
        self.repository = repository
        self.timeline_service = timeline_service or InvestigationTimelineService()
        self.before_finalize = before_finalize

    def preview(
        self,
        investigation_id: str,
        analysis: AnalysisResult | None,
    ) -> HandoffPreview:
        stored = self.repository.load_record(investigation_id)
        investigation = stored.investigation
        context = None
        if analysis is not None:
            try:
                context = InvestigationQueryContext(analysis, investigation)
            except Exception as exc:
                raise HandoffProvenanceMismatchError(
                    "The completed analysis does not match this investigation"
                ) from exc
            available, missing_required, missing_optional = self._artifact_status(
                analysis,
                investigation.analysis_artifact_keys,
            )
            timeline = self.timeline_service.timeline(context)
            timed_entry_count = len(timeline.entries)
            untimed_entry_count = len(timeline.untimed_entries)
        else:
            available, missing_required, missing_optional = self._offline_artifact_status(
                investigation.analysis_artifact_keys
            )
            timed_entry_count = 0
            untimed_entry_count = 0
        return HandoffPreview(
            investigation_id=investigation.investigation_id,
            title=investigation.metadata.title,
            owner=investigation.metadata.owner,
            status=investigation.metadata.status,
            revision=stored.revision,
            source_analysis_id=investigation.analysis_id,
            selected_case_count=sum(
                item.origin == "scope" and item.source_type == "case"
                for item in investigation.evidence_references
            ),
            analyst_evidence_count=sum(
                item.origin == "analyst_selection"
                for item in investigation.evidence_references
            ),
            hypothesis_count=len(investigation.hypotheses),
            decision_count=len(investigation.decisions),
            finding_count=len(investigation.findings),
            findings=tuple(
                HandoffFindingPreview(
                    finding_id=item.finding_id,
                    title=_preview_text(item.title),
                    conclusion=_preview_text(item.conclusion),
                    status=item.status,
                    confidence=item.confidence,
                    author=_preview_text(item.author),
                    updated_at=item.updated_at,
                    evidence_count=len(item.evidence_ids),
                    hypothesis_count=len(item.hypothesis_ids),
                    decision_count=len(item.decision_ids),
                    evidence_ids=tuple(sorted(item.evidence_ids)),
                    hypothesis_ids=tuple(sorted(item.hypothesis_ids)),
                    decision_ids=tuple(sorted(item.decision_ids)),
                    attack_tactics=tuple(sorted(item.attack_tactics)),
                    attack_techniques=tuple(sorted(item.attack_techniques)),
                    limitations=tuple(
                        _preview_text(value) for value in item.limitations
                    ),
                    lifecycle_state=item.lifecycle_state,
                    supersedes_finding_id=item.supersedes_finding_id,
                    superseded_by_finding_id=item.superseded_by_finding_id,
                    supersession_reason=(
                        _preview_text(item.supersession_reason)
                        if item.supersession_reason else None
                    ),
                    supersession_author=(
                        _preview_text(item.supersession_author)
                        if item.supersession_author else None
                    ),
                    superseded_at=item.superseded_at,
                )
                for item in sorted(
                    investigation.findings, key=lambda value: value.finding_id
                )
            ),
            response_action_count=len(investigation.response_actions),
            response_actions=tuple(HandoffResponseActionPreview(action_id=item.action_id, title=_preview_text(item.title), action_type=item.action_type, priority=item.priority, status=item.status, owner=_preview_text(item.owner), finding_ids=tuple(sorted(item.finding_ids)), transition_count=len(item.transition_history)) for item in sorted(investigation.response_actions, key=lambda value: value.action_id)),
            annotation_count=len(investigation.annotations),
            timed_entry_count=timed_entry_count,
            untimed_entry_count=untimed_entry_count,
            available_artifact_keys=available,
            required_artifacts_available=not missing_required,
            missing_required_artifact_keys=missing_required,
            missing_optional_artifact_keys=missing_optional,
            mode="full" if analysis is not None else "offline",
            source_analysis_available=analysis is not None,
        )

    def export(
        self,
        investigation_id: str,
        analysis: AnalysisResult | None,
        output_root: Path | str,
        *,
        overwrite: bool = False,
    ) -> HandoffResult:
        safe_id = _safe_segment(investigation_id, "Investigation ID")
        initial = self.repository.load_record(investigation_id)
        investigation = initial.investigation
        context = None
        if analysis is not None:
            try:
                context = InvestigationQueryContext(analysis, investigation)
            except Exception as exc:
                raise HandoffProvenanceMismatchError(
                    "The completed analysis does not match this investigation"
                ) from exc

        root = Path(output_root)
        if root.exists() and root.is_symlink():
            raise UnsafeHandoffOutputPathError("Handoff output root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True)
        resolved_root = root.resolve()
        target = (resolved_root / safe_id).resolve()
        if target.parent != resolved_root:
            raise UnsafeHandoffOutputPathError("Handoff target escapes the output root")
        if target.exists() and not overwrite:
            raise UnsafeHandoffOutputPathError("Handoff target already exists")

        analysis_before = deepcopy(analysis) if analysis is not None else None
        warnings: list[str] = []
        staging = Path(tempfile.mkdtemp(prefix=f".{safe_id}.", dir=resolved_root))
        try:
            self._write_bundle(
                staging,
                investigation,
                context,
                initial.revision,
                analysis,
                warnings,
            )
            source_hashes = (
                self._artifact_hashes(analysis) if analysis is not None else {}
            )
            if self.before_finalize is not None:
                self.before_finalize()
            final = self.repository.load_record(investigation_id)
            if final.revision != initial.revision or final.investigation != investigation:
                raise InvestigationChangedDuringHandoffError(
                    "Investigation changed while the handoff was being created"
                )
            if analysis is not None and (
                analysis != analysis_before
                or self._artifact_hashes(analysis) != source_hashes
            ):
                raise HandoffError(
                    "Source analysis changed while the handoff was being created"
                )
            validate_handoff_bundle(staging)
            self._publish(staging, target, overwrite=overwrite)
            manifest = _read_json(target / "manifest.json")
            files = tuple(HandoffFile(**item) for item in manifest["files"])
            return HandoffResult(
                handoff_id=manifest["handoff_id"],
                investigation_id=investigation_id,
                revision=initial.revision,
                output_path=target,
                manifest_path=target / "manifest.json",
                files=files,
                warnings=tuple(warnings),
                validation_status="valid",
            )
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise

    @staticmethod
    def _publish(staging: Path, target: Path, *, overwrite: bool) -> None:
        if not target.exists():
            os.replace(staging, target)
            return
        if not overwrite:
            raise UnsafeHandoffOutputPathError("Handoff target already exists")
        backup = target.parent / f".{target.name}.previous"
        if backup.exists():
            raise UnsafeHandoffOutputPathError("Handoff replacement backup already exists")
        os.replace(target, backup)
        try:
            os.replace(staging, target)
        except Exception:
            os.replace(backup, target)
            raise
        shutil.rmtree(backup)
    def _write_bundle(
        self,
        staging: Path,
        investigation: Investigation,
        context: InvestigationQueryContext | None,
        revision: int,
        analysis: AnalysisResult | None,
        warnings: list[str],
    ) -> None:
        selected_case_ids = sorted(
            item.source_id
            for item in investigation.evidence_references
            if item.origin == "scope" and item.source_type == "case"
        )
        if context is not None:
            timeline_payload = _serialize_timeline(context, self.timeline_service)
        else:
            timeline_payload = self._offline_timeline(investigation)
        limitations = list(timeline_payload["limitations"])
        components = {
            "investigation.json": {
                "investigation_id": investigation.investigation_id,
                "title": investigation.metadata.title,
                "owner": investigation.metadata.owner,
                "status": investigation.metadata.status,
                "created_at": investigation.metadata.created_at,
                "updated_at": investigation.metadata.updated_at,
                "source_analysis_id": investigation.analysis_id,
                "selected_case_ids": selected_case_ids,
                "revision": revision,
                "limitations": limitations,
            },
            "evidence_index.json": _serialize_evidence(investigation),
            "hypotheses.json": _serialize_hypotheses(investigation),
            "decisions.json": _serialize_decisions(investigation),
            "findings.json": _serialize_findings(investigation),
            "response_actions.json": _serialize_response_actions(investigation),
            "annotations.json": _serialize_annotations(investigation),
            "timeline.json": timeline_payload,
        }
        for filename, payload in components.items():
            _write_component(staging, filename, payload)

        if analysis is not None:
            artifact_files = self._copy_artifacts(staging, analysis, warnings)
        else:
            artifact_files = {}
            expected_keys = tuple(sorted(investigation.analysis_artifact_keys))
            warnings.append(
                "Source analysis is unavailable; analysis-derived timeline entries "
                "and source artifacts were not exported."
            )
            warnings.extend(
                f"Analysis artifact is unavailable offline: {key}"
                for key in expected_keys
            )
        limitations.extend(warnings)
        _write_component(
            staging,
            "limitations.json",
            {
                "sensitive_data_warning": SENSITIVE_DATA_WARNING,
                "automatic_redaction": False,
                "digital_signature": False,
                "limitations": sorted(set(limitations)),
            },
        )

        identity = _identity_payload(investigation, revision)
        handoff_id = f"HANDOFF-{_canonical_digest(identity)[:24]}"
        identity_manifest = HandoffManifest(
            manifest_id=handoff_id,
            investigation_id=investigation.investigation_id,
            evidence_reference_ids=tuple(
                sorted(item.reference_id for item in investigation.evidence_references)
            ),
            hypothesis_ids=tuple(
                sorted(item.hypothesis_id for item in investigation.hypotheses)
            ),
            decision_ids=tuple(sorted(item.decision_id for item in investigation.decisions)),
            annotation_ids=tuple(
                sorted(item.annotation_id for item in investigation.annotations)
            ),
            artifact_keys=tuple(sorted(
                analysis.artifacts
                if analysis is not None
                else investigation.analysis_artifact_keys
            )),
            created_at=investigation.metadata.updated_at,
        )
        inventory = self._inventory(staging, artifact_files)
        manifest = {
            "schema_version": HANDOFF_SCHEMA_VERSION,
            "handoff_id": handoff_id,
            "investigation_id": investigation.investigation_id,
            "source_analysis_id": investigation.analysis_id,
            "source_analysis_available": analysis is not None,
            "mode": "full" if analysis is not None else "offline",
            "provenance": {
                "algorithm": (
                    investigation.provenance.derivation_algorithm
                    if investigation.provenance is not None
                    else "sha256-canonical-json-v1"
                ),
                "version": "1",
            },
            "investigation_revision": revision,
            "created_at": investigation.metadata.updated_at,
            "owner": investigation.metadata.owner,
            "status": investigation.metadata.status,
            "selected_case_ids": selected_case_ids,
            "logical_artifact_references": sorted(
                analysis.artifacts
                if analysis is not None
                else investigation.analysis_artifact_keys
            ),
            "identity_manifest": identity_manifest.to_dict(),
            "files": [asdict(item) for item in inventory],
            "sensitive_data_warning": SENSITIVE_DATA_WARNING,
            "limitations": sorted(set(limitations)),
            "creation_tool": {"name": HANDOFF_TOOL, "version": __version__},
        }
        _write_component(staging, "manifest.json", manifest)

    def _copy_artifacts(
        self,
        staging: Path,
        analysis: AnalysisResult,
        warnings: list[str],
    ) -> Dict[str, str]:
        unknown = sorted(set(analysis.artifacts).difference(ARTIFACT_FILENAMES))
        if unknown:
            raise UnsafeHandoffArtifactPathError(
                f"Unsupported analysis artifact key: {unknown[0]}"
            )
        missing_required = sorted(
            key
            for key in REQUIRED_ARTIFACT_KEYS
            if key not in analysis.artifacts or not Path(analysis.artifacts[key]).is_file()
        )
        if missing_required:
            raise RequiredHandoffArtifactMissingError(
                f"Required analysis artifact is unavailable: {missing_required[0]}"
            )
        artifact_root = Path(analysis.output_dir).resolve()
        destination_root = staging / "source_artifacts"
        destination_root.mkdir()
        copied: Dict[str, str] = {}
        for key in sorted(analysis.artifacts):
            source = Path(analysis.artifacts[key])
            if not source.exists():
                warning = f"Optional analysis artifact is unavailable: {key}"
                warnings.append(warning)
                continue
            if source.is_symlink():
                raise UnsafeHandoffArtifactPathError(
                    f"Analysis artifact for {key} cannot be a symlink"
                )
            resolved = source.resolve()
            if not resolved.is_file() or not _inside(resolved, artifact_root):
                raise UnsafeHandoffArtifactPathError(
                    f"Analysis artifact for {key} is outside the approved artifact root"
                )
            filename = ARTIFACT_FILENAMES[key]
            destination = destination_root / filename
            shutil.copyfile(resolved, destination)
            if _digest_bytes(destination.read_bytes()) != _digest_bytes(resolved.read_bytes()):
                raise HandoffArtifactDigestMismatchError(
                    f"Copied analysis artifact failed integrity verification: {key}"
                )
            copied[f"source_artifacts/{filename}"] = f"artifact:{key}"
        return copied

    @staticmethod
    def _offline_timeline(investigation: Investigation) -> Dict[str, Any]:
        return {
            "investigation_id": investigation.investigation_id,
            "source_analysis_id": investigation.analysis_id,
            "timed_entries": [],
            "untimed_entries": [],
            "timeline_selections": [
                {
                    "selection_id": item.selection_id,
                    "evidence_reference_ids": sorted(item.evidence_reference_ids),
                    "start_time": item.start_time,
                    "end_time": item.end_time,
                }
                for item in sorted(
                    investigation.timeline_selections,
                    key=lambda value: value.selection_id,
                )
            ],
            "limitations": [
                "Source analysis is unavailable; analysis-derived timeline "
                "entries are not included."
            ],
        }

    @staticmethod
    def _offline_artifact_status(
        expected_keys: Tuple[str, ...],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
        unknown = sorted(set(expected_keys).difference(ARTIFACT_FILENAMES))
        if unknown:
            raise UnsafeHandoffArtifactPathError(
                f"Unsupported analysis artifact key: {unknown[0]}"
            )
        missing_required = tuple(
            sorted(set(expected_keys).intersection(REQUIRED_ARTIFACT_KEYS))
        )
        missing_optional = tuple(
            sorted(set(expected_keys).difference(REQUIRED_ARTIFACT_KEYS))
        )
        return (), missing_required, missing_optional

    @staticmethod
    def _artifact_status(
        analysis: AnalysisResult,
        expected_keys: Tuple[str, ...],
    ) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
        declared = set(analysis.artifacts)
        expected = declared | set(expected_keys)
        unknown = sorted(expected.difference(ARTIFACT_FILENAMES))
        if unknown:
            raise UnsafeHandoffArtifactPathError(
                f"Unsupported analysis artifact key: {unknown[0]}"
            )
        artifact_root = Path(analysis.output_dir).resolve()
        available = []
        missing = []
        for key in sorted(expected):
            source_value = analysis.artifacts.get(key)
            if source_value is None or not Path(source_value).exists():
                missing.append(key)
                continue
            source = Path(source_value)
            if source.is_symlink():
                raise UnsafeHandoffArtifactPathError(
                    f"Analysis artifact for {key} cannot be a symlink"
                )
            resolved = source.resolve()
            if not resolved.is_file() or not _inside(resolved, artifact_root):
                raise UnsafeHandoffArtifactPathError(
                    f"Analysis artifact for {key} is outside the approved artifact root"
                )
            available.append(key)
        missing_required = tuple(
            sorted(set(missing).intersection(REQUIRED_ARTIFACT_KEYS))
        )
        missing_optional = tuple(
            sorted(set(missing).difference(REQUIRED_ARTIFACT_KEYS))
        )
        return tuple(available), missing_required, missing_optional

    @staticmethod
    def _artifact_hashes(analysis: AnalysisResult) -> Dict[str, str | None]:
        return {
            key: _digest_bytes(Path(path).read_bytes()) if Path(path).is_file() else None
            for key, path in analysis.artifacts.items()
        }

    @staticmethod
    def _inventory(staging: Path, artifact_files: Mapping[str, str]) -> Tuple[HandoffFile, ...]:
        items = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            relative = path.relative_to(staging).as_posix()
            logical_type = artifact_files.get(relative, f"component:{path.stem}")
            data = path.read_bytes()
            items.append(HandoffFile(relative, logical_type, len(data), _digest_bytes(data)))
        return tuple(items)


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffBundleValidationError("Handoff bundle contains invalid JSON") from exc
    if not isinstance(payload, dict):
        raise HandoffBundleValidationError("Handoff component must be a JSON object")
    return payload


def _validate_references(bundle: Path, manifest: Mapping[str, Any]) -> None:
    investigation = _read_json(bundle / "investigation.json")
    evidence = _read_json(bundle / "evidence_index.json")
    hypotheses = _read_json(bundle / "hypotheses.json")
    decisions = _read_json(bundle / "decisions.json")
    timeline = _read_json(bundle / "timeline.json")
    if investigation.get("investigation_id") != manifest.get("investigation_id"):
        raise HandoffReferenceIntegrityError("Manifest investigation identity mismatch")
    if investigation.get("source_analysis_id") != manifest.get("source_analysis_id"):
        raise HandoffReferenceIntegrityError("Manifest analysis identity mismatch")
    evidence_ids = {
        item.get("evidence_id")
        for item in evidence.get("analyst_selected_evidence", [])
    }
    hypothesis_ids = {
        item.get("hypothesis_id") for item in hypotheses.get("hypotheses", [])
    }
    decision_ids = {item.get("decision_id") for item in decisions.get("decisions", [])}
    findings_path = bundle / "findings.json"
    finding_ids = set()
    if findings_path.is_file():
        findings = _read_json(findings_path).get("findings")
        if not isinstance(findings, list):
            raise HandoffBundleValidationError("Handoff findings component is invalid")
        finding_ids = set()
        parsed_findings = []
        lifecycle_fields = {"lifecycle_state", "supersedes_finding_id", "superseded_by_finding_id", "supersession_reason", "supersession_author", "superseded_at"}
        for payload in findings:
            if not isinstance(payload, Mapping):
                raise HandoffBundleValidationError("Handoff finding is invalid")
            try:
                finding = InvestigationFinding.from_dict(payload)
            except (KeyError, TypeError, ValueError) as exc:
                raise HandoffBundleValidationError("Handoff finding is invalid") from exc
            if manifest.get("schema_version") in {FINDING_LIFECYCLE_HANDOFF_SCHEMA_VERSION, HANDOFF_SCHEMA_VERSION} and not lifecycle_fields.issubset(payload):
                raise HandoffBundleValidationError("Handoff finding lifecycle metadata is missing")
            if finding.finding_id in finding_ids:
                raise HandoffBundleValidationError("Handoff finding IDs must be unique")
            finding_ids.add(finding.finding_id)
            parsed_findings.append(finding)
            if finding.investigation_id != manifest.get("investigation_id"):
                raise HandoffReferenceIntegrityError(
                    "Finding references a different investigation"
                )
            if not set(finding.evidence_ids).issubset(evidence_ids):
                raise HandoffReferenceIntegrityError(
                    "Finding references missing evidence"
                )
            if not set(finding.hypothesis_ids).issubset(hypothesis_ids):
                raise HandoffReferenceIntegrityError(
                    "Finding references missing hypothesis"
                )
            if not set(finding.decision_ids).issubset(decision_ids):
                raise HandoffReferenceIntegrityError(
                    "Finding references missing decision"
                )
        by_id = {item.finding_id: item for item in parsed_findings}
        for finding in parsed_findings:
            if finding.supersedes_finding_id is not None:
                prior = by_id.get(finding.supersedes_finding_id)
                if prior is None or prior.superseded_by_finding_id != finding.finding_id:
                    raise HandoffReferenceIntegrityError("Finding supersession reference is inconsistent")
            if finding.superseded_by_finding_id is not None:
                replacement = by_id.get(finding.superseded_by_finding_id)
                if replacement is None or replacement.supersedes_finding_id != finding.finding_id:
                    raise HandoffReferenceIntegrityError("Finding supersession reference is inconsistent")
        for origin in parsed_findings:
            seen = set()
            current = origin
            while current.superseded_by_finding_id is not None:
                if current.finding_id in seen:
                    raise HandoffReferenceIntegrityError("Finding supersession graph contains a cycle")
                seen.add(current.finding_id)
                current = by_id[current.superseded_by_finding_id]
    actions_path = bundle / "response_actions.json"
    if actions_path.is_file():
        actions = _read_json(actions_path).get("response_actions")
        if not isinstance(actions, list): raise HandoffBundleValidationError("Handoff Response Actions component is invalid")
        action_ids = set()
        for payload in actions:
            if not isinstance(payload, Mapping): raise HandoffBundleValidationError("Handoff Response Action is invalid")
            try: action = ResponseAction.from_dict(payload)
            except (KeyError, TypeError, ValueError) as exc: raise HandoffBundleValidationError("Handoff Response Action is invalid") from exc
            timestamps = [item.timestamp for item in action.transition_history]
            if timestamps != sorted(timestamps):
                raise HandoffBundleValidationError(
                    "Handoff Response Action transition history is not ordered"
                )
            if action.action_id in action_ids: raise HandoffBundleValidationError("Handoff Response Action IDs must be unique")
            action_ids.add(action.action_id)
            if action.investigation_id != manifest.get("investigation_id"): raise HandoffReferenceIntegrityError("Response Action references a different investigation")
            if not set(action.finding_ids).issubset(finding_ids): raise HandoffReferenceIntegrityError("Response Action references missing Finding")
    for hypothesis in hypotheses.get("hypotheses", []):
        linked = set(hypothesis.get("supporting_evidence_ids", ())) | set(
            hypothesis.get("contradicting_evidence_ids", ())
        )
        if not linked.issubset(evidence_ids):
            raise HandoffReferenceIntegrityError("Hypothesis references missing evidence")
        if not set(hypothesis.get("assessment_history_ids", ())).issubset(decision_ids):
            raise HandoffReferenceIntegrityError("Hypothesis assessment reference is missing")
    for decision in decisions.get("decisions", []):
        if not set(decision.get("related_evidence_ids", ())).issubset(evidence_ids):
            raise HandoffReferenceIntegrityError("Decision references missing evidence")
        if not set(decision.get("related_hypothesis_ids", ())).issubset(hypothesis_ids):
            raise HandoffReferenceIntegrityError("Decision references missing hypothesis")
    for entry in timeline.get("timed_entries", []) + timeline.get("untimed_entries", []):
        if not set(entry.get("related_hypothesis_ids", ())).issubset(hypothesis_ids):
            raise HandoffReferenceIntegrityError("Timeline references missing hypothesis")
        if not set(entry.get("related_decision_ids", ())).issubset(decision_ids):
            raise HandoffReferenceIntegrityError("Timeline references missing decision")


def validate_handoff_bundle(path: Path | str) -> bool:
    bundle = Path(path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise HandoffBundleValidationError("Handoff bundle is unavailable")
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise HandoffBundleValidationError("Handoff manifest is missing")
    manifest = _read_json(manifest_path)
    schema_version = manifest.get("schema_version")
    if schema_version not in SUPPORTED_HANDOFF_SCHEMA_VERSIONS:
        raise UnsupportedHandoffSchemaError("Unsupported handoff schema version")
    if schema_version == HANDOFF_SCHEMA_VERSION:
        mode = manifest.get("mode")
        source_available = manifest.get("source_analysis_available")
        if mode not in {"full", "offline"} or not isinstance(
            source_available, bool
        ):
            raise HandoffBundleValidationError(
                "Handoff source-analysis availability metadata is invalid"
            )
        if source_available != (mode == "full"):
            raise HandoffBundleValidationError(
                "Handoff source-analysis availability metadata is inconsistent"
            )
    inventory = manifest.get("files")
    if not isinstance(inventory, list):
        raise HandoffBundleValidationError("Handoff file inventory is invalid")
    expected = set(
        CURRENT_REQUIRED_COMPONENTS
        if schema_version == HANDOFF_SCHEMA_VERSION
        else REQUIRED_COMPONENTS
        if schema_version != LEGACY_HANDOFF_SCHEMA_VERSION
        else LEGACY_REQUIRED_COMPONENTS
    )
    inventory_names = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise HandoffBundleValidationError("Handoff file inventory is invalid")
        filename = item.get("filename")
        if not isinstance(filename, str):
            raise HandoffBundleValidationError("Handoff file inventory is invalid")
        if (
            filename == "findings.json"
            and item.get("logical_type") != "component:findings"
        ):
            raise HandoffBundleValidationError(
                "Handoff findings logical type is invalid"
            )
        if filename == "response_actions.json" and item.get("logical_type") != "component:response_actions":
            raise HandoffBundleValidationError("Handoff Response Actions logical type is invalid")
        relative = Path(filename)
        if relative.is_absolute() or ".." in relative.parts or "\\" in filename:
            raise HandoffBundleValidationError("Handoff inventory path is unsafe")
        resolved = (bundle / relative).resolve()
        if not _inside(resolved, bundle.resolve()) or resolved.is_symlink():
            raise HandoffBundleValidationError("Handoff inventory path is unsafe")
        if not resolved.is_file():
            raise HandoffBundleValidationError("Handoff inventory file is missing")
        data = resolved.read_bytes()
        if len(data) != item.get("size") or _digest_bytes(data) != item.get("sha256"):
            raise HandoffArtifactDigestMismatchError("Handoff file digest mismatch")
        inventory_names.add(relative.as_posix())
    if not expected.issubset(inventory_names):
        raise HandoffBundleValidationError("Handoff required component is missing")
    actual = {
        item.relative_to(bundle).as_posix()
        for item in bundle.rglob("*")
        if item.is_file() and item.name != "manifest.json"
    }
    if actual != inventory_names:
        raise HandoffBundleValidationError("Handoff contains unexpected files")
    _validate_references(bundle, manifest)
    return True

def read_handoff_manifest(path: Path | str) -> HandoffManifestSummary:
    bundle = Path(path)
    validate_handoff_bundle(bundle)
    manifest = _read_json(bundle / "manifest.json")
    try:
        return HandoffManifestSummary(
            schema_version=str(manifest["schema_version"]),
            handoff_id=str(manifest["handoff_id"]),
            investigation_id=str(manifest["investigation_id"]),
            source_analysis_id=str(manifest["source_analysis_id"]),
            revision=int(manifest["investigation_revision"]),
            owner=manifest.get("owner"),
            status=str(manifest["status"]),
            selected_case_ids=tuple(manifest.get("selected_case_ids", ())),
            files=tuple(HandoffFile(**item) for item in manifest["files"]),
            limitations=tuple(manifest.get("limitations", ())),
            sensitive_data_warning=str(manifest["sensitive_data_warning"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HandoffBundleValidationError(
            "Handoff manifest summary is invalid"
        ) from exc
