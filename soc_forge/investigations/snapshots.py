from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

from soc_forge import __version__
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.pipeline import AnalysisResult


SNAPSHOT_SCHEMA_VERSION = "1.0"
SNAPSHOT_DIRECTORY = "analysis_snapshots"
SENSITIVE_DATA_WARNING = (
    "Completed analysis snapshots may contain sensitive security telemetry. "
    "Keep them local and review before sharing."
)
SOURCE_ANALYSIS_ID_PATTERN = re.compile(r"analysis-[0-9a-f]{20}")
COLLECTION_FILES = {
    "events": "events.json",
    "alerts": "alerts.json",
    "cases": "cases.json",
    "hunts": "hunts.json",
    "reconstructions": "reconstructions.json",
}
ARTIFACT_FILENAMES = {
    "alerts": "alerts.json",
    "cases": "cases.json",
    "events": "events.json",
    "hunts": "hunts.json",
    "reconstructions": "reconstructions.json",
    "report": "report.html",
}


class CompletedAnalysisSnapshotError(Exception):
    """Base error for local completed-analysis snapshots."""


class InvalidSnapshotIdError(CompletedAnalysisSnapshotError):
    pass


class SnapshotNotFoundError(CompletedAnalysisSnapshotError):
    pass


class SnapshotConflictError(CompletedAnalysisSnapshotError):
    pass


class SnapshotValidationError(CompletedAnalysisSnapshotError):
    pass


class UnsupportedSnapshotSchemaError(SnapshotValidationError):
    pass


class SnapshotIntegrityError(SnapshotValidationError):
    pass


class SnapshotProvenanceMismatchError(SnapshotValidationError):
    pass


@dataclass(frozen=True)
class CompletedAnalysisSnapshot:
    source_analysis_id: str
    path: Path
    manifest_path: Path
    created: bool


def _json_value(value: Any) -> Any:
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise SnapshotValidationError(
        f"Analysis field contains unsupported {type(value).__name__} content"
    )


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(_json_value(value), indent=2, sort_keys=True, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


class CompletedAnalysisSnapshotStore:
    def __init__(self, analysis_output_root: Path | str):
        self.analysis_output_root = Path(analysis_output_root)
        self.root = self.analysis_output_root / SNAPSHOT_DIRECTORY

    def publish(self, result: AnalysisResult) -> CompletedAnalysisSnapshot:
        source_analysis_id = AnalysisEvidenceCatalog().source_analysis_id(result)
        self._validate_id(source_analysis_id)
        self._prepare_root()
        target = self.root / source_analysis_id
        if target.is_symlink():
            raise SnapshotConflictError("Snapshot target cannot be a symlink")

        staging = Path(tempfile.mkdtemp(prefix=f".{source_analysis_id}.", dir=self.root))
        try:
            self._write_snapshot(staging, result, source_analysis_id)
            self._load_from_directory(staging, source_analysis_id)
            if target.exists():
                self._validate_existing_equivalence(staging, target, source_analysis_id)
                return CompletedAnalysisSnapshot(
                    source_analysis_id, target, target / "manifest.json", False
                )
            os.replace(staging, target)
            return CompletedAnalysisSnapshot(
                source_analysis_id, target, target / "manifest.json", True
            )
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def load(self, source_analysis_id: str) -> AnalysisResult:
        self._validate_id(source_analysis_id)
        self._reject_symlink_components(self.analysis_output_root)
        self._reject_symlink_components(self.root)
        target = self.root / source_analysis_id
        if not target.exists():
            raise SnapshotNotFoundError("Completed analysis snapshot was not found")
        if target.is_symlink() or not target.is_dir():
            raise SnapshotValidationError("Completed analysis snapshot is not a safe directory")
        return self._load_from_directory(target, source_analysis_id)

    def _write_snapshot(
        self,
        directory: Path,
        result: AnalysisResult,
        source_analysis_id: str,
    ) -> None:
        payloads = {
            "events.json": result.events,
            "alerts.json": result.alerts,
            "cases.json": result.cases,
            "hunts.json": result.hunt_findings,
            "reconstructions.json": result.reconstructions,
            "analysis.json": {
                "input_name": result.input_name,
                "event_count": result.event_count,
                "legacy_alerts": result.legacy_alerts,
                "yaml_alerts": result.yaml_alerts,
                "correlations": result.correlations,
                "risk_summary": result.risk_summary,
                "mitre_coverage": result.mitre_coverage,
                "ingest_diagnostics": result.ingest_diagnostics,
            },
        }
        for filename, payload in payloads.items():
            (directory / filename).write_bytes(_json_bytes(payload))

        artifact_root = directory / "artifacts"
        artifact_root.mkdir()
        artifact_index: dict[str, str] = {}
        unknown = sorted(set(result.artifacts).difference(ARTIFACT_FILENAMES))
        if unknown:
            raise SnapshotValidationError(
                f"Unsupported logical artifact key: {unknown[0]}"
            )
        approved_root = Path(result.output_dir).resolve()
        for key in sorted(result.artifacts):
            source = Path(result.artifacts[key])
            if source.is_symlink():
                raise SnapshotValidationError("Source analysis artifact cannot be a symlink")
            resolved = source.resolve()
            if not resolved.is_file() or not _inside(resolved, approved_root):
                raise SnapshotValidationError(
                    "Source analysis artifact is outside the approved output root"
                )
            relative = Path("artifacts") / ARTIFACT_FILENAMES[key]
            destination = directory / relative
            shutil.copyfile(resolved, destination)
            artifact_index[key] = relative.as_posix()
        (directory / "artifact_index.json").write_bytes(_json_bytes(artifact_index))

        inventory = []
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                inventory.append(
                    {
                        "filename": path.relative_to(directory).as_posix(),
                        "size": len(data),
                        "sha256": _digest(data),
                    }
                )
        provenance = AnalysisEvidenceCatalog().analysis_provenance(result)
        manifest = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "source_analysis_id": source_analysis_id,
            "provenance_algorithm": provenance.derivation_algorithm,
            "normalized_input_name": provenance.normalized_input_name,
            "event_count": len(result.events),
            "alert_count": len(result.alerts),
            "case_count": len(result.cases),
            "hunt_count": len(result.hunt_findings),
            "reconstruction_count": len(result.reconstructions),
            "observed_rule_ids": sorted(
                {
                    str(alert.get("rule_id") or "").strip()
                    for alert in result.alerts
                    if isinstance(alert, Mapping)
                    and str(alert.get("rule_id") or "").strip()
                }
            ),
            "logical_artifact_keys": sorted(result.artifacts),
            "files": inventory,
            "soc_forge_version": __version__,
            "sensitive_data_warning": SENSITIVE_DATA_WARNING,
            "cryptographic_authenticity": False,
        }
        (directory / "manifest.json").write_bytes(_json_bytes(manifest))

    def _load_from_directory(
        self, directory: Path, expected_source_analysis_id: str
    ) -> AnalysisResult:
        manifest = self._read_json(directory / "manifest.json")
        if manifest.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
            raise UnsupportedSnapshotSchemaError("Unsupported snapshot schema version")
        if manifest.get("source_analysis_id") != expected_source_analysis_id:
            raise SnapshotProvenanceMismatchError("Snapshot source analysis ID does not match")
        self._validate_inventory(directory, manifest)

        events = self._read_list(directory / "events.json")
        alerts = self._read_list(directory / "alerts.json")
        cases = self._read_list(directory / "cases.json")
        hunts = self._read_list(directory / "hunts.json")
        reconstructions = self._read_list(directory / "reconstructions.json")
        metadata = self._read_json(directory / "analysis.json")
        artifact_index = self._read_json(directory / "artifact_index.json")
        if not isinstance(artifact_index, dict):
            raise SnapshotValidationError("Snapshot artifact index must be an object")
        artifacts: dict[str, Path] = {}
        for key, relative_text in artifact_index.items():
            if key not in ARTIFACT_FILENAMES or not isinstance(relative_text, str):
                raise SnapshotValidationError("Snapshot artifact index is invalid")
            relative = Path(relative_text)
            path = (directory / relative).resolve()
            if relative.is_absolute() or ".." in relative.parts or not _inside(
                path, directory.resolve()
            ):
                raise SnapshotValidationError("Snapshot artifact path is unsafe")
            if not path.is_file() or path.is_symlink():
                raise SnapshotValidationError("Snapshot artifact is unavailable")
            artifacts[key] = path
        expected_keys = manifest.get("logical_artifact_keys")
        if not isinstance(expected_keys, list) or sorted(artifacts) != sorted(expected_keys):
            raise SnapshotValidationError("Snapshot artifact-key set does not match")

        counts = {
            "event_count": len(events),
            "alert_count": len(alerts),
            "case_count": len(cases),
            "hunt_count": len(hunts),
            "reconstruction_count": len(reconstructions),
        }
        for field, actual in counts.items():
            if manifest.get(field) != actual:
                raise SnapshotValidationError("Snapshot collection count does not match")
        if metadata.get("event_count") != len(events):
            raise SnapshotValidationError("Snapshot analysis event count does not match")

        result = AnalysisResult(
            input_name=str(metadata.get("input_name") or ""),
            input_path=None,
            output_dir=directory,
            alerts_path=artifacts.get("alerts"),
            report_path=artifacts.get("report"),
            cases_output_dir=directory if "cases" in artifacts else None,
            hunts_path=artifacts.get("hunts"),
            reconstructions_path=artifacts.get("reconstructions"),
            events_path=artifacts.get("events"),
            event_count=len(events),
            events=events,
            alerts=alerts,
            legacy_alerts=list(metadata.get("legacy_alerts") or []),
            yaml_alerts=list(metadata.get("yaml_alerts") or []),
            correlations=dict(metadata.get("correlations") or {}),
            hunt_findings=hunts,
            risk_summary=dict(metadata.get("risk_summary") or {}),
            cases=cases,
            reconstructions=reconstructions,
            mitre_coverage=[tuple(item) for item in metadata.get("mitre_coverage") or []],
            artifacts=artifacts,
            ingest_diagnostics=list(metadata.get("ingest_diagnostics") or []),
        )
        actual_source_analysis_id = AnalysisEvidenceCatalog().source_analysis_id(result)
        if actual_source_analysis_id != expected_source_analysis_id:
            raise SnapshotProvenanceMismatchError(
                "Snapshot contents do not reproduce the source analysis ID"
            )
        expected_rule_ids = sorted(manifest.get("observed_rule_ids") or [])
        actual_rule_ids = sorted(
            {
                str(alert.get("rule_id") or "").strip()
                for alert in alerts
                if isinstance(alert, Mapping)
                and str(alert.get("rule_id") or "").strip()
            }
        )
        if actual_rule_ids != expected_rule_ids:
            raise SnapshotValidationError("Snapshot observed rule IDs do not match")
        return result

    def _validate_inventory(self, directory: Path, manifest: Mapping[str, Any]) -> None:
        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            raise SnapshotValidationError("Snapshot file inventory is missing")
        seen = set()
        for item in files:
            if not isinstance(item, Mapping):
                raise SnapshotValidationError("Snapshot file inventory is invalid")
            filename = item.get("filename")
            if not isinstance(filename, str) or filename in seen:
                raise SnapshotValidationError("Snapshot file inventory is invalid")
            relative = Path(filename)
            path = (directory / relative).resolve()
            if relative.is_absolute() or ".." in relative.parts or not _inside(
                path, directory.resolve()
            ):
                raise SnapshotValidationError("Snapshot inventory path is unsafe")
            if not path.is_file() or path.is_symlink():
                raise SnapshotIntegrityError("Snapshot file is missing")
            data = path.read_bytes()
            if item.get("size") != len(data) or item.get("sha256") != _digest(data):
                raise SnapshotIntegrityError("Snapshot file integrity check failed")
            seen.add(filename)
        required = {
            "analysis.json",
            "artifact_index.json",
            *COLLECTION_FILES.values(),
        }
        if not required.issubset(seen):
            raise SnapshotValidationError("Snapshot required file inventory is incomplete")
        actual = {
            path.relative_to(directory).as_posix()
            for path in directory.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        }
        if actual != seen:
            raise SnapshotValidationError("Snapshot contains an unlisted or missing file")

    def _validate_existing_equivalence(
        self, staged: Path, target: Path, source_analysis_id: str
    ) -> None:
        self._load_from_directory(target, source_analysis_id)
        staged_files = {
            path.relative_to(staged).as_posix(): path.read_bytes()
            for path in staged.rglob("*")
            if path.is_file()
        }
        target_files = {
            path.relative_to(target).as_posix(): path.read_bytes()
            for path in target.rglob("*")
            if path.is_file()
        }
        if staged_files != target_files:
            raise SnapshotConflictError(
                "Existing immutable snapshot differs from the completed analysis"
            )

    def _prepare_root(self) -> None:
        self._reject_symlink_components(self.analysis_output_root)
        self.analysis_output_root.mkdir(parents=True, exist_ok=True)
        self._reject_symlink_components(self.root)
        self.root.mkdir(exist_ok=True)

    @staticmethod
    def _reject_symlink_components(path: Path) -> None:
        absolute = path.absolute()
        for component in (absolute, *absolute.parents):
            if component.exists() and component.is_symlink():
                raise SnapshotValidationError(
                    "Snapshot storage path cannot contain symlinks"
                )

    @staticmethod
    def _validate_id(source_analysis_id: str) -> None:
        if not isinstance(source_analysis_id, str) or not SOURCE_ANALYSIS_ID_PATTERN.fullmatch(
            source_analysis_id
        ):
            raise InvalidSnapshotIdError("Snapshot ID must be a source analysis ID")

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotValidationError("Snapshot JSON could not be read") from exc
        if not isinstance(value, dict):
            raise SnapshotValidationError("Snapshot JSON object is required")
        return value

    @classmethod
    def _read_list(cls, path: Path) -> list[Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SnapshotValidationError("Snapshot collection could not be read") from exc
        if not isinstance(value, list):
            raise SnapshotValidationError("Snapshot collection must be a list")
        return value
