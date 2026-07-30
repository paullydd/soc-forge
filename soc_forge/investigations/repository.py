from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
from typing import Any, List, Mapping

from soc_forge.investigations.models import Investigation


REPOSITORY_SCHEMA_VERSION = "1.0"
INVESTIGATIONS_DIRECTORY = "investigations"


class InvestigationRepositoryError(Exception):
    """Base error for local investigation persistence."""


class InvalidInvestigationIdError(InvestigationRepositoryError):
    pass


class InvestigationNotFoundError(InvestigationRepositoryError):
    pass


class InvestigationAlreadyExistsError(InvestigationRepositoryError):
    pass


class InvestigationConflictError(InvestigationRepositoryError):
    pass


class CorruptInvestigationRecordError(InvestigationRepositoryError):
    pass


@dataclass(frozen=True)
class StoredInvestigation:
    investigation: Investigation
    revision: int


@dataclass(frozen=True)
class InvestigationSummary:
    investigation_id: str
    title: str
    owner: str | None
    created_at: str
    updated_at: str
    revision: int


class InvestigationRepository:
    def __init__(self, storage_root: Path | str):
        self.storage_root = Path(storage_root)
        self.investigations_root = self.storage_root / INVESTIGATIONS_DIRECTORY

    def save(
        self,
        investigation: Investigation,
        *,
        expected_revision: int | None = None,
    ) -> int:
        record_path = self._record_path(investigation.investigation_id)
        current_revision = self._current_revision(record_path)

        if current_revision is None:
            if expected_revision is not None:
                raise InvestigationConflictError(
                    f"Investigation {investigation.investigation_id!r} does not exist "
                    f"at expected revision {expected_revision}"
                )
            next_revision = 1
        else:
            if expected_revision is None:
                raise InvestigationAlreadyExistsError(
                    f"Investigation {investigation.investigation_id!r} already exists"
                )
            if expected_revision != current_revision:
                raise InvestigationConflictError(
                    f"Investigation {investigation.investigation_id!r} is at revision "
                    f"{current_revision}, not expected revision {expected_revision}"
                )
            next_revision = current_revision + 1

        envelope = {
            "repository_schema_version": REPOSITORY_SCHEMA_VERSION,
            "revision": next_revision,
            "investigation": investigation.to_dict(),
        }
        serialized = json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        self.investigations_root.mkdir(parents=True, exist_ok=True)
        self._atomic_write(record_path, serialized)
        return next_revision

    def load(self, investigation_id: str) -> Investigation:
        return self.load_record(investigation_id).investigation

    def load_record(self, investigation_id: str) -> StoredInvestigation:
        record_path = self._record_path(investigation_id)
        if not record_path.is_file():
            raise InvestigationNotFoundError(
                f"Investigation {investigation_id!r} was not found"
            )
        return self._read_record(record_path, expected_id=investigation_id)

    def exists(self, investigation_id: str) -> bool:
        return self._record_path(investigation_id).is_file()

    def list_investigations(self) -> List[InvestigationSummary]:
        if not self.investigations_root.is_dir():
            return []

        summaries = []
        for record_path in self.investigations_root.glob("*.json"):
            safe_record_path = self._record_path(record_path.stem)
            stored = self._read_record(safe_record_path, expected_id=record_path.stem)
            investigation = stored.investigation
            summaries.append(
                InvestigationSummary(
                    investigation_id=investigation.investigation_id,
                    title=investigation.metadata.title,
                    owner=investigation.metadata.owner,
                    created_at=investigation.metadata.created_at,
                    updated_at=investigation.metadata.updated_at,
                    revision=stored.revision,
                )
            )

        summaries.sort(key=lambda summary: summary.investigation_id)
        summaries.sort(key=lambda summary: summary.updated_at, reverse=True)
        return summaries

    def delete(self, investigation_id: str) -> None:
        record_path = self._record_path(investigation_id)
        if not record_path.is_file():
            raise InvestigationNotFoundError(
                f"Investigation {investigation_id!r} was not found"
            )
        record_path.unlink()

    def _record_path(self, investigation_id: str) -> Path:
        self._validate_investigation_id(investigation_id)
        base = self.investigations_root.resolve()
        candidate = (self.investigations_root / f"{investigation_id}.json").resolve()
        if candidate.parent != base:
            raise InvalidInvestigationIdError(
                f"Investigation ID {investigation_id!r} escapes the repository root"
            )
        return candidate

    @staticmethod
    def _validate_investigation_id(investigation_id: str) -> None:
        if not isinstance(investigation_id, str) or not investigation_id.strip():
            raise InvalidInvestigationIdError("Investigation ID must be a non-empty string")
        if (
            Path(investigation_id).is_absolute()
            or ".." in investigation_id
            or "/" in investigation_id
            or "\\" in investigation_id
            or "\x00" in investigation_id
        ):
            raise InvalidInvestigationIdError(
                f"Investigation ID {investigation_id!r} is not a safe record identifier"
            )

    def _current_revision(self, record_path: Path) -> int | None:
        if not record_path.is_file():
            return None
        return self._read_record(record_path, expected_id=record_path.stem).revision

    def _read_record(self, record_path: Path, *, expected_id: str) -> StoredInvestigation:
        try:
            payload = json.loads(record_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("record must be a JSON object")
            self._validate_envelope(payload)
            investigation_payload = payload["investigation"]
            if not isinstance(investigation_payload, dict):
                raise ValueError("investigation must be a JSON object")
            investigation = Investigation.from_dict(investigation_payload)
            if investigation.investigation_id != expected_id:
                raise ValueError(
                    "stored investigation ID does not match the record filename"
                )
            return StoredInvestigation(
                investigation=investigation,
                revision=payload["revision"],
            )
        except CorruptInvestigationRecordError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise CorruptInvestigationRecordError(
                f"Investigation record {expected_id!r} is corrupt: {exc}"
            ) from exc

    @staticmethod
    def _validate_envelope(payload: Mapping[str, Any]) -> None:
        if payload.get("repository_schema_version") != REPOSITORY_SCHEMA_VERSION:
            raise ValueError("unsupported repository schema version")
        revision = payload.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("revision must be a positive integer")
        if "investigation" not in payload:
            raise ValueError("record is missing investigation")

    @staticmethod
    def _atomic_write(record_path: Path, serialized: str) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=record_path.parent,
                prefix=f".{record_path.stem}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                temporary_file.write(serialized)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, record_path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
