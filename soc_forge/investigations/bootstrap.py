from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Callable, Dict, Iterable, Mapping, Tuple

from soc_forge.pipeline import AnalysisResult
from soc_forge.investigations.models import AnalysisProvenance
from soc_forge.investigations.provenance import (
    ProvenanceDerivationError,
    derive_analysis_provenance,
)
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceResult,
)


REQUIRED_ARTIFACT_KEY = "cases"


class InvestigationBootstrapError(Exception):
    """Base error for completed-analysis bootstrap validation."""


class InvalidAnalysisResultError(InvestigationBootstrapError):
    pass


class NoCasesSelectedError(InvestigationBootstrapError):
    pass


class UnknownCaseIdError(InvestigationBootstrapError):
    pass


class MissingArtifactReferenceError(InvestigationBootstrapError):
    pass


class InvalidBootstrapTitleError(InvestigationBootstrapError):
    pass


@dataclass(frozen=True)
class InvestigationBootstrap:
    investigation_id: str
    title: str
    analysis_id: str
    provenance: AnalysisProvenance
    bootstrap_id: str
    case_ids: Tuple[str, ...]
    artifact_keys: Tuple[str, ...]
    source_input_name: str
    owner: str | None
    initial_status: str
    created_at: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvestigationBootstrapAdapter:
    def __init__(
        self,
        workspace_service: InvestigationWorkspaceService,
        *,
        clock: Callable[[], str] = _utc_now,
    ):
        self.workspace_service = workspace_service
        self.clock = clock

    def build_creation_request(
        self,
        analysis_result: AnalysisResult,
        investigation_id: str,
        case_ids: Iterable[str],
        *,
        title: str | None = None,
        owner: str | None = None,
        initial_status: str = "open",
        created_at: str | None = None,
    ) -> InvestigationBootstrap:
        case_map = self._case_map(analysis_result)
        selected_case_ids = self._selected_case_ids(case_ids, case_map)
        artifact_keys = self._artifact_keys(analysis_result.artifacts)
        if REQUIRED_ARTIFACT_KEY not in artifact_keys:
            raise MissingArtifactReferenceError(
                f"Completed analysis is missing required artifact key "
                f"{REQUIRED_ARTIFACT_KEY!r}"
            )

        source_input_name = self._source_input_name(analysis_result.input_name)
        try:
            provenance = derive_analysis_provenance(
                normalized_input_name=source_input_name,
                events=analysis_result.events,
                alerts=analysis_result.alerts,
                cases=analysis_result.cases,
                reconstructions=analysis_result.reconstructions,
                artifact_keys=artifact_keys,
            )
        except ProvenanceDerivationError as exc:
            raise InvalidAnalysisResultError(str(exc)) from exc
        analysis_id = provenance.source_analysis_id
        bootstrap_id = self._bootstrap_id(analysis_id, selected_case_ids)
        resolved_title = (
            self._validated_title(title)
            if title is not None
            else self._default_title(selected_case_ids, case_map)
        )
        timestamp = self._required_text(
            created_at if created_at is not None else self.clock(),
            "created_at",
        )

        return InvestigationBootstrap(
            investigation_id=self._required_text(
                investigation_id,
                "investigation_id",
            ),
            title=resolved_title,
            analysis_id=analysis_id,
            provenance=provenance,
            bootstrap_id=bootstrap_id,
            case_ids=selected_case_ids,
            artifact_keys=artifact_keys,
            source_input_name=source_input_name,
            owner=owner,
            initial_status=initial_status,
            created_at=timestamp,
        )

    def bootstrap_investigation(
        self,
        analysis_result: AnalysisResult,
        investigation_id: str,
        case_ids: Iterable[str],
        *,
        title: str | None = None,
        owner: str | None = None,
        initial_status: str = "open",
        created_at: str | None = None,
    ) -> WorkspaceResult:
        request = self.build_creation_request(
            analysis_result,
            investigation_id,
            case_ids,
            title=title,
            owner=owner,
            initial_status=initial_status,
            created_at=created_at,
        )
        return self.workspace_service.create_investigation(
            investigation_id=request.investigation_id,
            title=request.title,
            analysis_id=request.analysis_id,
            provenance=request.provenance,
            case_ids=request.case_ids,
            artifact_keys=request.artifact_keys,
            owner=request.owner,
            initial_status=request.initial_status,
            created_at=request.created_at,
        )

    @staticmethod
    def _case_map(analysis_result: AnalysisResult) -> Dict[str, Mapping]:
        if not isinstance(analysis_result, AnalysisResult):
            raise InvalidAnalysisResultError(
                "Bootstrap requires one completed AnalysisResult"
            )
        if (
            not isinstance(analysis_result.event_count, int)
            or isinstance(analysis_result.event_count, bool)
            or analysis_result.event_count < 0
        ):
            raise InvalidAnalysisResultError(
                "Completed analysis has an invalid event_count"
            )
        if not isinstance(analysis_result.cases, list):
            raise InvalidAnalysisResultError(
                "Completed analysis cases must be a list"
            )

        case_map: Dict[str, Mapping] = {}
        for case in analysis_result.cases:
            if not isinstance(case, Mapping):
                raise InvalidAnalysisResultError(
                    "Completed analysis contains a non-object case"
                )
            case_id = case.get("case_id") or case.get("id")
            if not isinstance(case_id, str) or not case_id.strip():
                raise InvalidAnalysisResultError(
                    "Completed analysis contains a case without a stable case ID"
                )
            normalized_id = case_id.strip()
            if normalized_id in case_map:
                raise InvalidAnalysisResultError(
                    f"Completed analysis contains duplicate case ID {normalized_id!r}"
                )
            case_map[normalized_id] = case
        return case_map

    @classmethod
    def _selected_case_ids(
        cls,
        case_ids: Iterable[str],
        case_map: Mapping[str, Mapping],
    ) -> Tuple[str, ...]:
        if isinstance(case_ids, (str, bytes)):
            raise NoCasesSelectedError(
                "case_ids must be an iterable of case identifiers"
            )
        selected = set()
        for case_id in case_ids:
            selected.add(cls._required_text(case_id, "case ID"))
        if not selected:
            raise NoCasesSelectedError(
                "At least one case ID must be selected explicitly"
            )
        unknown = sorted(selected.difference(case_map))
        if unknown:
            raise UnknownCaseIdError(
                "Selected case ID(s) were not found: " + ", ".join(unknown)
            )
        return tuple(sorted(selected))

    @classmethod
    def _artifact_keys(cls, artifacts: Mapping) -> Tuple[str, ...]:
        if not isinstance(artifacts, Mapping):
            raise InvalidAnalysisResultError(
                "Completed analysis artifacts must be a mapping"
            )
        keys = []
        for key, value in artifacts.items():
            normalized_key = cls._required_text(key, "artifact key")
            if value is not None:
                keys.append(normalized_key)
        return tuple(sorted(set(keys)))

    @classmethod
    def _default_title(
        cls,
        selected_case_ids: Tuple[str, ...],
        case_map: Mapping[str, Mapping],
    ) -> str:
        first_title = cls._case_title(case_map[selected_case_ids[0]])
        if len(selected_case_ids) == 1:
            return first_title
        return f"{first_title} and {len(selected_case_ids) - 1} related case(s)"

    @classmethod
    def _case_title(cls, case: Mapping) -> str:
        header = case.get("header")
        header_title = header.get("title") if isinstance(header, Mapping) else None
        value = case.get("title") or header_title
        if not isinstance(value, str) or not value.strip():
            raise InvalidBootstrapTitleError(
                "Selected case does not provide a usable title"
            )
        return cls._validated_title(value)

    @classmethod
    def _validated_title(cls, value: str) -> str:
        title = cls._required_text(value, "title")
        if "\n" in title or "\r" in title:
            raise InvalidBootstrapTitleError(
                "Investigation title must be a single line"
            )
        return title

    @classmethod
    def _source_input_name(cls, input_name: str) -> str:
        normalized = cls._required_text(input_name, "analysis input_name")
        return normalized.replace("\\", "/").rsplit("/", 1)[-1]

    @staticmethod
    def _bootstrap_id(
        analysis_id: str,
        selected_case_ids: Tuple[str, ...],
    ) -> str:
        manifest = {
            "analysis_id": analysis_id,
            "selected_case_ids": selected_case_ids,
        }
        digest = sha256(
            json.dumps(
                manifest,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:20]
        return f"bootstrap-{digest}"

    @staticmethod
    def _required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            error_type = (
                InvalidBootstrapTitleError
                if field_name == "title"
                else InvalidAnalysisResultError
            )
            raise error_type(f"{field_name} must be a non-empty string")
        return value.strip()
