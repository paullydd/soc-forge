from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable, Dict, Mapping

from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceDeletionResult,
    WorkspaceResult,
)


class InvestigationRequestError(ValueError):
    pass


class NoActiveAnalysisError(InvestigationRequestError):
    pass


def workspace_response(result: WorkspaceResult) -> Dict[str, Any]:
    return {
        "investigation": result.investigation.to_dict(),
        "revision": result.revision,
    }


def deletion_response(result: WorkspaceDeletionResult) -> Dict[str, Any]:
    return {
        "investigation_id": result.investigation_id,
        "deleted_revision": result.deleted_revision,
    }


class InvestigationWebApplication:
    def __init__(
        self,
        *,
        bootstrap_adapter: InvestigationBootstrapAdapter,
        workspace_service: InvestigationWorkspaceService,
        analysis_provider: Callable[[], object | None],
    ):
        self.bootstrap_adapter = bootstrap_adapter
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider

    def list_investigations(self) -> list[Dict[str, Any]]:
        return [asdict(summary) for summary in self.workspace_service.list_investigations()]

    def get_investigation(self, investigation_id: str) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.get_investigation(investigation_id)
        )

    def create_investigation(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        analysis_result = self.analysis_provider()
        if analysis_result is None:
            raise NoActiveAnalysisError(
                "Run or select a scenario before creating an investigation."
            )
        result = self.bootstrap_adapter.bootstrap_investigation(
            analysis_result,
            self._required_text(payload, "investigation_id"),
            self._required_list(payload, "case_ids"),
            title=self._optional_text(payload, "title"),
            owner=self._optional_text(payload, "owner"),
            initial_status=str(payload.get("initial_status") or "open"),
        )
        return workspace_response(result)

    def assign_owner(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        owner = payload.get("owner")
        if owner is not None and not isinstance(owner, str):
            raise InvestigationRequestError("owner must be a string or null")
        return workspace_response(
            self.workspace_service.assign_owner(
                investigation_id,
                owner,
                expected_revision=self._expected_revision(payload),
            )
        )

    def change_status(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.change_status(
                investigation_id,
                self._required_text(payload, "status"),
                expected_revision=self._expected_revision(payload),
            )
        )

    def reopen(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.reopen_investigation(
                investigation_id,
                expected_revision=self._expected_revision(payload),
            )
        )

    def add_annotation(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.add_annotation(
                investigation_id,
                annotation_id=self._required_text(payload, "annotation_id"),
                author=self._required_text(payload, "author"),
                body=self._required_text(payload, "text"),
                target_type=str(payload.get("target_type") or "investigation"),
                target_id=self._optional_text(payload, "target_id"),
                expected_revision=self._expected_revision(payload),
            )
        )

    def update_annotation(
        self,
        investigation_id: str,
        annotation_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.update_annotation(
                investigation_id,
                annotation_id,
                self._required_text(payload, "text"),
                expected_revision=self._expected_revision(payload),
            )
        )

    def remove_annotation(
        self,
        investigation_id: str,
        annotation_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.remove_annotation(
                investigation_id,
                annotation_id,
                expected_revision=self._expected_revision(payload),
            )
        )

    def record_decision(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return workspace_response(
            self.workspace_service.record_decision(
                investigation_id,
                decision_id=self._required_text(payload, "decision_id"),
                author=self._required_text(payload, "author"),
                decision_type=self._required_text(payload, "decision_type"),
                outcome=self._required_text(payload, "outcome"),
                rationale=self._required_text(payload, "rationale"),
                evidence_reference_ids=self._optional_list(
                    payload, "evidence_reference_ids"
                ),
                hypothesis_ids=self._optional_list(payload, "hypothesis_ids"),
                expected_revision=self._expected_revision(payload),
            )
        )

    def delete_investigation(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return deletion_response(
            self.workspace_service.delete_investigation(
                investigation_id,
                expected_revision=self._expected_revision(payload),
            )
        )

    @staticmethod
    def _expected_revision(payload: Mapping[str, Any]) -> int:
        value = payload.get("expected_revision")
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise InvestigationRequestError(
                "expected_revision must be a positive integer"
            )
        return value

    @staticmethod
    def _required_text(payload: Mapping[str, Any], field: str) -> str:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            raise InvestigationRequestError(f"{field} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _optional_text(payload: Mapping[str, Any], field: str) -> str | None:
        value = payload.get(field)
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise InvestigationRequestError(f"{field} must be a string or null")
        return value

    @classmethod
    def _required_list(
        cls, payload: Mapping[str, Any], field: str
    ) -> tuple[str, ...]:
        values = cls._optional_list(payload, field)
        if not values:
            raise InvestigationRequestError(f"{field} must contain at least one ID")
        return values

    @staticmethod
    def _optional_list(
        payload: Mapping[str, Any], field: str
    ) -> tuple[str, ...]:
        value = payload.get(field, [])
        if not isinstance(value, list):
            raise InvestigationRequestError(f"{field} must be a list")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise InvestigationRequestError(
                f"{field} must contain only non-empty strings"
            )
        return tuple(item.strip() for item in value)
