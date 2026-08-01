from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable, Dict, Mapping

from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.evidence_service import InvestigationEvidenceService
from soc_forge.investigations.workspace_service import (
    InvestigationWorkspaceService,
    WorkspaceDeletionResult,
    WorkspaceResult,
)


class InvestigationRequestError(ValueError):
    pass


class NoActiveAnalysisError(InvestigationRequestError):
    pass


class EvidenceAnalysisUnavailableError(InvestigationRequestError):
    pass


class EvidenceAnalysisProvenanceMismatchError(InvestigationRequestError):
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
        evidence_catalog: AnalysisEvidenceCatalog | None = None,
        evidence_service: InvestigationEvidenceService | None = None,
    ):
        self.bootstrap_adapter = bootstrap_adapter
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider
        self.evidence_catalog = evidence_catalog or AnalysisEvidenceCatalog()
        self.evidence_service = evidence_service or InvestigationEvidenceService(
            workspace_service
        )

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

    def list_evidence_candidates(
        self,
        investigation_id: str,
        evidence_type: str | None = None,
    ) -> Dict[str, Any]:
        current, analysis = self._evidence_context(investigation_id)
        evidence_types = None if evidence_type in (None, "all") else (evidence_type,)
        candidates = self.evidence_catalog.list_candidates(
            analysis,
            case_ids=self._scope_case_ids(current),
            evidence_types=evidence_types,
        )
        return {
            "candidates": [self._candidate_response(item) for item in candidates],
            "filter": evidence_type or "all",
            "revision": current.revision,
        }

    def get_evidence_candidate(
        self,
        investigation_id: str,
        evidence_id: str,
        *,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        current, analysis = self._evidence_context(investigation_id)
        candidate = self.evidence_catalog.get_candidate(analysis, evidence_id)
        if not set(candidate.case_ids).intersection(self._scope_case_ids(current)):
            from soc_forge.investigations.evidence_service import EvidenceOutsideScopeError

            raise EvidenceOutsideScopeError("Evidence is outside investigation case scope")
        details = self.evidence_catalog.resolve_details(analysis, evidence_id)
        fields = []
        for field in details.fields:
            item = field.to_dict()
            if field.sensitive and not include_sensitive:
                item["value"] = None
                item["value_hidden"] = True
            else:
                item["value_hidden"] = False
            fields.append(item)
        return {
            "candidate": self._candidate_response(candidate),
            "details": {"evidence_id": details.evidence_id, "fields": fields},
            "source_resolvable": True,
            "sensitive_values_included": include_sensitive,
            "revision": current.revision,
        }

    def list_evidence_selections(self, investigation_id: str) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        references = current.investigation.evidence_references
        scope = sorted(
            (item for item in references if item.origin == "scope"),
            key=lambda item: item.reference_id,
        )
        selected = sorted(
            (item for item in references if item.origin == "analyst_selection"),
            key=lambda item: item.reference_id,
        )
        return {
            "scope_references": [item.to_dict() for item in scope],
            "analyst_selections": [item.to_dict() for item in selected],
            "counts": {
                "scope": len(scope),
                "selected": len(selected),
                "supporting": sum(item.classification == "supporting" for item in selected),
                "contradicting": sum(
                    item.classification == "contradicting" for item in selected
                ),
                "context": sum(item.classification == "context" for item in selected),
            },
            "revision": current.revision,
        }

    def select_evidence(
        self,
        investigation_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        current, analysis = self._evidence_context(investigation_id)
        evidence_id = self._required_text(payload, "evidence_id")
        candidate = self.evidence_catalog.get_candidate(analysis, evidence_id)
        result = self.evidence_service.select_evidence(
            investigation_id,
            candidate,
            classification=self._string_value(payload, "classification"),
            rationale=self._string_value(payload, "rationale"),
            author=self._string_value(payload, "author"),
            expected_revision=self._expected_revision(payload),
        )
        return workspace_response(result)

    def update_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        allowed = {"classification", "rationale", "author", "expected_revision"}
        unknown = sorted(set(payload).difference(allowed))
        if unknown:
            raise InvestigationRequestError(
                "Evidence update contains unsupported field(s): " + ", ".join(unknown)
            )
        classification = self._optional_update_text(payload, "classification")
        rationale = self._optional_update_text(payload, "rationale")
        author = self._optional_update_text(payload, "author")
        result = self.evidence_service.update_evidence_rationale(
            investigation_id,
            evidence_id,
            classification=classification,
            rationale=rationale,
            author=author,
            expected_revision=self._expected_revision(payload),
        )
        return workspace_response(result)

    def remove_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        result = self.evidence_service.remove_evidence(
            investigation_id,
            evidence_id,
            expected_revision=self._expected_revision(payload),
        )
        return workspace_response(result)

    def _evidence_context(self, investigation_id: str):
        current = self.workspace_service.get_investigation(investigation_id)
        analysis = self.analysis_provider()
        if analysis is None:
            raise EvidenceAnalysisUnavailableError(
                "Source evidence details require the matching completed analysis to be active."
            )
        active_analysis_id = self.evidence_catalog.source_analysis_id(analysis)
        if active_analysis_id != current.investigation.analysis_id:
            raise EvidenceAnalysisProvenanceMismatchError(
                "The active analysis does not match this investigation."
            )
        return current, analysis

    @staticmethod
    def _scope_case_ids(current: WorkspaceResult) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.source_id
                for item in current.investigation.evidence_references
                if item.origin == "scope" and item.source_type == "case"
            )
        )

    @staticmethod
    def _candidate_response(candidate) -> Dict[str, Any]:
        return {
            "evidence_id": candidate.evidence_id,
            "evidence_type": candidate.evidence_type,
            "title": candidate.title,
            "summary": candidate.summary,
            "timestamp": candidate.timestamp,
            "source_id": candidate.source_id,
            "case_ids": list(candidate.case_ids),
            "rule_id": candidate.rule_id,
            "tactic": candidate.tactic,
            "technique": candidate.technique,
            "entities": list(candidate.entity_references),
            "sensitive_fields": list(candidate.sensitive_fields),
            "relationship": candidate.relationship,
            "limitation_reason": candidate.limitation_reason,
            "selectable": candidate.selectable,
            "source_analysis_id": candidate.source_analysis_id,
        }

    @staticmethod
    def _string_value(payload: Mapping[str, Any], field: str) -> str:
        value = payload.get(field)
        if not isinstance(value, str):
            raise InvestigationRequestError(f"{field} must be a string")
        return value

    @staticmethod
    def _optional_update_text(
        payload: Mapping[str, Any], field: str
    ) -> str | None:
        if field not in payload:
            return None
        value = payload[field]
        if not isinstance(value, str):
            raise InvestigationRequestError(f"{field} must be a string")
        return value

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
