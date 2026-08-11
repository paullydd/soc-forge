from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from soc_forge.investigations.bootstrap import InvestigationBootstrapAdapter
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.evidence_service import InvestigationEvidenceService
from soc_forge.investigations.handoff import (
    HandoffArtifactDigestMismatchError,
    HandoffBundleValidationError,
    HandoffManifestSummary,
    HandoffReferenceIntegrityError,
    HandoffResult,
    UnsupportedHandoffSchemaError,
    InvestigationHandoffService,
    read_handoff_manifest,
    validate_handoff_bundle,
)
from soc_forge.investigations.pivots import InvestigationPivotService
from soc_forge.investigations.query_context import (
    InvestigationQueryContext,
    opaque_entity_id,
)
from soc_forge.investigations.snapshots import CompletedAnalysisSnapshotStore
from soc_forge.investigations.query_models import (
    ENTITY_TYPES,
    InvestigationEntityIdentityCollisionError,
    InvestigationEntityNotFoundError,
    UnsupportedEntityTypeError,
)
from soc_forge.investigations.timeline_query import InvestigationTimelineService
from soc_forge.investigations.reasoning_service import InvestigationReasoningService
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


class DecisionNotFoundError(InvestigationRequestError):
    pass


class LegacyDecisionMutationError(InvestigationRequestError):
    pass


class TimelineEntryNotFoundError(InvestigationRequestError):
    pass


class HandoffRevisionConflictError(InvestigationRequestError):
    def __init__(self, investigation_id: str, authoritative_revision: int):
        super().__init__("The investigation revision has changed.")
        self.investigation_id = investigation_id
        self.authoritative_revision = authoritative_revision


class InvalidHandoffRequestError(InvestigationRequestError):
    pass

DECISION_RATIONALE_SUMMARY_LIMIT = 160


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
        reasoning_service: InvestigationReasoningService | None = None,
        handoff_service: InvestigationHandoffService | None = None,
        handoff_root: Path | None = None,
        snapshot_store: CompletedAnalysisSnapshotStore | None = None,
        analysis_activator: Callable[[object], None] | None = None,
    ):
        self.bootstrap_adapter = bootstrap_adapter
        self.workspace_service = workspace_service
        self.analysis_provider = analysis_provider
        self.evidence_catalog = evidence_catalog or AnalysisEvidenceCatalog()
        self.evidence_service = evidence_service or InvestigationEvidenceService(
            workspace_service
        )

        self.reasoning_service = reasoning_service or InvestigationReasoningService(
            workspace_service
        )
        self.timeline_service = InvestigationTimelineService()
        self.pivot_service = InvestigationPivotService()
        self.handoff_service = handoff_service or InvestigationHandoffService(
            workspace_service.repository
        )
        self.handoff_root = Path(handoff_root or "out/handoffs")
        self.snapshot_store = snapshot_store
        self.analysis_activator = analysis_activator

    def _workspace_response(self, result: WorkspaceResult) -> Dict[str, Any]:
        response = workspace_response(result)
        available = self._matching_analysis_available(result)
        response["source_analysis"] = {
            "source_analysis_id": result.investigation.analysis_id,
            "available": available,
            "status": "available" if available else "unavailable",
        }
        return response

    def load_source_analysis(self, investigation_id: str) -> Dict[str, Any]:
        if self.snapshot_store is None or self.analysis_activator is None:
            raise InvestigationRequestError("Source analysis recovery is unavailable.")
        current = self.workspace_service.get_investigation(investigation_id)
        source_analysis_id = current.investigation.analysis_id
        analysis = self.snapshot_store.load(source_analysis_id)
        InvestigationQueryContext(
            analysis,
            current.investigation,
            evidence_catalog=self.evidence_catalog,
        )
        self.analysis_activator(analysis)
        return {
            "investigation_id": investigation_id,
            "source_analysis_id": source_analysis_id,
            "loaded": True,
            "event_count": len(analysis.events),
            "alert_count": len(analysis.alerts),
            "case_count": len(analysis.cases),
            "reconstruction_count": len(analysis.reconstructions),
            "message": "Source analysis is available in this server session.",
        }

    def preview_handoff(self, investigation_id: str) -> Dict[str, Any]:
        analysis = self._active_handoff_analysis()
        return asdict(self.handoff_service.preview(investigation_id, analysis))

    def export_handoff(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        expected_revision = self._expected_revision(payload)
        current = self.workspace_service.get_investigation(investigation_id)
        if current.revision != expected_revision:
            raise HandoffRevisionConflictError(investigation_id, current.revision)
        if payload.get("output_root", "handoffs") != "handoffs":
            raise InvalidHandoffRequestError("Unsupported handoff output root.")
        overwrite = payload.get("overwrite", False)
        acknowledged = payload.get("sensitive_data_acknowledged", False)
        if not isinstance(overwrite, bool):
            raise InvalidHandoffRequestError("overwrite must be true or false")
        if acknowledged is not True:
            raise InvalidHandoffRequestError(
                "Sensitive-data acknowledgement is required."
            )
        allowed = {
            "expected_revision",
            "output_root",
            "overwrite",
            "sensitive_data_acknowledged",
        }
        if set(payload).difference(allowed):
            raise InvalidHandoffRequestError("Unsupported handoff export input.")
        analysis = self._active_handoff_analysis()
        result = self.handoff_service.export(
            investigation_id,
            analysis,
            self.handoff_root,
            overwrite=overwrite,
        )
        return self._handoff_result_response(result)

    def get_handoff_manifest(self, investigation_id: str) -> Dict[str, Any]:
        return self._manifest_response(
            read_handoff_manifest(self._handoff_bundle(investigation_id))
        )

    def validate_handoff(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        if payload:
            raise InvalidHandoffRequestError(
                "Handoff validation does not accept request fields."
            )
        bundle = self._handoff_bundle(investigation_id)
        try:
            validate_handoff_bundle(bundle)
            manifest = read_handoff_manifest(bundle)
        except HandoffBundleValidationError as exc:
            if isinstance(exc, HandoffArtifactDigestMismatchError):
                reason = "digest_mismatch"
            elif isinstance(exc, UnsupportedHandoffSchemaError):
                reason = "unsupported_schema"
            elif isinstance(exc, HandoffReferenceIntegrityError):
                reason = "reference_integrity_failure"
            elif "missing" in str(exc).casefold():
                reason = "missing_file"
            else:
                reason = "invalid_bundle"
            return {
                "valid": False,
                "handoff_id": None,
                "investigation_id": investigation_id,
                "schema_version": None,
                "file_count": 0,
                "digest_status": "invalid",
                "reference_integrity_status": (
                    "invalid" if reason == "reference_integrity_failure" else "unknown"
                ),
                "warnings": [reason],
                "failure_reason": reason,
            }
        return {
            "valid": True,
            "handoff_id": manifest.handoff_id,
            "investigation_id": manifest.investigation_id,
            "schema_version": manifest.schema_version,
            "file_count": len(manifest.files),
            "digest_status": "valid",
            "reference_integrity_status": "valid",
            "warnings": [],
        }

    def _active_handoff_analysis(self) -> object:
        analysis = self.analysis_provider()
        if analysis is None:
            raise NoActiveAnalysisError(
                "A matching active analysis is required for this handoff operation."
            )
        return analysis

    def _handoff_bundle(self, investigation_id: str) -> Path:
        if not investigation_id or any(
            value in investigation_id for value in ("/", "\\", "\x00")
        ) or investigation_id in {".", ".."}:
            raise InvalidHandoffRequestError("Invalid investigation ID.")
        return self.handoff_root / investigation_id

    @staticmethod
    def _handoff_result_response(result: HandoffResult) -> Dict[str, Any]:
        return {
            "handoff_id": result.handoff_id,
            "investigation_id": result.investigation_id,
            "revision": result.revision,
            "bundle_location": f"handoffs/{result.investigation_id}",
            "manifest_location": f"handoffs/{result.investigation_id}/manifest.json",
            "file_count": len(result.files),
            "validation_status": result.validation_status,
            "warnings": list(result.warnings),
        }

    @staticmethod
    def _manifest_response(summary: HandoffManifestSummary) -> Dict[str, Any]:
        return {
            "schema_version": summary.schema_version,
            "handoff_id": summary.handoff_id,
            "investigation_id": summary.investigation_id,
            "source_analysis_id": summary.source_analysis_id,
            "revision": summary.revision,
            "owner": summary.owner,
            "status": summary.status,
            "selected_case_ids": list(summary.selected_case_ids),
            "files": [asdict(item) for item in summary.files],
            "warnings": [],
            "limitations": list(summary.limitations),
            "sensitive_data_warning": summary.sensitive_data_warning,
        }

    def list_investigations(self) -> list[Dict[str, Any]]:
        return [asdict(summary) for summary in self.workspace_service.list_investigations()]

    def get_investigation(self, investigation_id: str) -> Dict[str, Any]:
        return self._workspace_response(
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
        return self._workspace_response(result)

    def assign_owner(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        owner = payload.get("owner")
        if owner is not None and not isinstance(owner, str):
            raise InvestigationRequestError("owner must be a string or null")
        return self._workspace_response(
            self.workspace_service.assign_owner(
                investigation_id,
                owner,
                expected_revision=self._expected_revision(payload),
            )
        )

    def change_status(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return self._workspace_response(
            self.workspace_service.change_status(
                investigation_id,
                self._required_text(payload, "status"),
                expected_revision=self._expected_revision(payload),
            )
        )

    def reopen(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return self._workspace_response(
            self.workspace_service.reopen_investigation(
                investigation_id,
                expected_revision=self._expected_revision(payload),
            )
        )

    def add_annotation(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        return self._workspace_response(
            self.workspace_service.add_annotation(
                investigation_id,
                annotation_id=self._required_text(payload, "annotation_id"),
                author=self._string_value(payload, "author"),
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
        return self._workspace_response(
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
        return self._workspace_response(
            self.workspace_service.remove_annotation(
                investigation_id,
                annotation_id,
                expected_revision=self._expected_revision(payload),
            )
        )

    def record_decision(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        raise LegacyDecisionMutationError(
            "Legacy decision creation is unavailable; use the reasoning decisions endpoint"
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
        return self._workspace_response(result)

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
        return self._workspace_response(result)

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
        return self._workspace_response(result)


    def get_reasoning_summary(self, investigation_id: str) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        summary = self.reasoning_service.reasoning_summary(investigation_id)
        response = asdict(summary)
        response["total_decisions"] = response.pop("decision_count")
        response["revision"] = current.revision
        return response

    def list_hypotheses(self, investigation_id: str) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        hypotheses = sorted(
            current.investigation.hypotheses,
            key=lambda item: item.hypothesis_id,
        )
        return {
            "hypotheses": [
                {
                    "hypothesis_id": item.hypothesis_id,
                    "statement": item.statement,
                    "state": item.state,
                    "author": item.author,
                    "created_at": item.created_at,
                    "updated_at": item.updated_at,
                    "supporting_evidence_count": len(
                        item.supporting_evidence_reference_ids
                    ),
                    "contradicting_evidence_count": len(
                        item.contradicting_evidence_reference_ids
                    ),
                }
                for item in hypotheses
            ],
            "revision": current.revision,
        }

    def get_hypothesis(
        self, investigation_id: str, hypothesis_id: str
    ) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        hypothesis = self._hypothesis(current, hypothesis_id)
        evidence = {
            item.reference_id: item
            for item in current.investigation.evidence_references
        }
        decisions = sorted(
            (
                item
                for item in current.investigation.decisions
                if hypothesis_id in item.hypothesis_ids
            ),
            key=lambda item: (item.decided_at or "", item.decision_id),
        )
        return {
            "hypothesis": hypothesis.to_dict(),
            "supporting_evidence": [
                evidence[evidence_id].to_dict()
                for evidence_id in hypothesis.supporting_evidence_reference_ids
            ],
            "contradicting_evidence": [
                evidence[evidence_id].to_dict()
                for evidence_id in hypothesis.contradicting_evidence_reference_ids
            ],
            "related_decisions": [item.to_dict() for item in decisions],
            "revision": current.revision,
            "source_details_available": self._matching_analysis_available(current),
        }

    def create_hypothesis(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        result = self.reasoning_service.create_hypothesis(
            investigation_id,
            hypothesis_id=self._required_text(payload, "hypothesis_id"),
            statement=self._string_value(payload, "statement"),
            author=self._string_value(payload, "author"),
            supporting_evidence_ids=self._optional_list(
                payload, "supporting_evidence_ids"
            ),
            contradicting_evidence_ids=self._optional_list(
                payload, "contradicting_evidence_ids"
            ),
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result, hypothesis_id=self._required_text(payload, "hypothesis_id")
        )

    def edit_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        hypothesis = self._hypothesis(current, hypothesis_id)
        result = self.reasoning_service.edit_hypothesis_statement(
            investigation_id,
            hypothesis_id,
            statement=self._string_value(payload, "statement"),
            author=hypothesis.author or "Unknown",
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result, hypothesis_id=hypothesis_id
        )

    def add_hypothesis_evidence(
        self,
        investigation_id: str,
        hypothesis_id: str,
        relationship: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        result = self.reasoning_service.add_hypothesis_evidence(
            investigation_id,
            hypothesis_id,
            self._required_text(payload, "evidence_id"),
            relationship=relationship,
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result, hypothesis_id=hypothesis_id
        )

    def remove_hypothesis_evidence(
        self,
        investigation_id: str,
        hypothesis_id: str,
        evidence_id: str,
        relationship: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        result = self.reasoning_service.remove_hypothesis_evidence(
            investigation_id,
            hypothesis_id,
            evidence_id,
            relationship=relationship,
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result, hypothesis_id=hypothesis_id
        )

    def assess_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        decision_id = self._required_text(payload, "decision_id")
        result = self.reasoning_service.assess_hypothesis(
            investigation_id,
            hypothesis_id,
            state=self._string_value(payload, "state"),
            rationale=self._string_value(payload, "rationale"),
            author=self._string_value(payload, "author"),
            decision_id=decision_id,
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result,
            hypothesis_id=hypothesis_id,
            decision_id=decision_id,
        )

    def reopen_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        decision_id = self._required_text(payload, "decision_id")
        result = self.reasoning_service.reopen_hypothesis(
            investigation_id,
            hypothesis_id,
            rationale=self._string_value(payload, "rationale"),
            author=self._string_value(payload, "author"),
            decision_id=decision_id,
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(
            result,
            hypothesis_id=hypothesis_id,
            decision_id=decision_id,
        )

    def list_reasoning_decisions(self, investigation_id: str) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        decisions = sorted(
            current.investigation.decisions,
            key=lambda item: (item.decided_at or "", item.decision_id),
        )
        return {
            "decisions": [
                {
                    "decision_id": item.decision_id,
                    "decision_type": item.decision_type,
                    "author": item.decided_by,
                    "decided_at": item.decided_at,
                    "rationale_summary": self._bounded_summary(
                        item.rationale, DECISION_RATIONALE_SUMMARY_LIMIT
                    ),
                    "outcome": item.outcome,
                    "related_hypothesis_count": len(item.hypothesis_ids),
                    "related_evidence_count": len(item.evidence_reference_ids),
                }
                for item in decisions
            ],
            "revision": current.revision,
        }

    def get_reasoning_decision(
        self, investigation_id: str, decision_id: str
    ) -> Dict[str, Any]:
        current = self.workspace_service.get_investigation(investigation_id)
        decision = next(
            (
                item
                for item in current.investigation.decisions
                if item.decision_id == decision_id
            ),
            None,
        )
        if decision is None:
            raise DecisionNotFoundError("Decision not found.")
        return {"decision": decision.to_dict(), "revision": current.revision}

    @staticmethod
    def _bounded_summary(value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."

    def record_reasoning_decision(
        self, investigation_id: str, payload: Mapping[str, Any]
    ) -> Dict[str, Any]:
        decision_id = self._required_text(payload, "decision_id")
        decision_type = self._required_text(payload, "decision_type")
        if decision_type == "hypothesis_assessment":
            from soc_forge.investigations.reasoning_service import InvalidDecisionTypeError

            raise InvalidDecisionTypeError(
                "Hypothesis assessments use the dedicated assessment endpoint"
            )
        result = self.reasoning_service.record_investigation_decision(
            investigation_id,
            decision_id=decision_id,
            decision_type=decision_type,
            outcome=self._optional_text(payload, "outcome") or decision_type,
            rationale=self._string_value(payload, "rationale"),
            author=self._string_value(payload, "author"),
            evidence_reference_ids=self._optional_list(
                payload, "evidence_reference_ids"
            ),
            hypothesis_ids=self._optional_list(payload, "hypothesis_ids"),
            expected_revision=self._expected_revision(payload),
        )
        return self._reasoning_mutation_response(result, decision_id=decision_id)

    def _reasoning_mutation_response(
        self,
        result: WorkspaceResult,
        *,
        hypothesis_id: str | None = None,
        decision_id: str | None = None,
    ) -> Dict[str, Any]:
        response = self._workspace_response(result)
        if hypothesis_id is not None:
            response["hypothesis"] = self._hypothesis(
                result, hypothesis_id
            ).to_dict()
        if decision_id is not None:
            decision = next(
                (
                    item
                    for item in result.investigation.decisions
                    if item.decision_id == decision_id
                ),
                None,
            )
            if decision is None:
                from soc_forge.investigations.reasoning_service import (
                    InvalidHypothesisTransitionError,
                )

                raise InvalidHypothesisTransitionError(
                    "The requested hypothesis transition did not append a decision"
                )
            response["decision"] = decision.to_dict()
        return response

    @staticmethod
    def _hypothesis(current: WorkspaceResult, hypothesis_id: str):
        from soc_forge.investigations.reasoning_service import HypothesisNotFoundError

        hypothesis = next(
            (
                item
                for item in current.investigation.hypotheses
                if item.hypothesis_id == hypothesis_id
            ),
            None,
        )
        if hypothesis is None:
            raise HypothesisNotFoundError(
                f"Hypothesis {hypothesis_id!r} was not found"
            )
        return hypothesis

    def get_timeline(
        self,
        investigation_id: str,
        filters: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        current, context = self._query_context(investigation_id)
        timeline = self.timeline_service.timeline(context, filters=filters)
        return {
            "investigation_id": timeline.investigation_id,
            "source_analysis_id": timeline.source_analysis_id,
            "revision": current.revision,
            "timed_entries": [asdict(item) for item in timeline.entries],
            "untimed_entries": [asdict(item) for item in timeline.untimed_entries],
            "applied_filters": asdict(timeline.applied_filters),
            "limitations": list(timeline.limitations),
        }

    def get_timeline_entry(
        self, investigation_id: str, entry_id: str
    ) -> Dict[str, Any]:
        payload = self.get_timeline(investigation_id)
        entry = next(
            (
                item
                for item in payload["timed_entries"] + payload["untimed_entries"]
                if item["entry_id"] == entry_id
            ),
            None,
        )
        if entry is None:
            raise TimelineEntryNotFoundError("Timeline entry not found")
        return {
            "investigation_id": payload["investigation_id"],
            "source_analysis_id": payload["source_analysis_id"],
            "revision": payload["revision"],
            "entry": entry,
            "navigation": {
                "evidence_id": entry["evidence_id"],
                "hypothesis_ids": entry["related_hypothesis_ids"],
                "decision_ids": entry["related_decision_ids"],
            },
        }

    def list_query_entities(
        self, investigation_id: str, entity_type: str | None = None
    ) -> Dict[str, Any]:
        current, context = self._query_context(investigation_id)
        if entity_type is not None and entity_type not in ENTITY_TYPES:
            raise UnsupportedEntityTypeError(
                f"Unsupported entity type: {entity_type}"
            )
        entities = tuple(
            item
            for item in self._entity_index(context).values()
            if entity_type is None or item.entity_type == entity_type
        )
        return {
            "investigation_id": investigation_id,
            "source_analysis_id": context.source_analysis_id,
            "revision": current.revision,
            "entity_type": entity_type,
            "entities": [self._entity_summary(context, item) for item in entities],
            "limitations": [],
        }

    def get_query_entity(
        self, investigation_id: str, entity_id: str
    ) -> Dict[str, Any]:
        current, context = self._query_context(investigation_id)
        entity = self._resolve_entity_id(context, entity_id)
        return {
            "investigation_id": investigation_id,
            "source_analysis_id": context.source_analysis_id,
            "revision": current.revision,
            "entity": self._entity_summary(context, entity),
        }

    def get_entity_pivot(
        self,
        investigation_id: str,
        entity_id: str,
        category: str,
    ) -> Dict[str, Any]:
        current, context = self._query_context(investigation_id)
        entity = self._resolve_entity_id(context, entity_id)
        if category == "timeline":
            timeline = self.pivot_service.timeline_for_entity(
                context, entity.entity_type, entity.value
            )
            return {
                "investigation_id": investigation_id,
                "source_analysis_id": context.source_analysis_id,
                "revision": current.revision,
                "entity": asdict(entity),
                "timed_entries": [asdict(item) for item in timeline.entries],
                "untimed_entries": [asdict(item) for item in timeline.untimed_entries],
                "applied_filters": asdict(timeline.applied_filters),
                "limitations": list(timeline.limitations),
            }
        if category == "related":
            result = self.pivot_service.related_entities(
                context, entity.entity_type, entity.value
            )
            return {
                "investigation_id": result.investigation_id,
                "source_analysis_id": result.source_analysis_id,
                "revision": current.revision,
                "entity": asdict(result.entity),
                "relationships": [asdict(item) for item in result.relationships],
                "limitations": list(result.limitations),
            }
        operations = {
            "events": self.pivot_service.events_for_entity,
            "alerts": self.pivot_service.alerts_for_entity,
            "cases": self.pivot_service.cases_for_entity,
            "evidence": self.pivot_service.evidence_for_entity,
            "hypotheses": self.pivot_service.hypotheses_for_entity,
        }
        operation = operations.get(category)
        if operation is None:
            raise InvestigationRequestError("Unsupported entity pivot category")
        result = operation(context, entity.entity_type, entity.value)
        return {
            "investigation_id": result.investigation_id,
            "source_analysis_id": result.source_analysis_id,
            "revision": current.revision,
            "entity": asdict(result.entity),
            "matches": [asdict(item) for item in result.matches],
            "limitations": list(result.limitations),
        }

    def _query_context(self, investigation_id: str):
        current, analysis = self._evidence_context(investigation_id)
        return current, InvestigationQueryContext(
            analysis,
            current.investigation,
            evidence_catalog=self.evidence_catalog,
        )

    def _entity_index(self, context):
        index = {}
        for entity in self.pivot_service.entities(context):
            entity_id = opaque_entity_id(
                context.investigation.investigation_id,
                context.source_analysis_id,
                entity,
            )
            existing = index.get(entity_id)
            if existing is not None and existing != entity:
                raise InvestigationEntityIdentityCollisionError(
                    "Opaque entity identity collision"
                )
            index[entity_id] = entity
        return index

    def _resolve_entity_id(self, context, entity_id: str):
        entity = self._entity_index(context).get(entity_id)
        if entity is None:
            raise InvestigationEntityNotFoundError("Entity not found")
        return entity

    def _entity_summary(self, context, entity) -> Dict[str, Any]:
        results = (
            self.pivot_service.events_for_entity(
                context, entity.entity_type, entity.value
            ),
            self.pivot_service.alerts_for_entity(
                context, entity.entity_type, entity.value
            ),
            self.pivot_service.cases_for_entity(
                context, entity.entity_type, entity.value
            ),
            self.pivot_service.evidence_for_entity(
                context, entity.entity_type, entity.value
            ),
        )
        timestamps = sorted(
            value
            for result in results
            for match in result.matches
            for value in (match.first_seen, match.last_seen)
            if value
        )
        return {
            "entity_id": opaque_entity_id(
                context.investigation.investigation_id,
                context.source_analysis_id,
                entity,
            ),
            **asdict(entity),
            "observed_counts": {
                "events": len(results[0].matches),
                "alerts": len(results[1].matches),
                "cases": len(results[2].matches),
                "evidence": len(results[3].matches),
                "evidence_selections": sum(
                    item.analyst_selected for item in results[3].matches
                ),
            },
            "first_seen": timestamps[0] if timestamps else None,
            "last_seen": timestamps[-1] if timestamps else None,
        }

    def _matching_analysis_available(self, current: WorkspaceResult) -> bool:
        analysis = self.analysis_provider()
        if analysis is None:
            return False
        try:
            return (
                self.evidence_catalog.source_analysis_id(analysis)
                == current.investigation.analysis_id
            )
        except Exception:
            return False

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
