from __future__ import annotations

from pathlib import Path
from typing import Callable

from soc_forge.investigations.handoff import (
    HandoffArtifactDigestMismatchError,
    HandoffBundleValidationError,
    HandoffError,
    HandoffManifestSummary,
    HandoffPreview,
    HandoffProvenanceMismatchError,
    HandoffReferenceIntegrityError,
    HandoffResult,
    InvestigationChangedDuringHandoffError,
    InvestigationHandoffService,
    RequiredHandoffArtifactMissingError,
    SENSITIVE_DATA_WARNING,
    UnsafeHandoffArtifactPathError,
    UnsafeHandoffOutputPathError,
    UnsupportedHandoffSchemaError,
    read_handoff_manifest,
    validate_handoff_bundle,
)
from soc_forge.investigations.repository import InvestigationRepositoryError
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.screen import begin_screen


DEFAULT_HANDOFF_ROOT = Path("out/handoffs")
CONSOLE_SENSITIVE_WARNING = (
    "This handoff may contain sensitive security telemetry and analyst-authored "
    "content, including usernames, hosts, IP addresses, evidence rationale, "
    "hypotheses, decisions, and annotations."
)


class InvestigationHandoffConsoleController:
    """Terminal presentation for the shared read-only handoff service."""

    def __init__(
        self,
        *,
        handoff_service: InvestigationHandoffService,
        analysis_provider: Callable[[], object | None],
        input_func: Callable[[str], str] = input,
        output_func: Callable[[str], None] = print,
        screen_func: Callable[[str], None] = begin_screen,
        pause_func: Callable[[], None] | None = None,
        default_output_root: Path | str = DEFAULT_HANDOFF_ROOT,
    ) -> None:
        self.handoff_service = handoff_service
        self.analysis_provider = analysis_provider
        self.input = input_func
        self.output = output_func
        self.screen = screen_func
        self.pause = pause_func or (lambda: self.input("\nPress Enter to return..."))
        self.default_output_root = Path(default_output_root)
        self.last_result: HandoffResult | None = None

    def run(self, current: WorkspaceResult) -> WorkspaceResult:
        while True:
            self.screen("INVESTIGATION HANDOFF")
            self.output("Read-only snapshot/export workflow")
            self.output("")
            self.output("[1] Preview handoff")
            self.output("[2] Export handoff")
            self.output("[3] Validate handoff bundle")
            self.output("[4] View last handoff result")
            self.output("[0] Back")
            choice = self.input("\nSelect option: ").strip()
            if choice == "0":
                return current
            if choice == "1":
                self.preview_flow(current)
                self.pause()
            elif choice == "2":
                self.export_flow(current)
                self.pause()
            elif choice == "3":
                self.validation_flow()
                self.pause()
            elif choice == "4":
                self.view_last_result()
                self.pause()
            else:
                self.output("Invalid option.")

    def preview_flow(self, current: WorkspaceResult) -> HandoffPreview | None:
        analysis = self._active_analysis()
        if analysis is None:
            return None
        try:
            preview = self.handoff_service.preview(
                current.investigation.investigation_id,
                analysis,
            )
        except self._handoff_errors() as exc:
            self._display_error(exc, action="preview")
            return None
        self.render_preview(preview)
        return preview

    def export_flow(self, current: WorkspaceResult) -> HandoffResult | None:
        analysis = self._active_analysis()
        if analysis is None:
            return None
        try:
            preview = self.handoff_service.preview(
                current.investigation.investigation_id,
                analysis,
            )
        except self._handoff_errors() as exc:
            self._display_error(exc, action="preview")
            return None
        self.render_preview(preview)
        self.output("")
        self.output("SENSITIVE DATA WARNING")
        self.output(CONSOLE_SENSITIVE_WARNING)
        self.output("Review the handoff before sharing it outside the intended environment.")
        self.output("Automatic redaction is not provided.")
        confirmation = self.input("Acknowledge and continue with export? (y/N): ")
        if confirmation.strip().lower() not in {"y", "yes"}:
            self.output("Handoff export cancelled.")
            return None

        root_value = self.input(
            f"Output root [{self.default_output_root}]: "
        ).strip()
        output_root = Path(root_value) if root_value else self.default_output_root
        self.output(
            f"Handoff location: {output_root} / "
            f"{current.investigation.investigation_id}/"
        )
        return self._export_to_root(current, analysis, output_root)

    def _export_to_root(
        self,
        current: WorkspaceResult,
        analysis: object,
        output_root: Path,
    ) -> HandoffResult | None:
        investigation_id = current.investigation.investigation_id
        try:
            result = self.handoff_service.export(
                investigation_id,
                analysis,
                output_root,
            )
        except UnsafeHandoffOutputPathError as exc:
            if "already exists" not in str(exc):
                self._display_error(exc, action="export")
                return None
            return self._existing_target_flow(current, analysis, output_root)
        except self._handoff_errors() as exc:
            self._display_error(exc, action="export")
            return None
        self.last_result = result
        self.render_result(result)
        return result

    def _existing_target_flow(
        self,
        current: WorkspaceResult,
        analysis: object,
        output_root: Path,
    ) -> HandoffResult | None:
        self.output("A handoff already exists for this investigation.")
        self.output("[1] Cancel")
        self.output("[2] Export to another root")
        self.output("[3] Overwrite existing handoff")
        choice = self.input("Select option: ").strip()
        if choice == "2":
            value = self.input("Another output root (blank to cancel): ").strip()
            if not value:
                self.output("Handoff export cancelled.")
                return None
            return self._export_to_root(current, analysis, Path(value))
        if choice != "3":
            self.output("Handoff export cancelled. Existing bundle was preserved.")
            return None
        self.output(
            "The existing handoff directory will be replaced only after a new "
            "bundle is fully staged and validated."
        )
        confirmation = self.input("Confirm overwrite? (y/N): ").strip().lower()
        if confirmation not in {"y", "yes"}:
            self.output("Overwrite cancelled. Existing bundle was preserved.")
            return None
        try:
            result = self.handoff_service.export(
                current.investigation.investigation_id,
                analysis,
                output_root,
                overwrite=True,
            )
        except self._handoff_errors() as exc:
            self._display_error(exc, action="export")
            return None
        self.last_result = result
        self.render_result(result)
        return result

    def validation_flow(self) -> HandoffManifestSummary | None:
        value = self.input("Handoff bundle directory (blank to cancel): ").strip()
        if not value:
            self.output("Handoff validation cancelled.")
            return None
        bundle = Path(value)
        try:
            validate_handoff_bundle(bundle)
            summary = read_handoff_manifest(bundle)
        except self._validation_errors() as exc:
            self._display_error(exc, action="validation")
            return None
        self.output("Handoff validation: VALID")
        self.output(f"Handoff ID: {summary.handoff_id}")
        self.output(f"Investigation ID: {summary.investigation_id}")
        self.output(f"Schema version: {summary.schema_version}")
        self.output(f"Files verified: {len(summary.files)}")
        self.output("Digest status: verified")
        self.output("Reference integrity: verified")
        for limitation in summary.limitations:
            self.output(f"Warning: {self._bounded(limitation)}")
        return summary

    def view_last_result(self) -> HandoffManifestSummary | None:
        if self.last_result is None:
            self.output("No handoff has been exported in this console session.")
            return None
        try:
            summary = read_handoff_manifest(self.last_result.output_path)
        except self._validation_errors() as exc:
            self._display_error(exc, action="manifest")
            return None
        self.render_manifest(summary)
        return summary

    def render_preview(self, preview: HandoffPreview) -> None:
        self.screen("HANDOFF PREVIEW")
        self.output(f"Investigation ID: {preview.investigation_id}")
        self.output(f"Title: {self._bounded(preview.title)}")
        self.output(f"Owner: {preview.owner or 'Unassigned'}")
        self.output(f"Status: {preview.status}")
        self.output(f"Revision: {preview.revision}")
        self.output(f"Source analysis ID: {preview.source_analysis_id}")
        self.output(f"Selected cases: {preview.selected_case_count}")
        self.output(f"Analyst-selected evidence: {preview.analyst_evidence_count}")
        self.output(f"Hypotheses: {preview.hypothesis_count}")
        self.output(f"Decisions: {preview.decision_count}")
        self.output(f"Annotations: {preview.annotation_count}")
        self.output(f"Timed timeline entries: {preview.timed_entry_count}")
        self.output(f"Untimed timeline entries: {preview.untimed_entry_count}")
        self.output(
            "Available artifacts: "
            + (", ".join(preview.available_artifact_keys) or "None")
        )
        self.output(
            "Required artifacts: "
            + ("available" if preview.required_artifacts_available else "missing")
        )
        self.output(
            "Missing optional artifacts: "
            + (", ".join(preview.missing_optional_artifact_keys) or "None")
        )
        self.output(f"Warning: {preview.sensitive_data_warning}")
        self.output("Terminal scrollback may retain displayed handoff metadata.")

    def render_result(self, result: HandoffResult) -> None:
        self.output("Handoff export complete.")
        self.output(f"Handoff ID: {result.handoff_id}")
        self.output(f"Investigation ID: {result.investigation_id}")
        self.output(f"Revision: {result.revision}")
        self.output(f"Output path: {result.output_path}")
        self.output(f"Manifest path: {result.manifest_path}")
        self.output(f"Validation status: {result.validation_status}")
        self.output(f"Files: {len(result.files)}")
        for warning in result.warnings:
            self.output(f"Warning: {self._bounded(warning)}")
        self.output("Investigation state was not modified.")

    def render_manifest(self, summary: HandoffManifestSummary) -> None:
        self.screen("HANDOFF MANIFEST")
        self.output(f"Schema version: {summary.schema_version}")
        self.output(f"Handoff ID: {summary.handoff_id}")
        self.output(f"Investigation ID: {summary.investigation_id}")
        self.output(f"Source analysis ID: {summary.source_analysis_id}")
        self.output(f"Revision: {summary.revision}")
        self.output(f"Owner: {summary.owner or 'Unassigned'}")
        self.output(f"Status: {summary.status}")
        self.output(
            "Selected case IDs: "
            + (", ".join(summary.selected_case_ids) or "None")
        )
        self.output("File inventory:")
        for item in summary.files:
            self.output(
                f"  {item.filename} | {item.logical_type} | {item.size} bytes | "
                f"SHA-256 {item.sha256}"
            )
        for limitation in summary.limitations:
            self.output(f"Warning: {self._bounded(limitation)}")
        self.output(f"Sensitive data notice: {summary.sensitive_data_warning}")
        self.output("Terminal scrollback may retain displayed handoff metadata.")

    def _active_analysis(self) -> object | None:
        analysis = self.analysis_provider()
        if analysis is None:
            self.output(
                "No completed analysis is active. Handoff preview and export are unavailable."
            )
        return analysis

    def _display_error(self, exc: Exception, *, action: str) -> None:
        if isinstance(exc, InvestigationChangedDuringHandoffError):
            self.output(
                "The investigation changed during handoff creation. No final handoff "
                "was published. Refresh the investigation and export again."
            )
        elif isinstance(exc, HandoffProvenanceMismatchError):
            self.output(
                "The active completed analysis does not match this investigation. "
                "No handoff was created."
            )
        elif isinstance(exc, RequiredHandoffArtifactMissingError):
            self.output("A required analysis artifact is unavailable. No handoff was created.")
        elif isinstance(exc, UnsafeHandoffOutputPathError):
            self.output("The selected handoff output location is not safe or available.")
        elif isinstance(exc, UnsafeHandoffArtifactPathError):
            self.output("A referenced analysis artifact is not safe to export.")
        elif isinstance(exc, UnsupportedHandoffSchemaError):
            self.output("Handoff validation failed: unsupported schema version.")
        elif isinstance(exc, HandoffArtifactDigestMismatchError):
            self.output("Handoff validation failed: a file digest does not match.")
        elif isinstance(exc, HandoffReferenceIntegrityError):
            self.output("Handoff validation failed: an internal reference is invalid.")
        elif isinstance(exc, HandoffBundleValidationError):
            self.output("Handoff validation failed: the bundle is invalid or incomplete.")
        elif isinstance(exc, InvestigationRepositoryError):
            self.output(f"Handoff {action} is unavailable for this investigation.")
        else:
            self.output(f"Handoff {action} failed safely.")

    @staticmethod
    def _bounded(value: object, limit: int = 160) -> str:
        text = " ".join(str(value or "").split())
        return text if len(text) <= limit else text[: limit - 3] + "..."

    @staticmethod
    def _handoff_errors() -> tuple[type[Exception], ...]:
        return (HandoffError, InvestigationRepositoryError, ValueError)

    @staticmethod
    def _validation_errors() -> tuple[type[Exception], ...]:
        return (HandoffBundleValidationError, OSError, ValueError)
