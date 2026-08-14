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
from soc_forge.investigations.timeline_handoff_view import (
    render_handoff_manifest,
    render_handoff_preview,
    render_handoff_result,
    render_handoff_workspace,
)
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
            for line in render_handoff_workspace(
                current,
                source_available=self.analysis_provider() is not None,
                last_result=self.last_result,
            ).splitlines():
                self.output(line)
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
        analysis = self.analysis_provider()
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
        analysis = self.analysis_provider()
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
        analysis: object | None,
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
        analysis: object | None,
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
        for line in render_handoff_manifest(summary, validation=True).splitlines():
            self.output(line)
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
        for line in render_handoff_preview(preview).splitlines():
            self.output(line)

    def render_result(self, result: HandoffResult) -> None:
        for line in render_handoff_result(result).splitlines():
            self.output(line)

    def render_manifest(self, summary: HandoffManifestSummary) -> None:
        self.screen("HANDOFF MANIFEST")
        for line in render_handoff_manifest(summary).splitlines():
            self.output(line)

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
    def _handoff_errors() -> tuple[type[Exception], ...]:
        return (HandoffError, InvestigationRepositoryError, ValueError)

    @staticmethod
    def _validation_errors() -> tuple[type[Exception], ...]:
        return (HandoffBundleValidationError, OSError, ValueError)
