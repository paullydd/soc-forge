from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from query_fixtures import build_query_analysis, build_query_investigation
from soc_forge.investigations.handoff import (
    InvestigationHandoffService,
    validate_handoff_bundle,
)
from soc_forge.investigations.handoff_console import (
    InvestigationHandoffConsoleController,
)
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.investigations.workspace_service import WorkspaceResult
from soc_forge.ui.terminal import strip_ansi


class ScriptedInput:
    def __init__(self, values=()):
        self.values = iter(values)
        self.prompts = []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        return next(self.values)


def hashes(paths):
    return {key: sha256(path.read_bytes()).hexdigest() for key, path in paths.items()}


def repository_bytes(root):
    return {
        path.name: path.read_bytes()
        for path in (root / "investigations").glob("*.json")
    }


def build_console(tmp_path, inputs=(), *, analysis=True, before_finalize=None):
    analysis_result = build_query_analysis(tmp_path / "analysis")
    investigation = build_query_investigation(analysis_result)
    workspace_root = tmp_path / "workspace"
    repository = InvestigationRepository(workspace_root)
    repository.save(investigation)
    messages = []
    screens = []
    scripted = ScriptedInput(inputs)
    controller = InvestigationHandoffConsoleController(
        handoff_service=InvestigationHandoffService(
            repository,
            before_finalize=before_finalize,
        ),
        analysis_provider=lambda: analysis_result if analysis else None,
        input_func=scripted,
        output_func=messages.append,
        screen_func=screens.append,
        pause_func=lambda: None,
        default_output_root=tmp_path / "handoffs",
    )
    current = WorkspaceResult(investigation, 1)
    return (
        controller,
        current,
        analysis_result,
        repository,
        workspace_root,
        messages,
        screens,
        scripted,
    )


@pytest.mark.parametrize(
    ("choice", "method"),
    [(" 1 ", "preview_flow"), ("2", "export_flow"), ("3", "validation_flow"), ("4", "view_last_result")],
)
def test_handoff_menu_is_read_only_dispatches_once_and_preserves_back(
    tmp_path, choice, method
):
    controller, current, *_rest = build_console(tmp_path, [choice, "0"])
    calls = []
    setattr(controller, method, lambda *args: calls.append(args))

    assert controller.run(current) == current
    assert calls and len(calls) == 1
    assert any("Read-only snapshot/export workflow" in item for item in _rest[3])


def test_handoff_menu_invalid_input_rerenders_without_extra_pause(tmp_path):
    controller, current, *_rest = build_console(tmp_path, ["bad", "0"])
    pauses = []
    controller.pause = lambda: pauses.append("pause")
    assert controller.run(current) == current
    assert "Invalid option." in _rest[3]
    assert pauses == []


def test_preview_is_bounded_complete_and_writes_nothing(tmp_path):
    (
        controller,
        current,
        analysis,
        repository,
        workspace_root,
        messages,
        *_rest,
    ) = build_console(tmp_path)
    repo_before = repository_bytes(workspace_root)
    artifacts_before = hashes(analysis.artifacts)

    preview = controller.preview_flow(current)

    assert preview is not None
    assert preview.revision == 1
    assert preview.selected_case_count == 1
    assert preview.analyst_evidence_count == 3
    assert preview.hypothesis_count == 1
    assert preview.decision_count == 3
    assert preview.annotation_count == 1
    assert preview.timed_entry_count > 0
    assert preview.untimed_entry_count > 0
    assert preview.required_artifacts_available
    assert set(preview.available_artifact_keys) == set(analysis.artifacts)
    assert not (tmp_path / "handoffs").exists()
    assert repository_bytes(workspace_root) == repo_before
    assert repository.load_record("INV-QUERY").revision == 1
    assert hashes(analysis.artifacts) == artifacts_before
    assert any("Terminal scrollback" in item for item in messages)
    assert not any("powershell.exe -enc sensitive" in item for item in messages)


def test_preview_handles_missing_and_mismatched_active_analysis(tmp_path):
    controller, current, *_rest = build_console(tmp_path / "missing", analysis=False)
    before = next(_rest[1].investigations_root.glob("*.json")).read_bytes()
    preview = controller.preview_flow(current)
    assert preview is not None
    assert preview.mode == "offline"
    assert preview.source_analysis_available is False
    assert any("OFFLINE handoff" in item for item in _rest[3])
    assert next(_rest[1].investigations_root.glob("*.json")).read_bytes() == before

    controller, current, analysis, *_rest = build_console(tmp_path / "mismatch")
    analysis.events[0]["host"] = "OTHER-HOST"
    assert controller.preview_flow(current) is None
    assert any("does not match" in item for item in _rest[2])


def test_export_requires_warning_acknowledgement_and_cancel_writes_nothing(tmp_path):
    controller, current, *_rest = build_console(tmp_path, [""])
    assert controller.export_flow(current) is None
    assert not (tmp_path / "handoffs").exists()
    assert any("SENSITIVE DATA WARNING" in item for item in _rest[3])
    assert any("Automatic redaction is not provided" in item for item in _rest[3])


@pytest.mark.parametrize("custom", [False, True])
def test_export_default_and_custom_roots_display_result_without_mutation(tmp_path, custom):
    chosen = tmp_path / "custom-handoffs"
    inputs = ["yes", str(chosen) if custom else ""]
    (
        controller,
        current,
        analysis,
        repository,
        workspace_root,
        messages,
        *_rest,
    ) = build_console(tmp_path, inputs)
    repo_before = repository_bytes(workspace_root)
    artifacts_before = hashes(analysis.artifacts)
    analysis_before = deepcopy(analysis)

    result = controller.export_flow(current)

    assert result is not None
    expected_root = chosen if custom else tmp_path / "handoffs"
    assert result.output_path == expected_root / "INV-QUERY"
    assert result.manifest_path.is_file()
    assert validate_handoff_bundle(result.output_path)
    assert controller.last_result == result
    assert any(result.handoff_id in item for item in messages)
    output = strip_ansi("\n".join(messages))
    assert "Revision" in output and "1" in output
    assert "Manifest path" in output
    assert "[VALID]" in output
    assert "Investigation state was not modified." in output
    assert repository_bytes(workspace_root) == repo_before
    assert repository.load_record("INV-QUERY").revision == 1
    assert analysis == analysis_before
    assert hashes(analysis.artifacts) == artifacts_before


def test_existing_target_cancel_preserves_bundle_and_explicit_overwrite_restores_validity(tmp_path):
    controller, current, analysis, _repository, _workspace, messages, *_ = build_console(
        tmp_path, ["yes", ""]
    )
    first = controller.export_flow(current)
    before = {
        path.relative_to(first.output_path).as_posix(): path.read_bytes()
        for path in first.output_path.rglob("*") if path.is_file()
    }

    controller.input = ScriptedInput(["yes", "", "1"])
    assert controller.export_flow(current) is None
    after_cancel = {
        path.relative_to(first.output_path).as_posix(): path.read_bytes()
        for path in first.output_path.rglob("*") if path.is_file()
    }
    assert after_cancel == before
    assert any("Existing bundle was preserved" in item for item in messages)

    copied = first.output_path / "source_artifacts" / "alerts.json"
    copied.write_text("tampered", encoding="utf-8")
    with pytest.raises(Exception):
        validate_handoff_bundle(first.output_path)
    controller.input = ScriptedInput(["yes", "", "3", "yes"])
    replacement = controller.export_flow(current)
    assert replacement is not None
    assert validate_handoff_bundle(replacement.output_path)
    assert copied.read_bytes() == analysis.artifacts["alerts"].read_bytes()
    assert any("fully staged and validated" in item for item in messages)


def test_existing_target_can_choose_another_root(tmp_path):
    controller, current, *_ = build_console(tmp_path, ["yes", ""])
    controller.export_flow(current)
    other = tmp_path / "other"
    controller.input = ScriptedInput(["yes", "", "2", str(other)])
    result = controller.export_flow(current)
    assert result.output_path == other / "INV-QUERY"


def test_manifest_inspection_is_bounded_safe_and_uses_last_session_result(tmp_path):
    controller, current, analysis, *_rest = build_console(tmp_path, ["yes", ""])
    result = controller.export_flow(current)
    summary = controller.view_last_result()
    messages = _rest[2]

    assert summary.handoff_id == result.handoff_id
    output = strip_ansi("\n".join(messages))
    assert "File inventory:" in output
    assert "SHA-256" in output
    assert "Sensitive data notice:" in output
    assert str(analysis.output_dir) not in output
    assert "powershell.exe -enc sensitive" not in output


def test_validation_works_without_active_analysis_and_tamper_is_read_only(tmp_path):
    controller, current, analysis, repository, workspace_root, *_ = build_console(
        tmp_path, ["yes", ""]
    )
    result = controller.export_flow(current)
    repo_before = repository_bytes(workspace_root)
    artifact_before = hashes(analysis.artifacts)
    bundle_before = {
        path.relative_to(result.output_path).as_posix(): path.read_bytes()
        for path in result.output_path.rglob("*") if path.is_file()
    }

    controller.analysis_provider = lambda: None
    controller.input = ScriptedInput([str(result.output_path)])
    assert controller.validation_flow().handoff_id == result.handoff_id

    target = result.output_path / "evidence_index.json"
    target.write_text("{}\n", encoding="utf-8")
    tampered_before = target.read_bytes()
    controller.input = ScriptedInput([str(result.output_path)])
    assert controller.validation_flow() is None
    assert target.read_bytes() == tampered_before
    assert repository_bytes(workspace_root) == repo_before
    assert repository.load_record("INV-QUERY").revision == 1
    assert hashes(analysis.artifacts) == artifact_before
    assert bundle_before["manifest.json"] == (result.output_path / "manifest.json").read_bytes()


def test_revision_conflict_is_concise_not_retried_and_publishes_nothing(tmp_path):
    holder = {}

    def change_revision():
        repository = holder["repository"]
        investigation = holder["investigation"]
        updated = replace(
            investigation,
            metadata=replace(investigation.metadata, updated_at="2026-08-10T17:00:00Z"),
        )
        repository.save(updated, expected_revision=1)

    data = build_console(tmp_path, ["yes", ""], before_finalize=change_revision)
    controller, current, _analysis, repository, _workspace, messages, *_ = data
    holder.update(repository=repository, investigation=current.investigation)

    assert controller.export_flow(current) is None
    assert not (tmp_path / "handoffs" / "INV-QUERY").exists()
    assert repository.load_record("INV-QUERY").revision == 2
    assert sum("investigation changed during handoff creation" in item for item in messages) == 1
    assert any("No final handoff was published" in item for item in messages)
    assert controller.last_result is None


def test_console_source_only_presents_shared_handoff_operations():
    source_path = Path("soc_forge/investigations/handoff_console.py")
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "InvestigationHandoffService" in source
    assert "validate_handoff_bundle" in source
    assert "read_handoff_manifest" in source
    assert {"json", "hashlib", "shutil"}.isdisjoint(imports)
    assert {"write_text", "write_bytes", "unlink", "rmtree", "copyfile"}.isdisjoint(attributes)
    assert "run_analysis" not in source
