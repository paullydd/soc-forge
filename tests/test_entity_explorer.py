from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from soc_forge.entity_explorer import (
    EntityExplorerService, EntityObservationService,
)
from soc_forge.investigations.evidence_catalog import AnalysisEvidenceCatalog
from soc_forge.investigations.models import (
    EvidenceReference, InvestigationFinding, ResponseAction,
)
from soc_forge.investigations.query_context import normalize_entity
from soc_forge.investigations.repository import InvestigationRepository
from soc_forge.menus.entity_explorer import (
    EntityExplorerConsoleController, render_entity_result, render_entity_type_menu,
)
from soc_forge.pipeline import AnalysisResult
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_investigation_repository import build_investigation


def _analysis():
    event = {
        "event_id": 4625, "timestamp": "2026-08-20T10:00:00Z",
        "host": "WIN-ENDPOINT-01", "username": "DOMAIN\\paul",
        "src_ip": "192.0.2.10", "process_name": r"C:\Windows\PowerShell.EXE",
        "message": "Structured event",
    }
    alert = {
        "rule_id": "SOCF-010", "title": "Password spray",
        "timestamp": "2026-08-20T11:00:00Z",
        "details": {
            "host": "win-endpoint-01", "username": "DOMAIN\\paul",
            "ip": "192.0.2.10", "process_name": "powershell.exe",
        },
        "mitre": [{"tactic": "Credential Access",
                   "technique_id": "T1110.003",
                   "technique": "Password Spraying"}],
    }
    return AnalysisResult(
        "events.jsonl", None, Path("out"), None, None, None, None, None, None,
        1, [event], [alert], [], [alert], {}, [], {}, [], [], [], {}, [], 1,
    )


def _service(tmp_path, analysis=None):
    repository = InvestigationRepository(tmp_path / "workspace")
    provider = (lambda: analysis) if analysis is not None else (lambda: None)
    return repository, EntityExplorerService(
        EntityObservationService(repository, provider)
    )


@pytest.mark.parametrize(("kind", "left", "right", "normalized"), [
    ("host", " WIN-ENDPOINT-01 ", "win-endpoint-01", "win-endpoint-01"),
    ("user", "DOMAIN\\Paul", "domain\\paul", "domain\\paul"),
    ("ip", "2001:0db8::1", "2001:db8::1", "2001:db8::1"),
    ("process", r"C:\Windows\PowerShell.EXE", "powershell.exe", "powershell.exe"),
])
def test_controlled_normalization(kind, left, right, normalized):
    assert normalize_entity(kind, left).normalized_value == normalized
    assert normalize_entity(kind, right).normalized_value == normalized


def test_account_formats_remain_distinct_and_no_fuzzy_merging():
    values = [
        normalize_entity("user", value).normalized_value
        for value in ("DOMAIN\\paul", "paul", "paul@example.com")
    ]
    assert len(set(values)) == 3
    assert normalize_entity("host", "server-01").normalized_value != "server01"


def test_full_machine_observations_counts_related_entities_and_attack(tmp_path):
    _repository, service = _service(tmp_path, _analysis())
    result = service.search("host", "WIN-ENDPOINT-01")
    assert result.mode == "full"
    assert result.observation_count == 2
    assert result.alert_count == 1
    assert result.investigation_count == result.finding_count == 0
    assert [row.origin for row in result.observations] == ["machine", "machine"]
    assert result.observations[0].source_type == "alert"
    assert result.attack_tactics[0].value == "Credential Access"
    assert result.attack_techniques[0].value == "T1110.003 - Password Spraying"
    related = {(row.entity_type, row.normalized_value): row.observation_count
               for row in result.related_entities}
    assert related[("user", "domain\\paul")] == 2
    assert related[("ip", "192.0.2.10")] == 2
    assert related[("process", "powershell.exe")] == 2


def test_exact_search_handles_each_supported_type(tmp_path):
    _repository, service = _service(tmp_path, _analysis())
    for kind, value in (
        ("host", "win-endpoint-01"), ("user", "DOMAIN\\paul"),
        ("ip", "192.0.2.10"), ("process", "powershell.exe"),
    ):
        assert service.search(kind, value).observation_count == 2
    assert service.search("user", "paul").observation_count == 0


def test_offline_is_honest_and_does_not_invent_from_durable_ids_or_prose(tmp_path):
    repository, service = _service(tmp_path)
    investigation = replace(
        build_investigation("INV-1"),
        metadata=replace(build_investigation("INV-1").metadata,
                         title="WIN-ENDPOINT-01 mentioned in prose"),
    )
    repository.save(investigation)
    result = service.search("host", "WIN-ENDPOINT-01")
    assert result.mode == "offline"
    assert result.observation_count == 0
    assert result.investigation_count == 0


def test_selected_evidence_finding_and_action_are_explicit_analyst_observations(tmp_path):
    analysis = _analysis()
    repository, service = _service(tmp_path, analysis)
    catalog = AnalysisEvidenceCatalog()
    candidate = next(row for row in catalog.list_candidates(analysis)
                     if row.evidence_type == "event")
    reference = EvidenceReference(
        reference_id=candidate.evidence_id, source_type="event",
        source_id=candidate.source_id, origin="analyst_selection",
        classification="supporting", rationale="Structured evidence.",
        selected_by="analyst", selected_at="2026-08-20T12:00:00Z",
        source_analysis_id=candidate.source_analysis_id, evidence_type="event",
    )
    finding = InvestigationFinding(
        "FIND-1", "INV-1", "Structured host Finding", "Supported.",
        "substantiated", "high", "analyst", "2026-08-20T12:00:00Z",
        "2026-08-20T13:00:00Z", evidence_ids=(candidate.evidence_id,),
        attack_tactics=("Credential Access",),
    )
    action = ResponseAction(
        "ACT-1", "INV-1", ("FIND-1",), "Review host", "Review it.",
        "host_action", "high", "proposed", "Explicit Finding link.",
        "analyst", "analyst", "2026-08-20T13:00:00Z",
        "2026-08-20T13:00:00Z",
    )
    base = build_investigation("INV-1")
    repository.save(replace(
        base, analysis_id=candidate.source_analysis_id,
        evidence_references=base.evidence_references + (reference,),
        findings=(finding,), response_actions=(action,), handoff_manifest=None,
    ))
    result = service.search("host", "win-endpoint-01")
    assert result.investigation_ids == ("INV-1",)
    assert result.finding_count == result.response_action_count == 1
    assert {row.source_type for row in result.observations} >= {
        "event", "evidence", "finding", "response_action"
    }
    assert any(row.origin == "analyst" for row in result.observations)


def test_sensitive_structured_field_is_not_projected(tmp_path, monkeypatch):
    analysis = _analysis()
    catalog = AnalysisEvidenceCatalog()
    original = catalog.resolve_details
    def sensitive_details(current, evidence_id):
        details = original(current, evidence_id)
        fields = tuple(replace(field, sensitive=True)
                       if field.field_name == "process" else field
                       for field in details.fields)
        return replace(details, fields=fields)
    monkeypatch.setattr(catalog, "resolve_details", sensitive_details)
    repository = InvestigationRepository(tmp_path / "workspace")
    service = EntityExplorerService(EntityObservationService(
        repository, lambda: analysis, catalog=catalog
    ))
    assert service.search("user", "paul").observation_count == 0


def test_projection_is_deterministic_bounded_immutable_and_read_only(tmp_path):
    analysis = _analysis()
    before = deepcopy(analysis)
    repository, _service_default = _service(tmp_path, analysis)
    base = build_investigation("INV-1")
    repository.save(base)
    record = repository.investigations_root / "INV-1.json"
    before_bytes = record.read_bytes()
    service = EntityExplorerService(
        EntityObservationService(repository, lambda: analysis),
        observation_limit=1,
    )
    first = service.search("host", "win-endpoint-01")
    assert first == service.search("host", "win-endpoint-01")
    assert len(first.observations) == 1
    with pytest.raises(FrozenInstanceError):
        first.mode = "offline"
    assert record.read_bytes() == before_bytes
    assert repository.load_record("INV-1").revision == 1
    assert analysis == before
    assert analysis.artifacts == before.artifacts


def test_no_mapping_is_inferred_from_entity_or_detection_coverage(tmp_path):
    analysis = _analysis()
    analysis.alerts[0]["mitre"] = []
    _repository, service = _service(tmp_path, analysis)
    result = service.search("host", "win-endpoint-01")
    assert result.attack_tactics == result.attack_techniques == ()


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_terminal_result_width_color_sections_and_warning(tmp_path, width, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _repository, service = _service(tmp_path, _analysis())
    rendered = render_entity_result(service.search("host", "WIN-ENDPOINT-01"),
                                    width=width)
    assert all(len(line) <= resolve_terminal_width(width)
               for line in rendered.splitlines())
    assert strip_ansi(rendered) == rendered
    assert "ENTITY" in rendered
    if width >= 80:
        assert "ENTITY EXPLORER" in rendered
        assert "ATT&CK ACTIVITY" in rendered
        assert "RELATED ENTITIES" in rendered
        assert "RECENT OBSERVATIONS" in rendered
        assert "shared attacker or campaign" in rendered


def test_empty_state_and_type_menu():
    repository = InvestigationRepository(Path("/tmp/nonexistent-entity-test"))
    result = EntityExplorerService(EntityObservationService(repository)).search(
        "host", "absent"
    )
    assert "No observations found for this entity." in render_entity_result(
        result, ansi=False
    )
    menu = render_entity_type_menu(ansi=False)
    assert all(label in menu for label in ("Host", "User", "IP Address", "Process"))


def test_controller_search_and_back_flow(tmp_path):
    _repository, service = _service(tmp_path, _analysis())
    inputs = iter(("1", "WIN-ENDPOINT-01", "", "0"))
    output = []
    EntityExplorerConsoleController(
        service, input_func=lambda _prompt="": next(inputs),
        output_func=output.append,
    ).run()
    assert any("RECENT OBSERVATIONS" in item for item in output)


def test_analysis_option_two_dispatches_real_controller(monkeypatch):
    from soc_forge.menus import analysis
    calls = []
    choices = iter(("2", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("entity")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analysis, "begin_screen", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_group", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_option", lambda *_args: None)
    analysis.analysis_menu(lambda: None, lambda: None, lambda: None, None, controller)
    assert calls == ["entity"]
