from copy import deepcopy
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from soc_forge.attack_activity import AttackActivityObservation
from soc_forge.cross_investigation import (
    CAUTION, CrossInvestigationAnalysisService,
)
from soc_forge.entity_explorer import (
    EntityObservation, ObservedEntity,
)
from soc_forge.investigations.query_context import normalize_entity
from soc_forge.menus.cross_investigation import (
    CrossInvestigationConsoleController, render_cross_investigation_menu,
    render_overview, render_relationship_detail, render_relationship_index,
    render_relationships,
)
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi


class EntitySource:
    def __init__(self, mode, rows):
        self.mode, self.rows = mode, tuple(rows)

    def list_observations(self):
        return self.mode, self.rows


class AttackSource:
    def __init__(self, mode, rows):
        self.mode, self.rows = mode, tuple(rows)

    def summarize(self):
        return SimpleNamespace(mode=self.mode, observations=self.rows)


def entity(kind, value, investigation, source, *, origin="analyst",
           timestamp="2026-08-21T10:00:00Z"):
    normalized = normalize_entity(kind, value)
    observed = ObservedEntity(
        kind, normalized.display_value, normalized.normalized_value,
        normalized.secondary_key,
    )
    return EntityObservation(
        kind, observed.display_value, observed.normalized_value,
        "evidence", source, investigation, timestamp, source, (), (),
        (observed,), origin,
    )


def attack(investigation, source, *, tactic=None, technique_id=None,
           technique_name=None, attribution="analyst"):
    return AttackActivityObservation(
        tactic, technique_id, technique_name, "finding", source, investigation,
        "2026-08-21T11:00:00Z", attribution, source,
    )


def service(entity_rows=(), attack_rows=(), *, entity_mode="offline",
            attack_mode="offline", recent_limit=10):
    return CrossInvestigationAnalysisService(
        EntitySource(entity_mode, entity_rows),
        AttackSource(attack_mode, attack_rows),
        recent_limit=recent_limit,
    )


@pytest.mark.parametrize(("kind", "left", "right"), (
    ("host", "WIN-ENDPOINT-01", "win-endpoint-01"),
    ("user", "DOMAIN\\Paul", "domain\\paul"),
    ("ip", "2001:0db8::1", "2001:db8::1"),
    ("process", r"C:\\Windows\\PowerShell.EXE", "powershell.exe"),
))
def test_exact_entity_normalization_is_reused_across_investigations(
    kind, left, right
):
    summary = service((
        entity(kind, left, "INV-1", "SRC-1"),
        entity(kind, right, "INV-2", "SRC-2"),
    )).summarize()
    relationship = summary.relationships[0]
    assert relationship.relationship_type == "shared_entity"
    assert relationship.entity_type == kind
    assert relationship.investigation_ids == ("INV-1", "INV-2")
    assert relationship.relationship_id.startswith(f"XINV:ENTITY:{kind}:")


def test_one_investigation_repetition_and_fuzzy_values_are_excluded():
    summary = service((
        entity("host", "server-01", "INV-1", "SRC-1"),
        entity("host", "server-01", "INV-1", "SRC-2"),
        entity("host", "server01", "INV-2", "SRC-3"),
    )).summarize()
    assert summary.relationships == ()


def test_shared_tactic_and_technique_use_explicit_attack_observations_only():
    rows = (
        attack("INV-1", "FIND-1", tactic="Credential Access",
               technique_id="T1110.003", technique_name="Password Spraying"),
        attack("INV-2", "FIND-2", tactic="Credential Access",
               technique_id="T1110.003", technique_name="Password Spraying"),
    )
    summary = service(attack_rows=rows).summarize()
    assert summary.shared_tactic_count == summary.shared_technique_count == 1
    ids = {row.relationship_id for row in summary.relationships}
    assert ids == {
        "XINV:ATTACK:TACTIC:credential-access",
        "XINV:ATTACK:TECHNIQUE:T1110.003",
    }


def test_counts_attribution_sources_membership_and_no_double_counting():
    duplicate = attack(
        "INV-1", "SRC-1", tactic="Discovery", attribution="machine"
    )
    summary = service(attack_rows=(
        duplicate, duplicate,
        attack("INV-2", "SRC-2", tactic="Discovery", attribution="analyst"),
        attack("INV-3", "SRC-3", tactic="Discovery", attribution="machine"),
    ), attack_mode="full").summarize()
    relationship = summary.relationships[0]
    assert summary.mode == "full"
    assert summary.relationship_count == 1
    assert summary.investigation_count == 3
    assert relationship.observation_count == 3
    assert relationship.machine_observation_count == 2
    assert relationship.analyst_observation_count == 1
    assert relationship.source_ids == ("SRC-1", "SRC-2", "SRC-3")


def test_deterministic_order_identity_recent_bound_and_immutability():
    rows = (
        entity("host", "b-host", "INV-1", "B1"),
        entity("host", "b-host", "INV-2", "B2"),
        entity("host", "a-host", "INV-1", "A1"),
        entity("host", "a-host", "INV-2", "A2"),
        entity("host", "a-host", "INV-3", "A3"),
    )
    projection = service(rows, recent_limit=2)
    first = projection.summarize()
    assert first == projection.summarize()
    assert [row.display_value for row in first.relationships] == [
        "a-host", "b-host"
    ]
    assert len(first.relationships[0].recent_observations) == 2
    with pytest.raises(FrozenInstanceError):
        first.mode = "full"


def test_full_and_offline_are_explicit_and_unassigned_machine_rows_do_not_fabricate():
    machine = attack(None, "ALERT-1", tactic="Discovery", attribution="machine")
    durable = (
        attack("INV-1", "FIND-1", tactic="Discovery"),
        attack("INV-2", "FIND-2", tactic="Discovery"),
    )
    offline = service(attack_rows=durable).summarize()
    full = service(
        attack_rows=durable + (machine,), attack_mode="full"
    ).summarize()
    assert offline.mode == "offline"
    assert full.mode == "full"
    assert offline.relationships == full.relationships
    assert full.relationships[0].machine_observation_count == 0


def test_projection_does_not_mutate_sources():
    entities = [entity("host", "host-1", "INV-1", "E1"),
                entity("host", "host-1", "INV-2", "E2")]
    attacks = [attack("INV-1", "F1", tactic="Discovery"),
               attack("INV-2", "F2", tactic="Discovery")]
    before = deepcopy((entities, attacks))
    assert service(entities, attacks).summarize()
    assert (entities, attacks) == before


def test_empty_state_is_bounded_and_does_not_claim_unrelated():
    summary = service().summarize()
    rendered = render_overview(summary, ansi=False)
    assert "No shared structured observations were found" in rendered
    assert "current supported structured overlap rules" in " ".join(rendered.split())
    assert "unrelated" not in rendered.casefold()


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_terminal_views_are_width_safe_no_color_and_cautious(width, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    summary = service(
        (entity("host", "host-1", "INV-1", "E1"),
         entity("host", "host-1", "INV-2", "E2")),
        (attack("INV-1", "F1", tactic="Discovery",
                technique_id="T1087", technique_name="Account Discovery"),
         attack("INV-2", "F2", tactic="Discovery",
                technique_id="T1087", technique_name="Account Discovery")),
    ).summarize()
    views = (
        render_cross_investigation_menu(width=width),
        render_overview(summary, width=width),
        render_relationships(summary, "shared_entity", "SHARED ENTITIES",
                             width=width),
        render_relationships(summary, "shared_attack_tactic",
                             "SHARED ATT&CK TACTICS", width=width),
        render_relationships(summary, "shared_attack_technique",
                             "SHARED ATT&CK TECHNIQUES", width=width),
        render_relationship_index(summary, width=width),
        render_relationship_detail(summary.relationships[0], width=width),
    )
    for rendered in views:
        assert strip_ansi(rendered) == rendered
        assert all(len(line) <= resolve_terminal_width(width)
                   for line in rendered.splitlines())
    ascii_rendered = render_overview(
        summary, width=width, ansi=False, unicode=False
    )
    assert "+" in ascii_rendered
    assert all(len(line) <= resolve_terminal_width(width)
               for line in ascii_rendered.splitlines())
    monkeypatch.setenv("TERM", "dumb")
    dumb = render_overview(summary, width=width)
    assert strip_ansi(dumb) == dumb
    if width >= 80:
        joined = "\n".join(views)
        assert "[MACHINE]" in joined and "[ANALYST]" in joined
        assert "Shared observations do not establish" in joined
        assert "attacker, campaign, or cause." in joined


def test_controller_all_views_detail_and_back():
    projection = service((
        entity("host", "host-1", "INV-1", "E1"),
        entity("host", "host-1", "INV-2", "E2"),
    ), (
        attack("INV-1", "F1", tactic="Discovery", technique_id="T1087"),
        attack("INV-2", "F2", tactic="Discovery", technique_id="T1087"),
    ))
    inputs = iter(("1", "", "2", "", "3", "", "4", "", "5", "1", "", "0"))
    output = []
    CrossInvestigationConsoleController(
        projection, input_func=lambda _prompt="": next(inputs),
        output_func=output.append,
    ).run()
    joined = "\n".join(output)
    assert "CROSS-INVESTIGATION STATE" in joined
    assert "SHARED ENTITIES" in joined
    assert "SHARED ATT&CK TACTICS" in joined
    assert "SHARED ATT&CK TECHNIQUES" in joined
    assert "RELATIONSHIP DETAIL" in joined


def test_analysis_option_four_dispatches_real_controller(monkeypatch):
    from soc_forge.menus import analysis
    calls = []
    choices = iter(("4", "0"))
    controller = type("Controller", (), {"run": lambda self: calls.append("cross")})()
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(choices))
    monkeypatch.setattr(analysis, "begin_screen", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_group", lambda _title: None)
    monkeypatch.setattr(analysis, "menu_option", lambda *_args: None)
    analysis.analysis_menu(
        lambda: None, None, None, None, controller
    )
    assert calls == ["cross"]
