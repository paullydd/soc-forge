from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from soc_forge.attack_activity import AttackActivityService
from soc_forge.investigations.operational_summary import OperationalSummaryService
from soc_forge.investigations.operations_prioritization import OperationsPrioritizationService
from soc_forge.investigations.operations_queue import OperationsQueueService
from soc_forge.menus.reporting import (
    ReportingConsoleController, render_executive_summary,
    render_export_center, render_investigation_report,
    render_report_artifact, render_report_center,
)
from soc_forge.reporting import (
    ExecutiveSummaryService, InvestigationReportService, ReportCenterService,
)
from soc_forge.threat_activity import ThreatActivityOverviewService
from soc_forge.ui.terminal import resolve_terminal_width, strip_ansi
from test_temporal_analysis import analysis, repository


def services(tmp_path, *, full=False):
    repo = repository(tmp_path, ("INV-1",))
    provider = analysis if full else (lambda: None)
    operational = OperationalSummaryService(
        OperationsPrioritizationService(OperationsQueueService(repo))
    )
    return (
        repo,
        InvestigationReportService(repo, provider),
        ExecutiveSummaryService(
            operational, ThreatActivityOverviewService(repo, provider),
            AttackActivityService(repo, provider),
        ),
        operational,
    )


def test_report_center_known_discovery_order_path_and_no_creation(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.html").write_text("report", encoding="utf-8")
    (out / "password_spray_report.html").write_text("spray", encoding="utf-8")
    (out / "unrelated.html").write_text("ignore", encoding="utf-8")
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    rows = ReportCenterService(out).list_reports()
    assert [row.filename for row in rows] == [
        "password_spray_report.html", "report.html"
    ]
    assert all(Path(row.path).is_absolute() for row in rows)
    assert {path.name: path.read_bytes() for path in out.iterdir()} == before


def test_report_center_empty_and_artifact_render(tmp_path):
    assert ReportCenterService(tmp_path).list_reports() == ()
    out = tmp_path / "out"
    out.mkdir()
    path = out / "report.html"
    path.write_text("x", encoding="utf-8")
    row = ReportCenterService(out).list_reports()[0]
    assert "No existing Analysis Reports" in render_report_center((), ansi=False)
    rendered = render_report_artifact(row, ansi=False)
    assert "REPORT ARTIFACT" in rendered and "report.html" in rendered
    assert row.path == str(path.resolve())


def test_investigation_report_durable_content_offline_and_deterministic(tmp_path):
    repo, reports, _executive, _operational = services(tmp_path)
    before = (repo.investigations_root / "INV-1.json").read_bytes()
    report = reports.build("INV-1")
    assert report == reports.build("INV-1")
    assert report.mode == "offline" and report.revision == 1
    assert len(report.active_findings) == 1
    assert report.historical_findings == ()
    assert report.evidence_count == 1
    assert report.hypotheses and report.decisions
    assert len(report.response_actions[0].transition_history) == 3
    assert report.attack_tactics == ("Discovery",)
    rendered = render_investigation_report(report, ansi=False)
    assert "ANALYST ASSESSMENT" in rendered
    assert "Transitions: 3" in rendered
    assert "Protected evidence values are not revealed" in rendered
    assert "command_line" not in rendered
    assert (repo.investigations_root / "INV-1.json").read_bytes() == before
    with pytest.raises(FrozenInstanceError):
        report.mode = "full"


def test_investigation_report_full_only_changes_source_availability(tmp_path):
    _repo, reports, _executive, _operational = services(tmp_path, full=True)
    report = reports.build("INV-1")
    assert report.mode == "full"
    assert report.source_analysis_available


def test_executive_summary_reuses_operations_top_attention_and_attack(tmp_path):
    repo, _reports, executive, operational = services(tmp_path)
    before = (repo.investigations_root / "INV-1.json").read_bytes()
    expected = operational.summarize()
    summary = executive.summarize()
    assert summary.mode == "offline"
    assert summary.investigation_count == 1
    assert summary.active_findings == 1
    assert summary.historical_findings == 0
    assert summary.open_response_actions == 0
    assert summary.attention_items == expected.total_attention_items
    assert summary.top_attention == expected.top_item
    assert summary.observed_attack_tactics[0].tactic == "Discovery"
    assert not summary.machine_context_available
    rendered = render_executive_summary(summary, ansi=False)
    assert "TOP ATTENTION" in rendered and "OBSERVED ATT&CK" in rendered
    assert (repo.investigations_root / "INV-1.json").read_bytes() == before


def test_executive_full_and_empty_state(tmp_path):
    _repo, _reports, full, _operational = services(tmp_path / "full", full=True)
    assert full.summarize().machine_context_available
    from soc_forge.investigations.repository import InvestigationRepository
    empty_repo = InvestigationRepository(tmp_path / "empty")
    operational = OperationalSummaryService(OperationsPrioritizationService(
        OperationsQueueService(empty_repo)
    ))
    empty = ExecutiveSummaryService(
        operational, ThreatActivityOverviewService(empty_repo),
        AttackActivityService(empty_repo),
    ).summarize()
    rendered = render_executive_summary(empty, ansi=False)
    assert empty.investigation_count == empty.attention_items == 0
    assert "Top Attention: None" in rendered
    assert "No observed ATT&CK activity." in rendered


@pytest.mark.parametrize("width", (100, 80, 60, 24))
def test_reporting_views_width_color_ascii_and_sensitive_notice(
    tmp_path, width, monkeypatch
):
    _repo, reports, executive, _operational = services(tmp_path)
    report = reports.build("INV-1")
    summary = executive.summarize()
    monkeypatch.setenv("NO_COLOR", "1")
    views = (
        render_investigation_report(report, width=width),
        render_executive_summary(summary, width=width),
        render_export_center(width=width),
        render_export_center(width=width, ansi=False, unicode=False),
    )
    for rendered in views:
        assert strip_ansi(rendered) == rendered
        assert all(len(line) <= resolve_terminal_width(width)
                   for line in rendered.splitlines())
    if width >= 80:
        joined = "\n".join(views)
        assert "Reports may contain sensitive" in joined
        assert "sharing." in joined
        assert "Handoff remains authoritative" in joined


def test_controller_report_opener_and_export_handoff_instruction(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.html").write_text("x", encoding="utf-8")
    _repo, reports, executive, _operational = services(tmp_path / "state")
    opened, output = [], []
    controller = ReportingConsoleController(
        ReportCenterService(out), reports, executive, opened.append,
        input_func=lambda _prompt="": "1", output_func=output.append,
    )
    controller.report_center_run()
    assert opened == [str((out / "report.html").resolve())]
    inputs = iter(("1", ""))
    controller.input_func = lambda _prompt="": next(inputs)
    controller.export_run()
    assert "Investigation Workspaces > Handoff" in "\n".join(output)
    assert "ATT&CK Coverage" not in render_export_center(ansi=False)
