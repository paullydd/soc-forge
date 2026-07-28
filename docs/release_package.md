# SOC-Forge Portfolio Release Package

This package is the recommended way to present SOC-Forge to reviewers, recruiters, mentors, or interview panels. It is designed to show both engineering depth and analyst workflow judgment.

## Release Snapshot

```text
Project: SOC-Forge
Version: 2.2.0
Primary demo: Local analyst web UI guided demo
Secondary demo: Terminal analyst console investigation workflow
Test status: pytest -q
Sample artifacts: samples/attack_chain_demo/
Screenshots: docs/screenshots/
```

## What To Show First

Start with the web UI. It is the cleanest visual demo and tells the story quickly:

```bash
cd /home/pauly/projects/soc-forge
source .venv/bin/activate
python -m soc_forge.web.app --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

Then use:

```text
Detection Lab -> Start Demo
```

The guided path walks through:

```text
Generate -> Dashboard -> Case -> Graph -> Scorecard -> Report
```

## Reviewer Checklist

A reviewer should be able to confirm:

- The project runs locally from a Python virtual environment
- Demo scenarios can generate repeatable security events
- YAML rules produce alerts with MITRE ATT&CK context
- Correlation turns related alerts into cases
- Cases include risk, quality, findings, evidence, containment guidance, entities, and timelines
- The graph highlights the primary investigation path and relationship evidence
- The scorecard makes detection engineering quality visible
- HTML and JSON artifacts are generated for review
- Tests cover the major workflows

## Screenshots To Include

The current screenshot folder contains:

```text
docs/screenshots/web-overview.png
docs/screenshots/case-detail.png
docs/screenshots/entity-relationship-explorer.png
docs/screenshots/html-report.png
```

Recommended next screenshots after this release:

```text
docs/screenshots/web-graph.png
docs/screenshots/detection-scorecard.png
docs/screenshots/guided-demo.png
```

## Strong Demo Script

Use this concise narrative:

```text
SOC-Forge starts with raw security events or a guided demo scenario, runs them through one shared analysis pipeline, applies MITRE-mapped YAML detections plus legacy compatibility detection, correlates related alerts into cases, reconstructs the activity path, scores the case, and produces analyst-ready web, terminal, JSON, and HTML outputs.
```

Then show:

1. `Start Demo` in the web UI
2. Dashboard triage summary
3. Highest-risk case and case quality brief
4. Graph primary path and relationship evidence
5. Detection Engineering Scorecard
6. HTML report
7. `pytest -q` test result

## Files That Matter Most

```text
soc_forge/pipeline.py            Shared analysis pipeline used by CLI and web demos
soc_forge/rules/                 Detection content
soc_forge/rules/quality.py       Rule quality gate
soc_forge/correlate/rules.py     Correlation logic
soc_forge/cases/builder.py       Case construction
soc_forge/report/html_report.py  HTML report generation
soc_forge/web/app.py             Local web API and scenario runner
soc_forge/web/static/            Web UI
soc_forge/core/investigation_graph.py  Graph model
samples/attack_chain_demo/       Reviewable sample output
```

## Release Commands

Run the main checks before sharing:

```bash
source .venv/bin/activate
python -m soc_forge.cli --rule-quality
pytest -q
```

Generate fresh demo output:

```bash
python -m soc_forge.cli --simulate detection_lab --sim-output out/detection_lab_events.jsonl
python -m soc_forge.cli --input out/detection_lab_events.jsonl --out out/alerts.json --html out/report.html
```

Start the web UI:

```bash
python -m soc_forge.web.app --port 8765
```

## Positioning

SOC-Forge is best described as a compact local SOC investigation platform and detection engineering portfolio project. It is not trying to replace a SIEM or operate as a hosted multi-user product. The guided web demo is the primary portfolio experience, the terminal analyst console is an optional deep-dive interface, and the CLI is the automation, simulation, coverage, and detection-engineering interface.

## Local Safety

The web server binds to `127.0.0.1` by default and does not include authentication. If it is explicitly bound to a non-loopback host, SOC-Forge prints a warning because the local API and generated artifacts may expose investigation data. Review and redact generated HTML and JSON artifacts before sharing them.

## Future Work

These ideas are postponed future work, not current release capability:

- Custom JSONL and CSV dataset loading in the web UI
- Saved notes and closure workflow in the web UI
- Exportable graph images and additional case bundle formats
- Cloud identity and SaaS audit-log detection packs
- Per-rule false-positive notes, severity rationale, and data-source requirements
