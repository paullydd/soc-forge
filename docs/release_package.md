# SOC-Forge Portfolio Release Package

This package is the recommended way to present SOC-Forge to reviewers, recruiters, mentors, or interview panels. It is designed to show both engineering depth and analyst workflow judgment.

## Release Snapshot

```text
Project: SOC-Forge
Version: 1.0.0
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
Dashboard -> Highest-risk case -> Investigation graph -> Detection scorecard -> HTML report
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
SOC-Forge starts with raw security events, normalizes them, applies MITRE-mapped YAML detections, correlates related alerts into cases, reconstructs the activity path, scores the case, and produces analyst-ready web, terminal, JSON, and HTML outputs.
```

Then show:

1. `Start Demo` in the web UI
2. Highest-risk case and case quality brief
3. Graph primary path and relationship evidence
4. Detection Engineering Scorecard
5. HTML report
6. `pytest -q` test result

## Files That Matter Most

```text
soc_forge/rules/                 Detection content
soc_forge/rules/quality.py       Rule quality gate
soc_forge/correlate/rules.py     Correlation logic
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

SOC-Forge is best described as a compact SOC investigation platform and detection engineering portfolio project. It is not trying to replace a SIEM. It demonstrates the engineering pieces behind alert generation, correlation, case quality, graph-based investigation, and analyst handoff.

## Next Release Ideas

- Web upload for custom JSONL and CSV event sets
- Saved notes and closure workflow in the web UI
- Exportable graph images and case PDF bundles
- Cloud identity and SaaS audit-log detection pack
- Per-rule false-positive notes, severity rationale, and data-source requirements
