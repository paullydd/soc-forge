# SOC-Forge

SOC-Forge is a lightweight Security Operations Center (SOC) investigation platform written in Python. It processes security events, applies detection rules, correlates related alerts into cases, reconstructs attack activity, scores risk, and produces analyst-friendly reports and investigation artifacts.

The project is designed as a portfolio-ready SOC workflow: it shows detection engineering depth, analyst triage, attack reconstruction, case quality, graph analysis, and report export in one repeatable demo.

## What It Does

- Ingests JSONL security events and Windows Security CSV exports
- Normalizes event data for analysis
- Runs YAML-based detection rules with MITRE ATT&CK mappings
- Runs a built-in brute-force detector for legacy compatibility
- Correlates related alerts into investigation cases
- Tracks case lifecycle fields including owner, status history, notes, timestamps, and evidence
- Builds timelines, IOC summaries, attack chains, and attack graphs
- Scores case risk and generates analyst summaries
- Exports alerts, hunts, cases, reconstructions, and HTML reports
- Includes attack simulation scenarios for demos and regression testing
- Provides a local web UI with scenario switching, guided demo flow, case review, graph view, alerts, hunts, and scorecard
- Provides a terminal analyst console for deeper case review workflows
- Supports case filtering, sorting, owner/status persistence, closure workflow, and investigation bundle export
- Adds case quality briefs with executive summaries, key findings, evidence rationale, containment guidance, and quality gaps
- Includes process-chain, credential-access, lateral-movement, persistence, and collection detections
- Scores detection engineering maturity across rule quality, MITRE coverage, evidence context, correlation depth, and demo readiness

## Pipeline

```text
Security Events
  -> Event Normalization
  -> Detection Rules
  -> Alert Generation
  -> Correlation
  -> Case Building
  -> Risk Scoring
  -> IOC Extraction
  -> Attack Reconstruction
  -> HTML Report / Investigation Export
```

## Main Components

```text
soc_forge/
  cli.py                    Command-line analysis pipeline
  config.py                 YAML-backed configuration
  models.py                 Shared alert and case normalization helpers
  ingest/                   Event loaders and converters
  rules/                    YAML detection rules and rule engine
  correlate/                Multi-alert correlation logic
  hunts/                    Hunt analytics
  scoring/                  Risk scoring
  reconstruct/              Attack reconstruction
  intelligence/             Summaries, scoring, and story generation
  investigations/           Analyst workspace helpers
  ui/                       Terminal UI panels and investigation views
  web/                      Local analyst web UI
  report/                   HTML report generation
  simulator/                Attack scenario generator
```

## Quick Start

Install the project in editable mode:

```bash
pip install -e .
```

Run analysis against a JSONL event file:

```bash
soc-forge --input sample_events.jsonl
```

Generate a demo attack scenario and analyze it:

```bash
python3 -m soc_forge.cli --simulate mixed --sim-output out/simulated_events.jsonl
python3 -m soc_forge.cli --input out/simulated_events.jsonl --out out/alerts.json --html out/report.html

# Richer graph demo: RDP -> scheduled task -> new admin account -> log clearing
python3 -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
python3 -m soc_forge.cli --input out/attack_chain_events.jsonl --out out/alerts.json --html out/report.html

# Detection engineering demo: Office -> PowerShell -> credential access
python3 -m soc_forge.cli --simulate detection_lab --sim-output out/detection_lab_events.jsonl
python3 -m soc_forge.cli --input out/detection_lab_events.jsonl --out out/alerts.json --html out/report.html
```

Review generated artifacts:

```text
out/alerts.json
out/hunts.json
out/cases.json
out/reconstructions.json
out/report.html
```

Start the local web UI:

```bash
python3 -m soc_forge.web.app --port 8765
```

Then open `http://127.0.0.1:8765`, choose a scenario, and click `Start Demo`.

Local safety note: SOC-Forge is a local analyst tool and does not include authentication. Generated reports and JSON artifacts may contain sensitive telemetry such as usernames, hosts, IP addresses, command lines, and investigation notes. Review and redact artifacts before sharing them, and avoid binding the web UI to a non-loopback host unless you understand the exposure.


## Portfolio Demo Package

SOC-Forge now includes a portfolio-ready demo package that shows both analyst workflow and detection engineering depth:

- [Release package guide](docs/release_package.md)
- [Portfolio overview](docs/portfolio_overview.md)
- [Demo in 5 minutes](docs/demo_in_5_minutes.md)
- [Detailed attack-chain walkthrough](docs/demo_walkthrough.md)
- [Architecture diagrams](docs/architecture.md)
- [Case quality polish](docs/case_quality.md)
- [Detection engineering](docs/detection_engineering.md)
- [Rule quality](docs/rule_quality.md)
- [Web UI](docs/web_ui.md)
- [Checked-in sample artifacts](samples/attack_chain_demo/)

The attack-chain scenario demonstrates RDP activity, scheduled task persistence, service-style admin account creation, privileged group assignment, log clearing, correlated case generation, investigation replay, graph review, lifecycle tracking, and case export.

The detection-lab scenario demonstrates process-chain and credential-access detections: Office spawning PowerShell, execution from a user-writable path, LSASS dumping, browser credential-store access, and three related correlations.

## Screenshots

### Analyst Web UI Overview

![SOC-Forge web overview showing 8 alerts, 3 correlations, 1 hunt, and 100/100 case quality](docs/screenshots/web-overview.png)

### Case Detail And Findings

![SOC-Forge case detail showing executive summary, key findings, containment guidance, and evidence](docs/screenshots/case-detail.png)

### Entity Relationship Explorer

![SOC-Forge terminal entity relationship explorer showing IP, user, host, action, and graph summary](docs/screenshots/entity-relationship-explorer.png)

### HTML Report Export

![SOC-Forge HTML report showing critical risk, MITRE coverage, and correlation summary](docs/screenshots/html-report.png)

## Demo Walkthrough

For the best portfolio-style demo, run the attack-chain scenario:

```bash
python3 -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
python3 -m soc_forge.cli --input out/attack_chain_events.jsonl --out out/alerts.json --html out/report.html
python3 analyst_console.py
```

Then open `Investigations -> Investigation Workspace` and inspect replay, timeline, graph, entity profiles, relationship evidence, next actions, and case closure/export.

A complete walkthrough lives in [`docs/demo_walkthrough.md`](docs/demo_walkthrough.md). Sample generated artifacts live in [`samples/attack_chain_demo/`](samples/attack_chain_demo/).

## Rule Coverage

Print MITRE coverage for loaded rules:

```bash
soc-forge --coverage
```

Run rule quality checks before adding or showing detection content:

```bash
python3 -m soc_forge.cli --rule-quality
```

See [`docs/rule_quality.md`](docs/rule_quality.md) for the current rule quality standard.

Rules live in `soc_forge/rules` and use a YAML format with:

- Rule metadata
- Match conditions
- Severity and score
- MITRE ATT&CK mapping
- Optional score modifiers
- Optional emitted detail fields

## Testing

Run the full test suite:

```bash
pytest -q
```

The suite covers detection rules, config loading, correlation, risk scoring, MITRE coverage, CSV ingestion, case enrichment, attack reconstruction, hunts, simulation, and shared model normalization.

## Current Enhancement Roadmap

1. Add event upload and custom dataset loading to the web UI so demos can move beyond the built-in scenarios.
2. Add saved analyst notes, ownership, and closure decisions to the web UI case workflow.
3. Add exportable graph images and case PDF bundles for analyst handoff.
4. Expand detection content into cloud identity, SaaS audit logs, and EDR-style process telemetry.
5. Add rule tuning metadata such as false-positive notes, data-source requirements, severity rationale, and test coverage status.

## Project Goals

SOC-Forge is built to explore and demonstrate:

- Detection engineering
- SIEM-style alert correlation
- SOC case triage workflows
- MITRE ATT&CK mapping
- Incident reconstruction
- Analyst-facing reporting
