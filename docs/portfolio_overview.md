# SOC-Forge Portfolio Overview

SOC-Forge is a Python-based security operations project that demonstrates the core workflow of a small SOC platform: ingest security events, normalize them, run detection rules, correlate alerts, build cases, reconstruct attack activity, and produce analyst-friendly reports.

The current portfolio package is centered on a local analyst web UI with a guided demo path. It also includes one shared CLI/web analysis pipeline, an optional terminal analyst console, checked-in sample artifacts, an HTML incident report, rule quality checks, and a detection engineering scorecard.

## What This Project Demonstrates

- Event ingestion and normalization from structured security logs
- YAML-based detection rules with MITRE ATT&CK mappings
- Alert correlation across related events and entities
- Case creation, risk scoring, lifecycle tracking, notes, evidence, and closure
- Case quality briefs with executive summaries, findings, evidence rationale, and containment guidance
- Investigation reconstruction with timelines, replay, entity graphs, relationships, and attack paths
- Detection engineering maturity scoring across rule quality, MITRE coverage, context, correlations, and demo readiness
- Portfolio-ready output through screenshots, checked-in sample artifacts, and an HTML report
- Regression-tested behavior for rules, correlation, case handling, graphs, exports, simulation, and the web workspace

## Portfolio Demo Story

SOC-Forge has two strong demo modes:

```text
Detection Lab
  -> Office spawns PowerShell
  -> suspicious process execution
  -> credential dumping
  -> browser credential store access
  -> correlated credential-access case
```

```text
Attack Chain
  -> RDP logon
  -> suspicious scheduled task
  -> service-style admin account creation
  -> privileged group assignment
  -> audit log clearing
```

The Detection Lab demo is the cleanest web walkthrough because it shows process-chain detections, credential-access behavior, case quality, graph reconstruction, and scorecard maturity in a short path. The Attack Chain demo remains the strongest end-to-end incident story because it shows persistence, privilege escalation, defense evasion, and case export.

## Recommended Review Path

1. Start the local web UI.
2. Select `Detection Lab`.
3. Click `Start Demo`.
4. Step through Dashboard, Case, Graph, Scorecard, and Report.
5. Open `samples/attack_chain_demo/` for checked-in artifacts that can be reviewed without rerunning the simulator.
6. Run `pytest -q` to confirm the project behavior is covered by tests.

## Key Artifacts

- `README.md`: project entry point, quick start, screenshots, and roadmap
- `docs/release_package.md`: portfolio release guide and demo checklist
- `docs/demo_in_5_minutes.md`: short guided demo script
- `docs/demo_walkthrough.md`: detailed attack-chain walkthrough
- `docs/architecture.md`: pipeline, component, and lifecycle diagrams
- `docs/detection_engineering.md`: rule content, fixture standard, and detection-lab coverage
- `docs/rule_quality.md`: rule quality gate and metadata standard
- `docs/web_ui.md`: local web UI usage and endpoints
- `docs/screenshots/`: portfolio screenshots
- `samples/attack_chain_demo/`: checked-in sample events, alerts, cases, reconstructions, hunts, and report

## Current Strengths

- Clear end-to-end pipeline from events to case export
- Local web UI that supports guided demos and reviewer screenshots
- Detection engineering scorecard that makes rule maturity visible
- Rich attack-chain and detection-lab scenarios with multiple rule and correlation layers
- Analyst-focused case quality, graph, replay, and report artifacts
- MITRE-aligned detection content with fixture-backed quality checks
- Test coverage around the most important moving pieces

## Honest Limitations

SOC-Forge is intentionally lightweight. It is not a full SIEM, production case management platform, or enterprise detection engine. Future improvement areas include:

- Custom dataset loading in the web UI
- Saved analyst notes and closure decisions in the web UI
- Exportable graph images and additional investigation bundle formats
- More false-positive guidance and data-source requirements per rule
- Broader event sources, especially cloud identity and SaaS audit logs

## Suggested Talking Points

- "The goal was to model the analyst workflow, not just write one-off detections."
- "Rules generate atomic alerts, then correlation turns related signals into cases."
- "The scorecard makes detection engineering quality measurable instead of invisible."
- "The graph and replay views make the attack path easier to explain during triage."
- "The sample artifacts are checked in so reviewers can inspect output without rerunning the simulator."
