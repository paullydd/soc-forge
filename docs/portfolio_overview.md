# SOC-Forge Portfolio Overview

SOC-Forge is a Python-based security operations platform that demonstrates the full analyst workflow of a small SOC: ingest security telemetry, normalize it, run deterministic detection rules, correlate alerts into cases, open a durable Investigation, select evidence, develop hypotheses, record decisions, reach analyst Findings, track Response Actions, and produce a defensible report or structured Handoff.

The current portfolio package (v3.6.1) is centered on a local analyst web UI with a guided demo path, backed by a shared CLI/web analysis pipeline. It also includes a full-featured terminal analyst console, checked-in sample artifacts, an HTML incident report, rule quality checks, a detection engineering scorecard, and a durable Investigation model that persists analyst reasoning independent of the underlying machine analysis.

## What This Project Demonstrates

- Event ingestion and normalization from structured security logs (Windows Security events, Sysmon-style process telemetry, EVTX), via the CLI or a direct browser upload in the web UI
- YAML-based detection rules with explicit MITRE ATT&CK mappings, covering 11 of 14 Enterprise tactics across 24 rules
- Alert correlation across related events and entities, including multi-stage correlation chains (for example, external initial access followed by discovery activity)
- Case creation, risk scoring, and case quality briefs with executive summaries, findings, evidence rationale, and containment guidance
- A durable Investigation model, independent of the analysis pipeline: revisioned evidence selection, analyst hypotheses, recorded decisions, analyst-authored Findings (explicitly distinct from machine certainty), and Response Actions that record work without executing remediation
- Structured, integrity-checked Investigation Handoff, separate from human-readable Reporting
- Deterministic FULL/OFFLINE projections throughout: durable analyst state remains available and honestly labeled even when the matching source analysis isn't loaded
- Investigation reconstruction with timelines, replay, entity relationship graphs, relationship exploration, and attack paths
- Detection engineering maturity scoring across rule quality, MITRE coverage, context, correlations, and demo readiness
- Security-conscious engineering practice: closed a real command-injection vulnerability, added optional web authentication and security response headers, `bandit`/`pip-audit` wired into CI, and a documented audit trail of what was found and fixed
- Portfolio-ready output through screenshots, checked-in sample artifacts, and an HTML report
- Regression-tested behavior across 1,570 tests covering rules, correlation, case handling, the durable Investigation model, graphs, exports, simulation, and both the terminal console and web workspace

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
  -> RDP logon from an external-looking source address (initial access)
  -> account and group discovery commands (whoami, net localgroup)
  -> suspicious scheduled task
  -> service-style admin account creation
  -> privileged group assignment
  -> audit log clearing
```

The Detection Lab demo is the cleanest web walkthrough because it shows process-chain detections, credential-access behavior, case quality, graph reconstruction, and scorecard maturity in a short path. The Attack Chain demo is the strongest end-to-end incident story: it now shows a complete kill chain from initial access through impact, and is a good candidate for creating a durable Investigation to demonstrate evidence selection, hypotheses, and Handoff.

## Recommended Review Path

1. Start the local web UI.
2. Select `Detection Lab` or `Attack Chain`, then click `Start Demo`.
3. Step through the Command Center, Detection workspace (Coverage vs. Observed ATT&CK Activity), a Case, and the Reporting scorecard.
4. Create a durable Investigation from the richest case and walk through Evidence, Hypotheses and Decisions, Findings, and Investigation Handoff.
5. Open `samples/attack_chain_demo/` for checked-in artifacts that can be reviewed without rerunning the simulator.
6. Optionally, open the terminal console (`python analyst_console.py`) and repeat the same Investigation workflow, including Investigation Replay and the Entity Relationship Explorer.
7. Run `pytest -q` to confirm the project behavior is covered by tests.

## Key Artifacts

- `README.md`: project entry point, quick start, screenshots, and roadmap
- `docs/release_package.md`: portfolio release guide and demo checklist
- `docs/demo_in_5_minutes.md`: short guided demo script
- `docs/demo_walkthrough.md`: detailed attack-chain walkthrough
- `docs/architecture.md`: pipeline, component, and lifecycle diagrams
- `docs/console_architecture.md`: terminal console ownership boundaries and navigation
- `docs/detection_engineering.md`: rule content, fixture standard, and detection-lab coverage
- `docs/investigation_domain.md`: the durable Investigation model
- `docs/rule_quality.md`: rule quality gate and metadata standard
- `docs/web_ui.md`: local web UI usage, endpoints, and optional authentication
- `docs/screenshots/`: portfolio screenshots
- `samples/attack_chain_demo/`: checked-in demo run for portfolio review

## Current Strengths

- A durable Investigation model with genuine provenance: evidence stays traceable back to the alert and rule that surfaced it, and machine-derived data is never presented as an analyst conclusion
- Deterministic FULL/OFFLINE architecture throughout Analysis, Operations, Reporting, and System - durable analyst state is never silently converted to a failure or a fake zero
- Clear end-to-end pipeline from events to case to durable Investigation to Handoff
- Local web UI and full-featured terminal console that support guided demos and reviewer screenshots, deliberately kept free of duplicated responsibility between the two
- Detection engineering scorecard that makes rule maturity visible, alongside an explicit split between Detection Coverage (what rules exist) and Observed ATT&CK Activity (what fired) - never merged into one misleading number
- Rich attack-chain and detection-lab scenarios with multiple rule and correlation layers, including a full initial-access-through-impact kill chain
- MITRE-aligned detection content with fixture-backed quality checks, and a fixture regime that goes beyond "does the rule fire at all" to catch dead branches in multi-alternative match logic
- Security-hardened by practice, not just claim: a real vulnerability was found and fixed, with tests added specifically to prevent regression
- Test coverage around the most important moving pieces, at 1,570 tests

## Honest Limitations

SOC-Forge is intentionally lightweight. It is not a full SIEM, production case management platform, or enterprise detection engine. Current, accurate limitations:

- Single-OS telemetry footprint: every rule reads Windows Security or Sysmon-style process events. There is no Linux, cloud identity, or SaaS audit log coverage yet.
- Three ATT&CK tactics remain uncovered by design, not oversight: Reconnaissance and Resource Development are pre-compromise, attacker-side activity that never touches the victim endpoint, so no honest endpoint-telemetry rule can detect them. Exfiltration would need network telemetry (destination, data volume) SOC-Forge doesn't ingest; a process-level proxy would be too speculative to trust.
- Response Actions and Investigation Handoff are analyst-controlled workflow records. SOC-Forge does not execute remediation, integrate a SIEM, or provide live monitoring.
- The web UI has no authentication by default (loopback-only binding is the safety boundary); an optional shared-secret auth token is available for non-default deployments but is not required.

## Suggested Talking Points

- "The goal was to model the analyst workflow end to end, not just write one-off detections."
- "Machine-derived data and analyst-authored conclusions are architecturally kept apart - a Finding's confidence is an analyst's assessment, never machine certainty."
- "Rules generate atomic alerts, then correlation turns related signals into cases, and a durable Investigation is where an analyst's own reasoning lives - independent of whether the original analysis is still loaded."
- "The scorecard makes detection engineering quality measurable instead of invisible, and Detection Coverage is kept explicitly separate from what was actually observed."
- "The graph, replay, and relationship-explorer views make the attack path easier to explain during triage."
- "I found and fixed a real command-injection bug during a security pass on this project, and added regression tests and CI scanning so it can't come back quietly."
- "The sample artifacts are checked in so reviewers can inspect output without rerunning the simulator."
