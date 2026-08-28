# SOC-Forge v3.6.0 Release Package

## Release Snapshot

```text
Project: SOC-Forge
Version: 3.6.0
Primary demo: Local analyst web application
Secondary demo: Terminal analyst console
Rules: 21 packaged YAML rules
Validation: Full suite, clean distributions, isolated installed-wheel smoke
```

SOC-Forge is a local, analyst-centric security investigation platform and detection-engineering portfolio project. It is not a hosted SIEM, production monitoring service, SOAR platform, or remediation engine.

## Primary Demonstration

```bash
source .venv/bin/activate
soc-forge-web --port 8765
```

Open `http://127.0.0.1:8765`. The current sidebar is:

```text
Workspace   Command Center
Operations  Operations / Investigations / Cases
Engineering Detection
Analysis    Security Analysis
Information Reporting / System
```

For a short generated-data path, open **Demo / Lab controls** on Command Center and choose **Start Guided Demo**:

```text
Generate -> Command Center -> Case -> Graph -> Detection Health -> Report
```

Then show the consolidated product flow:

1. Command Center operational attention
2. Detection Overview, Alerts, Rules, ATT&CK, and Health
3. Operations queue reason and authoritative destination
4. Investigation Summary, Findings, Evidence, Timeline, Response, and Handoff
5. Security Analysis exact entities, explicit ATT&CK observations, relationships, chronology, and Hunts
6. Reporting reports, Investigation presentation, executive context, and exports
7. System read-only status, configuration, health, storage, environment, and About

## Interpretation Boundaries

- Detection Coverage describes explicit loaded-rule mappings; it is not observed activity or complete security visibility.
- Shared observations do not establish the same attacker, incident, or campaign.
- Chronology does not establish causality.
- Finding confidence is analyst assessment, not machine certainty.
- Response Actions record analyst-controlled work and do not execute remediation.
- Operations is read-only prioritization, not SOAR.
- Investigation Report is a presentation; Investigation Handoff is the structured validated transfer.
- OFFLINE is valid durable analyst state, UNKNOWN is not automatically failure, and unavailable machine context is not zero.

## Files That Matter Most

```text
soc_forge/pipeline.py             Shared deterministic analysis pipeline
soc_forge/rules/                  Packaged detection content
soc_forge/investigations/         Durable analyst domain and services
soc_forge/detection_engineering.py Rule catalog and health authority
soc_forge/reporting.py            Reporting projections
soc_forge/system_workspace.py     Read-only local system projection
soc_forge/web/app.py              Local web API and scenario runner
soc_forge/web/static/             Consolidated v3.6 web application
samples/attack_chain_demo/        Reviewable sample artifacts
```

## Release Validation

Build from a clean repository root after source validation:

```bash
python -m build
python -m twine check dist/*
pytest -q tests/test_packaging_release.py
```

Expected artifacts:

```text
dist/soc_forge-3.6.0-py3-none-any.whl
dist/soc_forge-3.6.0.tar.gz
```

The packaging contract verifies the 21 YAML rules, exact web static-asset allowlist, metadata version, excluded tests/caches/generated output, isolated installation outside the checkout, representative rule execution, and authoritative service imports. CI repeats the build, `twine` validation, installed version/rule checks, and Python 3.10–3.12 test matrix.

## Visual Documentation

The [v3.6 walkthrough](walkthrough.md) reflects current navigation without using unverified images. The [screenshot index](screenshots/README.md) preserves the historical v3.5 set and records the outstanding manual v3.6 capture list.

## Local Safety

The local server binds to `127.0.0.1` by default and has no authentication. Generated artifacts and durable analyst records may contain sensitive telemetry, identities, command lines, evidence, rationales, and annotations; review and redact them before sharing.
