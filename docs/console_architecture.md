# Console Architecture

SOC-Forge v3.5 keeps the top-level analyst console stable while assigning each area a distinct product responsibility.

## Top-level ownership

| Option | Area | Authoritative question |
| --- | --- | --- |
| 1 | Detection | What can SOC-Forge detect, what fired, and why? |
| 2 | Investigations | What does the evidence support about a specific security issue? |
| 3 | Analysis | What patterns exist across SOC-Forge security data? |
| 4 | Reporting | How are results communicated and exported? |
| 5 | System | How is SOC-Forge configured and operating? |
| 6 | Operations Queue | What analyst work needs attention next? |
| 0 | Exit | Leave the analyst console. |

These boundaries prevent Detection from becoming Investigation, Analysis from becoming Investigation Lite, Operations Queue from becoming Analysis, Reporting from duplicating Handoff, and System from becoming a demo menu.

## Detection

Detection Engineering owns Detection Overview, Rule Catalog, Detection Lab, Detection Coverage, Rule Explainability, and Detection Gaps. Detection Results owns Alert Explorer.

The existing capabilities remain available:

- Analyze Telemetry File, Run Attack Simulation, Evaluate Rules Only, and an
  ephemeral Last Lab Result are under Detection Lab. They reuse the production
  pipeline and its existing artifact ownership. A triggered rule can open the
  shared Rule Explainability view without rerunning detection.
- View Alerts and Search Alerts are under Alert Explorer.

Slice 2 implements Detection Overview and Rule Catalog as read-only projections
of the production rule loader and stored alert state. They create no independent
registry or state and never run detections. Rule Explainability projects
configured logic, while Detection Coverage and Detection Gaps now project
explicit ATT&CK metadata, unmapped rules, and disabled-only technique
availability without a global baseline or completeness score.

## Investigations

Investigations owns durable issue-specific evidence, hypotheses, decisions, Findings, Response Actions, summaries, timelines, reconstruction, and Handoff.

Legacy Attack Stories are preserved as Investigation Narrative in the existing Investigation Workspace. Attack Graph remains in that same reconstruction workflow. They are no longer duplicated as top-level Analysis concepts.

Investigation Handoff is a structured durable investigation export. It remains under Investigations and is not duplicated under Reporting.

## Analysis

Analysis owns future cross-source and cross-investigation pattern analysis: Threat Activity Overview, Entity Explorer, ATT&CK Activity, Cross-Investigation Analysis, Temporal Analysis, and Hunt Workspace.

These cross-investigation services are not implemented in Slice 1. Each selection states that limitation, lists planned scope without fabricated counts, and performs no source or investigation mutation.

## Operations Queue

Operations Queue remains a deterministic, read-only projection of authoritative Investigation Findings and Response Actions. It owns prioritization of attention, not analysis or work state. No queue persistence or mutation is introduced by this cleanup.

## Reporting

Analysis Report remains the analysis-generated human-readable report. ATT&CK Coverage retains the existing report coverage behavior.

Reporting does not own Investigation Handoff. Analysis Report and Investigation Handoff are separate delivery concepts and use their existing persistence behavior.

## System

System now provides architectural destinations for Platform Status, Configuration, Rule / Asset Health, Repository & Storage, Environment, and About SOC-Forge.

Platform Status is deferred in Slice 1. The existing startup display uses fixed readiness labels and is not a reusable authoritative health source; presenting or duplicating it as live status would be misleading. Later work may introduce a shared read-only readiness source.

Create Demo Case is removed from primary analyst navigation. Its helper remains in analyst_console.py for developer and test use, but the System controller no longer receives or invokes it.

## Placeholder policy

Production menu labels never say Coming Soon. A destination that is not implemented opens a professional bounded informational screen which:

- states that the capability is not implemented in this slice;
- identifies planned scope without fake data;
- states that no independent state is created or modified;
- uses shared width, breadcrumb, color, and ASCII-fallback rendering.

A placeholder screen is not an implemented feature.

## Persistence and roadmap boundaries

Navigation changes do not create domain state or duplicate persistence. Detection, Investigation, Analysis, Operations Queue, Reporting, and System continue to use their existing authorities.

Later v3.5 slices may implement detection coverage, rule explainability,
detection gaps, and the listed Security Analysis and System services. Detection
Overview and Rule Catalog are implemented without changing persistence.
