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

Reporting is a read-only delivery workspace with Report Center, Investigation Report, Executive Summary, and Export Center. Report Center discovers only known existing analysis HTML artifacts; it does not create a report registry. Investigation Report presents durable Investigation state and remains distinct from the structured Investigation Handoff. Executive Summary composes the existing Operational Summary, Threat Activity, and ATT&CK Activity projections so queue counts, ordering, and top attention remain authoritative.

ATT&CK Coverage remains owned by Detection. Investigation Handoff remains owned by Investigation Workspace; Export Center points to that workflow rather than duplicating its schema or export implementation. Reporting adds no persistence, mutation, AI inference, or remediation execution, and supports FULL and OFFLINE source-context disclosure.

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


## Threat Activity Overview

Analysis option 1 is a real read-only projection over durable Investigation state and optional current machine analysis. FULL exposes current alert, case, hunt, and reconstruction counts; OFFLINE preserves Investigation, Finding, and Response Action counts while machine fields say Unavailable.

Explicit alert and Finding ATT&CK mappings are counted as separately attributed observations. Recent activity uses alert, Finding, and Response Action transition timestamps with deterministic ordering and [MACHINE]/[ANALYST] labels. The feature does not persist, prioritize, score, correlate Investigations, or measure detection coverage. Remaining Analysis destinations stay deferred.

## Entity Explorer

Analysis option 2 is a real read-only Entity Explorer. EntityObservationService projects explicit structured observations from the current AnalysisResult evidence catalog and explicit durable Investigation links; EntityExplorerService performs deterministic exact matching, counts, ATT&CK aggregation, co-observation projection, ordering, and bounding. No entity database or index is persisted. FULL and OFFLINE are explicit, and co-observation never claims shared attacker, campaign, or incident identity.
## ATT&CK Activity Analysis

Analysis option 3 is a real ATT&CK Activity workspace backed by AttackActivityService. The immutable projection reads durable Finding ATT&CK fields and optional current AnalysisResult Alerts, explicitly mapped Cases, and Reconstruction steps. It groups and orders observed tactics and techniques without using Detection Coverage, persisting an activity index, or changing source state. FULL/OFFLINE attribution and cross-Investigation cautions remain explicit.

## Cross-Investigation Analysis

Analysis option 4 is a real deterministic projection over the existing EntityObservationService and AttackActivityService. It owns overlap questions only: shared exact entities, explicit ATT&CK tactics, and explicit ATT&CK techniques across two or more distinct Investigations. Entity Explorer remains authoritative for entity extraction and normalization, and ATT&CK Activity remains authoritative for observed mappings.

The workspace does not persist or link Investigations, calculate relationship scores, infer campaigns or attackers, use temporal proximity, or mutate source state. FULL/OFFLINE mode, source attribution, counts, deterministic IDs, deterministic ordering, and the observation-without-causation caution are explicit. Hunt Workspace remains a bounded deferred destination.


## Temporal Analysis

Analysis option 5 is a real read-only TemporalAnalysisService projection over the durable Investigation repository and optional active AnalysisResult. It produces immutable timed and untimed entries with deterministic identities, explicit [MACHINE]/[ANALYST] attribution, stable chronological ordering, and bounded recent reversal.

The service supports exact Investigation, controlled source-type, explicit ATT&CK tactic, and technique-ID views. Temporal Analysis remains distinct from Investigation Timeline and Reconstruction. It performs no causal inference, correlation scoring, persistence, snapshot activation, output scanning, or mutation. Hunt Workspace remains deferred.


## Hunt Workspace

Analysis option 6 is a real Hunt Workspace composed from the active AnalysisResult Hunt findings, EntityExplorerService, AttackActivityService, and TemporalAnalysisService. Existing pipeline Hunts remain detector outputs owned by the analysis pipeline; entity, ATT&CK, and Investigation searches are ephemeral projections and never become persisted Hunt records.

The workspace has no custom query language, scoring, external integration, detection execution, snapshot activation, or mutable navigation state. FULL/OFFLINE availability is explicit, results use reused deterministic ordering and a 25-item bound, and overlap never claims a shared campaign.
