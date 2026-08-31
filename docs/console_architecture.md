# Console Architecture

SOC-Forge v3.6 keeps the top-level analyst console stable while assigning each area a distinct product responsibility.

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

Investigation Handoff is a structured durable investigation export. It remains under Investigations and is not duplicated under Reporting.

The Investigations menu's legacy ephemeral case workspace (filter/sort case browsing, flat-file notes, flat-file status) has been removed: everything it did maps onto durable Investigation state (Annotations, validated status transitions, Assign Owner, Response Actions) except two genuinely unique features, which were ported into the durable Investigation Workspace itself as read-only options: Investigation Replay (a step-through/auto-play walkthrough of a case's timeline) and the Entity Relationship Explorer (interactive entity browser, entity profile, relationship, and attack-path views). Both resolve the underlying machine-generated case from the investigation's scoped evidence reference and the active analysis; if no matching analysis is loaded, they report that honestly rather than duplicating or fabricating case data.

The Investigations menu is now two options: View Cases (a read-only list of the current analysis's machine-generated cases) and Investigation Workspaces (the durable model). The legacy per-case Entity Explorer, Analyst Notes, and Case Status Management were removed as duplicates: Entity Explorer is authoritatively owned by Analysis (deterministic exact matching, ATT&CK aggregation, durable Investigation membership - the legacy version was a cruder same-case co-occurrence index with no durable awareness); notes and status are owned by durable Investigation Annotations and validated status transitions, which the legacy flat files (`out/notes/*.txt`, `out/case_status.json`) never were. The Command Center's status counts now read directly from durable Investigation status (`open`, `in_progress`, `escalated`, `closed`) instead of the removed flat-file source.

## Analysis

Analysis owns deterministic cross-source and cross-investigation pattern analysis: Threat Activity Overview, Entity Explorer, ATT&CK Activity, Cross-Investigation Analysis, Temporal Analysis, and Hunt Workspace.

These services are immutable FULL/OFFLINE projections over existing current analysis and durable Investigation sources. They do not create an analysis registry, persist relationships, auto-load snapshots, or mutate source state.

## Operations Queue

Operations Queue remains a deterministic, read-only projection of authoritative Investigation Findings and Response Actions. It owns prioritization of attention, not analysis or work state. No queue persistence or mutation is introduced by this cleanup.

## Reporting

Reporting is a read-only delivery workspace with Report Center, Investigation Report, Executive Summary, and Export Center. Report Center discovers only known existing analysis HTML artifacts; it does not create a report registry. Investigation Report presents durable Investigation state and remains distinct from the structured Investigation Handoff. Executive Summary composes the existing Operational Summary, Threat Activity, and ATT&CK Activity projections so queue counts, ordering, and top attention remain authoritative.

ATT&CK Coverage remains owned by Detection. Investigation Handoff remains owned by Investigation Workspace; Export Center points to that workflow rather than duplicating its schema or export implementation. Reporting adds no persistence, mutation, AI inference, or remediation execution, and supports FULL and OFFLINE source-context disclosure.

## System

System owns read-only local platform inspection through Platform Status, Configuration, Rule / Asset Health, Repository & Storage, Environment, and About SOC-Forge. Startup and System consume the same immutable authoritative status model. Runtime, Detection Rules, Investigation Repository, Analysis Services, and Analyst Services are required; Reporting and Web Assets are optional for core terminal operation.

System performs bounded current-process and known-path inspection only. It does not duplicate Detection Coverage, persist health state, modify configuration or environment, create write probes, monitor live services, control processes, install packages, or provide developer tools.

Create Demo Case has been removed entirely: it was already unreachable from primary analyst navigation and had no remaining developer or test usage, so the dead helper and the unused `create_demo_case` parameter on `system_menu` were deleted.

## Persistence boundaries

Navigation and read-only projections do not create domain state or duplicate persistence. Detection, Investigation, Analysis, Operations Queue, Reporting, and System continue to use their existing authorities. Detection Coverage, Rule Explainability, Detection Gaps, Security Analysis, Reporting, and System inspection are implemented without new persistence.


## Threat Activity Overview

Analysis option 1 is a real read-only projection over durable Investigation state and optional current machine analysis. FULL exposes current alert, case, hunt, and reconstruction counts; OFFLINE preserves Investigation, Finding, and Response Action counts while machine fields say Unavailable.

Explicit alert and Finding ATT&CK mappings are counted as separately attributed observations. Recent activity uses alert, Finding, and Response Action transition timestamps with deterministic ordering and [MACHINE]/[ANALYST] labels. The feature does not persist, prioritize, score, correlate Investigations, or measure detection coverage.

## Entity Explorer

Analysis option 2 is a real read-only Entity Explorer. EntityObservationService projects explicit structured observations from the current AnalysisResult evidence catalog and explicit durable Investigation links; EntityExplorerService performs deterministic exact matching, counts, ATT&CK aggregation, co-observation projection, ordering, and bounding. No entity database or index is persisted. FULL and OFFLINE are explicit, and co-observation never claims shared attacker, campaign, or incident identity.
## ATT&CK Activity Analysis

Analysis option 3 is a real ATT&CK Activity workspace backed by AttackActivityService. The immutable projection reads durable Finding ATT&CK fields and optional current AnalysisResult Alerts, explicitly mapped Cases, and Reconstruction steps. It groups and orders observed tactics and techniques without using Detection Coverage, persisting an activity index, or changing source state. FULL/OFFLINE attribution and cross-Investigation cautions remain explicit.

## Cross-Investigation Analysis

Analysis option 4 is a real deterministic projection over the existing EntityObservationService and AttackActivityService. It owns overlap questions only: shared exact entities, explicit ATT&CK tactics, and explicit ATT&CK techniques across two or more distinct Investigations. Entity Explorer remains authoritative for entity extraction and normalization, and ATT&CK Activity remains authoritative for observed mappings.

The workspace does not persist or link Investigations, calculate relationship scores, infer campaigns or attackers, use temporal proximity, or mutate source state. FULL/OFFLINE mode, source attribution, counts, deterministic IDs, deterministic ordering, and the observation-without-causation caution are explicit.


## Temporal Analysis

Analysis option 5 is a real read-only TemporalAnalysisService projection over the durable Investigation repository and optional active AnalysisResult. It produces immutable timed and untimed entries with deterministic identities, explicit [MACHINE]/[ANALYST] attribution, stable chronological ordering, and bounded recent reversal.

The service supports exact Investigation, controlled source-type, explicit ATT&CK tactic, and technique-ID views. Temporal Analysis remains distinct from Investigation Timeline and Reconstruction. It performs no causal inference, correlation scoring, persistence, snapshot activation, output scanning, or mutation.


## Hunt Workspace

Analysis option 6 is a real Hunt Workspace composed from the active AnalysisResult Hunt findings, EntityExplorerService, AttackActivityService, and TemporalAnalysisService. Existing pipeline Hunts remain detector outputs owned by the analysis pipeline; entity, ATT&CK, and Investigation searches are ephemeral projections and never become persisted Hunt records.

The workspace has no custom query language, scoring, external integration, detection execution, snapshot activation, or mutable navigation state. FULL/OFFLINE availability is explicit, results use reused deterministic ordering and a 25-item bound, and overlap never claims a shared campaign.
