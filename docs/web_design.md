# Web Design System

SOC-Forge v3.6 treats the browser as an analyst application rather than a collection of independently styled feature pages. Slice 1 establishes shared presentation contracts without changing domain behavior, APIs, persistence, or workflow semantics.

## Principles

Every web page should make four things clear: current location, important state, next available action, and supporting detail. The interface favors deterministic hierarchy, progressive disclosure, useful analyst density, consistent semantics, and restrained visual character.

- Presentation consumes authoritative APIs; it does not own domain state.
- Machine observations remain distinct from analyst-authored conclusions.
- Status uses text and color together.
- Important limitations remain visible; repeated low-value metadata can move into detail.
- Tables and compact lists are preferred for repeated records; panels establish hierarchy rather than wrapping every value.
- FULL combines current machine analysis with durable analyst state. OFFLINE presents durable analyst state only and is not a failure.

## Application Shell

The shell remains framework-free: one packaged HTML entry point, shared CSS, and plain JavaScript modules. The persistent desktop sidebar contains only implemented web destinations:

- **Workspace:** Command Center
- **Operations:** Operations Queue, Investigations, Cases, Alerts
- **Engineering:** Detection Scorecard
- **Analysis:** Investigation Graph, Hunt Findings
- **Output:** generated HTML report and JSON artifacts

Terminal-only Detection Engineering, Security Analysis, Reporting, and System workspaces are not represented as web destinations. There are no “Coming Soon” links.

The compact top bar exposes the current page title, a bounded purpose statement, local-platform state, v3.6.1 release identity, and existing scenario/search/refresh controls. It does not duplicate primary navigation. Active navigation uses both styling and `aria-current="page"`.

## Layout and Hierarchy

The shared canvas supports a wide dashboard and record workspace, full-width horizontally scrollable tables, and a constrained reading-width primitive for long prose. Investigation detail remains a split list/detail layout on wide screens and stacks on narrower screens. A shared context-navigation style is available for the later Investigation redesign: Overview, Evidence, Reasoning, Findings, Response, Timeline, and Handoff.

Typography uses the system font stack. IDs, revisions, timestamps, rule IDs, ATT&CK IDs, Investigation IDs, Finding IDs, and Action IDs use the existing monospace treatment and tabular numerals.

## Design Tokens and Semantic Color

Central CSS properties define canvas, sidebar, primary and secondary surfaces, interactive state, borders, text hierarchy, spacing, radii, content widths, focus treatment, and sidebar width. Semantic tokens cover:

- severity and priority: critical, high, medium, low
- validation and availability: valid, warning, error, information
- lifecycle: proposed, approved, in progress, completed, dismissed

Color is never the only carrier of meaning; visible text labels remain authoritative. Existing Finding lifecycle and Response Action classes continue to consume the same semantic language.

## Shared Components

Slice 1 standardizes contracts for grouped navigation, page headings, technical IDs, status indicators, buttons, badges, compact metric groups, primary panels, warnings, empty states, tables, and future Investigation context navigation.

- Buttons have a visible keyboard focus ring and a selected/pressed state.
- Warnings use one restrained notice treatment and retain their full text.
- Empty states explain absence or unavailability instead of saying only “No data.”
- Table headers remain readable, rows use compact spacing, hover is subtle, and narrow layouts scroll rather than truncate columns.
- Metrics are grouped into one compact surface instead of separate high-emphasis cards.

## Responsive and Accessibility Foundation

The primary desktop shell uses a compact sticky sidebar. Standard laptop widths reduce padding and the Investigation list column. At tablet/narrow widths, the sidebar becomes an explicitly labelled drawer controlled by a keyboard-operable button with `aria-controls` and `aria-expanded`; grids stack predictably and tables scroll horizontally. Phone-first redesign remains outside this slice.

The system preserves semantic buttons and links, form labels, text status labels, contrast, focus visibility, and reduced-motion preferences. This is an accessibility foundation, not a WCAG certification.

## Safe DOM Policy

Analyst-authored Finding, Response Action, Summary, Query Workbench, and Operations Queue content continues through `createElement`, `textContent`, and `replaceChildren` helpers. No browser storage was introduced for authoritative state. Existing legacy dashboard and Investigation template rendering remains escaped; later migration should replace those bounded template paths incrementally rather than mixing presentation work with domain changes.

## Feature Availability

| Feature | Terminal | Web |
| --- | --- | --- |
| Command Center | Yes | Yes |
| Cases and alerts | Yes | Yes |
| Durable Investigations | Yes | Yes |
| Evidence selection and inspection | Yes | Yes |
| Hypotheses and decisions | Yes | Yes |
| Findings | Yes | Yes |
| Response Actions and lifecycle | Yes | Yes |
| Investigation Summary | Yes | Yes |
| Timeline and pivots | Yes | Yes |
| Investigation Handoff | Yes | Yes |
| Operations Queue | Yes | Yes |
| Detection Overview / Rule Catalog / Explainability / Coverage / Gaps / Lab | Yes | No; Detection Scorecard and demo analysis only |
| Threat / Entity / ATT&CK / Cross-Investigation / Temporal Analysis | Yes | No; graph and hunt projections only |
| Report Center / Investigation Report / Executive Summary / Export Center | Yes | No; generated HTML report artifact only |
| Platform Status / Configuration / Asset Health / Storage / Environment / About | Yes | No |

## Confirmed Clutter and Redundancy Audit

| Finding | Disposition | Slice |
| --- | --- | --- |
| Eight ungrouped sidebar destinations obscure workflow ownership | **MERGE** into implemented-only navigation groups | Slice 1 |
| “Overview” does not communicate the Command Center role | **REDESIGN** label and contextual title | Slice 1 |
| The static “Investigation Workspace” title appears on every page | **REMOVE** repetition; use per-view title and description | Slice 1 |
| Five independent metric cards give every count equal emphasis | **MERGE** into one compact metric group | Slice 1 foundation; content decisions in Slice 2 |
| Investigation identity, revision, owner, and timestamps repeat through a very tall detail page | **MOVE TO DETAIL** using persistent context plus subsection navigation | Later Investigation slice |
| Investigation Summary repeats counts also shown by Evidence, Reasoning, Findings, and Response sections | **REDESIGN LATER** with progressive disclosure; preserve access | Later Investigation slice |
| Findings and Response Actions use nested bordered records for most metadata | **REDESIGN LATER** as compact lists plus detail panes | Later Investigation slice |
| Queue summary metrics and top-priority records repeat information before the filterable list | **KEEP** current semantics; reassess density after Command Center redesign | Later Operations slice |
| Sensitive-data and non-remediation warnings can repeat within one long workspace | **MERGE** only when a shared persistent warning preserves the boundary | Later Investigation slice |
| Empty states vary in height and visual treatment | **MERGE** into one shared presentation contract | Slice 1 |
| Status colors and badge selectors grew feature by feature | **MERGE** through semantic tokens while preserving textual labels | Slice 1 |
| Legacy dashboard and Investigation renderers duplicate string-template helpers | **REDESIGN LATER** toward the existing safe-DOM helper pattern | Later migration |

No information was deleted in Slice 1. No CSS selectors were removed because current static inspection alone did not prove them unused across dynamically rendered states.

## Later v3.6 Boundaries

- Slice 2: Command Center content hierarchy and operational overview.
- Later Investigation slice: persistent context, secondary navigation, list/detail patterns, and progressive disclosure.
- Later feature slices: deliberate web implementations for Detection, Analysis, Reporting, or System only where product scope authorizes them.
- Deferred platform work: global search redesign, command palette, charts, polling, WebSockets, themes, preferences, authentication, and roles.

Slice 1 adds no API, dependency, framework, persistence, polling, remediation, or screenshot refresh.

## Slice 4: Detection Workspace

The former separate **Alerts** and **Detection Scorecard** sidebar destinations are consolidated into one focused **Detection** workspace. Contextual tabs expose only implemented data: Overview, Alerts, Rules, ATT&CK, and Health. The workspace remains framework-free and consumes the existing generated-alert and scorecard projections plus a new read-only web projection of the existing `DetectionEngineeringService` rule catalog.

Overview prioritizes current alert volume, Critical/High alerts, triggered rules, enabled rules, recent machine detections, and bounded rule activity. Alerts use a list/detail layout with textual severity, technical identity, detection reason, normalized entity context, observed ATT&CK mappings, and supporting metadata. Rules use a list/detail layout with loaded state, current trigger count, purpose, ATT&CK coverage, and deterministic match/emit/aggregate/modifier metadata. There are no rule editing or enable/disable controls.

ATT&CK maintains two explicit semantic regions:

- **Detection Coverage** answers what loaded rules are mapped to detect. It does not claim complete ATT&CK coverage.
- **Observed ATT&CK Activity** answers which mappings are present on alerts in the current analysis. It does not prove attacker intent.

Health preserves the existing scorecard grade, score, quality gate, component scores, and supporting details without reinterpreting them. Missing values are labelled Unknown or Unavailable rather than treated as failure. Detection rendering uses `createElement`, `textContent`, and `replaceChildren`; the backend remains authoritative and no browser persistence or mutation endpoint is introduced.

## Slice 2: Command Center

The Command Center answers one primary question: **what requires analyst attention now?** Its hierarchy is:

1. compact operational status
2. authoritative Top Attention
3. bounded Recent Activity
4. supporting generated security activity

### Authoritative ownership

The dashboard composes existing read-only sources and owns no business rules:

| Display | Authoritative source |
| --- | --- |
| Investigation count and recent updates | `/api/investigations` durable summaries |
| High/Critical attention and open Response Actions | Operations Queue `operational_summary` |
| Top Attention membership, order, reasons, and destinations | Operations Queue `top_items` |
| Alerts, correlations, Hunts, cases, rule counts, tactic observations | `/api/workspace` generated analysis artifacts |
| Enabled rule count | existing Detection Scorecard projection |

There is no dashboard-specific priority or risk score. Top Attention takes the first four already ordered Operations Queue `top_items` and exposes authoritative Finding or Response Action navigation. The former Highest Risk Case panel was removed from the landing page because it competed with Operations prioritization and displayed report-like prose; full case risk and quality remain accessible in Cases.

### Recent Activity

Recent Activity is a non-persistent presentation merge of timestamped machine alerts and durable Investigation summary updates. It is reverse chronological, deterministically tie-broken, bounded to seven rows, visibly attributed, and navigates only to an existing Alerts or Investigation destination. It does not infer causality or claim to be a complete activity log. Finding and Response Action transitions are not added independently because no unified web activity projection currently owns that stream.

### Supporting security activity

The former equal-bar Rule Activity chart was removed: many one-count bars provided little situational value. A compact Detection summary now reports the existing enabled-rule count, correlations, Hunts, and cases. ATT&CK is limited to five observed tactics with counts and explicitly states that observed activity is not Detection Coverage. No completeness or effectiveness percentage is calculated.

When generated machine artifacts are absent, the Command Center reports that fact without calling the state OFFLINE: the current web workspace payload does not expose an authoritative global analysis mode. It also states that durable Investigation and Operations state is separate. Unavailable values are not silently converted into machine zeroes.

### Controls and navigation

Refresh remains a primary analyst control because it reloads workspace artifacts, Investigation summaries, and the authoritative Operations Queue. Scenario generation and the guided demo remain available inside a collapsed **Demo / Lab controls** disclosure below operational content. Their labels distinguish generation and guidance from analyst or remediation actions.

The existing search filters cases, alerts, and Hunts in current generated analysis; it is not a global authoritative search engine. It remains in the header with reduced width and is labelled **Filter current analysis**. A later search slice may replace it.

No sidebar destinations changed in Slice 2. Cases, Alerts, Detection Scorecard, Investigation Graph, Hunt Findings, and secondary output artifacts remain reachable. Later work should move raw JSON/report artifacts into a dedicated Reporting or developer-actions surface when web Reporting scope is authorized.

### Dashboard/report boundary

Command Center rows contain status, technical identity, a short authoritative reason, attribution, and timestamp. Long executive summaries, evidence narratives, and deep lifecycle history remain in Cases, Investigations, Findings, Response Actions, reports, and handoffs. Dashboard projection never mutates those sources.

## Slice 5: Operations Workspace

The former card-heavy Operations Queue is now a focused prioritization and navigation workspace. It answers what needs attention, why it is prioritized, what kind of work it is, which Investigation owns it, and which authoritative Finding or Response Action workflow the analyst should open next.

### Authority and semantics

The workspace continues to consume `/api/operations-queue` with `no-store` caching. `OperationsQueueService` remains the sole membership authority and `OperationsPrioritizationService` remains the sole ordering and explainability authority. The browser preserves the server-provided order and fixed `priority_basis`; it does not score, rank, age, group, or infer work locally.

The projection remains read-only. It does not persist queue items or introduce acknowledgement, assignment, snoozing, escalation, ticketing, orchestration, remediation, or execution. Permitted changes remain in the owning Investigation's existing Finding or Response Action workflow, and returning to Operations reloads authoritative state.

### Information hierarchy

The repeated Top Priority cards and full queue cards were consolidated into:

1. five compact workload facts: attention items, High/Critical, Response Actions, uncovered Findings, and represented Investigations;
2. the existing read-only filters;
3. one server-ordered attention list; and
4. a persistent detail pane containing the authoritative reason, complete priority basis, work type, owner, timestamps, and source-workflow destination.

Priority and lifecycle remain textual, not color-only. Uncovered Findings retain neutral MEDIUM priority; Finding confidence is never reinterpreted as operational severity. Empty filtered views explicitly distinguish an empty queue projection from an absence of alerts or Investigations. Rendering uses `createElement`, `textContent`, and `replaceChildren`, with no browser persistence.

## Slice 6: Security Analysis Workspace

The fragmented Analysis navigation is consolidated into one **Security Analysis** destination with six contextual subviews: Overview, Entities, ATT&CK, Relationships, Timeline, and Hunts. The former case-scoped Investigation Graph remains an internal guided-demo view rather than a primary Analysis destination; it is not presented as a substitute for cross-state relationship analysis.

### Semantic ownership

Security Analysis is an immutable exploration layer over existing authoritative services. Detection continues to own current alerts, rule explainability, and rule coverage. Investigations continue to own durable state and all Finding, Response Action, evidence, handoff, and lifecycle mutation. Operations continues to own analyst-work prioritization. Security Analysis owns only cross-state pattern, entity, explicit ATT&CK observation, overlap, chronology, and Hunt projections.

### FULL and OFFLINE

FULL means current machine analysis plus durable analyst state. OFFLINE means durable analyst state only and is a valid operating mode, not a failure. Machine alert, case, reconstruction, and existing pipeline Hunt values are labelled **Unavailable** when current machine context is absent; they are never rendered as misleading zeroes. Machine and analyst attribution remains textual throughout the workspace.

### Subview boundaries

- **Overview** uses `ThreatActivityOverviewService` for bounded state, attribution, and recent activity. It introduces no synthetic score.
- **Entities** uses the four supported `EntityExplorerService` types and exact normalization. There is no fuzzy matching, alias resolution, identity stitching, enrichment, or global-search claim.
- **ATT&CK** uses `AttackActivityService` and shows explicit observed or recorded mappings. It never imports Detection Coverage or the rule catalog.
- **Relationships** uses deterministic `CrossInvestigationAnalysisService` IDs and exact shared entities, tactics, and techniques. Shared observations do not establish the same attacker, attack, campaign, or cause; no relationship score is calculated.
- **Timeline** uses `TemporalAnalysisService` deterministic chronology, its existing Investigation/source/tactic/technique filters, and a separate untimed region. Chronology does not establish causality and remains distinct from an Investigation-specific Timeline or Reconstruction.
- **Hunts** preserves the difference between current pipeline Hunt findings and ephemeral entity, technique, or Investigation projections. Exploration does not save a Hunt, persist results, or rerun detection.

### Pivots and deferred capabilities

Read-only pivots open the authoritative Investigation Workspace, move explicit entity ATT&CK context into an ephemeral technique Hunt projection, and preserve technical identity without mutation coupling. Deferred capabilities include fuzzy/global search, external enrichment, campaign inference, relationship scoring, saved or scheduled Hunts, query languages, SIEM connectors, background monitoring, entity/time-window Timeline filters, and Detection rule/coverage duplication.

## Slice 7: Reporting and System Workspaces

The former sidebar Output links are consolidated into one **Reporting** workspace, and the established terminal System projections now have one intentionally read-only **System** workspace. Both are lower-frequency information surfaces and introduce no persistence, polling, mutation, or remote administration.

### Reporting architecture

Reporting uses five contextual views: Overview, Reports, Investigation Report, Executive, and Exports. `ReportCenterService` remains the bounded authority for known existing HTML reports and their real modified timestamps. `InvestigationReportService` projects durable Investigation state without revealing protected evidence values. `ExecutiveSummaryService` deterministically composes the authoritative Operations, Threat Activity, and observed ATT&CK projections; it adds no generated prose or score.

Investigation Report is a presentation view. Investigation Handoff remains the structured operational-transfer artifact owned by Investigations, and Reporting only links analysts back to that workflow. Exports exposes the existing allowlisted HTML and JSON artifacts without transformation. PDF, arbitrary CSV, scheduling, email delivery, document management, mutable report building, and AI-generated summaries remain deferred.

Reporting uses one contextual sensitive-content notice because generated and durable reports can contain usernames, hosts, IP addresses, analyst rationales, Findings, annotations, and case metadata. FULL means current machine analysis plus durable analyst state. OFFLINE means durable analyst state only; machine context is labelled unavailable rather than rendered as zero or failure.

### System architecture

System uses six contextual views: Status, Configuration, Health, Storage, Environment, and About. All data comes from `SystemWorkspaceService`. Platform Status preserves the authoritative `ready`, `degraded`, `unavailable`, and `unknown` states and separates required components from optional Reporting/Web assets. UNKNOWN means the state could not be determined and is never converted into failure.

Configuration is a bounded read-only effective configuration projection with sensitive-key masking. Health reports rule loadability and packaged web/report assets; it does not duplicate Detection Coverage, ATT&CK completeness, or rule effectiveness. Storage inspects only known repository, output, snapshot, and report locations without write probes, repair, directory creation, permission changes, or snapshot mutation. Environment uses the existing Python-native cross-platform projection and does not expose environment variables, secrets, credentials, tokens, or PATH.

About uses the authoritative SOC-Forge version and current **Security Operations Platform** identity and explicitly states that SOC-Forge does not execute remediation. Configuration editing, service control, repository repair, package installation, secret management, live monitoring, remote diagnostics, and environment mutation remain deferred.

## Slice 8: Cross-Workspace Release Polish

All primary web workspaces now share one compact hierarchy for workspace headers, tabs, metrics, panels, state notices, lists, and technical disclosures. Analyst-readable UTC timestamps are used for summary metadata while exact serialized UTC values remain available through semantic time metadata or technical detail; forensic timelines retain their precision.

The interface remains desktop-first and reflows at narrower widths: navigation becomes dismissible, tab rows scroll deliberately, metric groups collapse without joining labels and values, list/detail surfaces stack, controls stay reachable, and long identifiers or analyst text wrap safely. Tabs expose selected state, keyboard traversal, and explicit control/panel relationships; status updates are announced where useful and visible focus treatment is consistent.

State wording preserves product semantics across workspaces. **UNKNOWN** is not failure, **OFFLINE** is valid durable analyst state, and unavailable machine context is not converted to zero activity. Observed ATT&CK activity remains distinct from Detection Coverage. Analyst-readable summaries precede collapsed technical paths and supporting metadata, while ownership, provenance, severity, priority, and evidence remain visible.

Presentation changes do not move authority. Investigations retain durable mutation workflows; Operations, Security Analysis, Reporting, and System remain read-only projections within their documented boundaries. SOC-Forge continues not to execute remediation, orchestrate endpoint changes, infer campaign identity, or treat chronology as causality.
