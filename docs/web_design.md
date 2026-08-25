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

The compact top bar exposes the current page title, a bounded purpose statement, local-platform state, v3.5.0 baseline identity, and existing scenario/search/refresh controls. It does not duplicate primary navigation. Active navigation uses both styling and `aria-current="page"`.

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
