# Analyst Operations Queue

See the [v3.6 product walkthrough](walkthrough.md) for the current end-to-end interface tour.

The Analyst Operations Queue is a deterministic, read-only projection across durable Investigations. It answers which existing analyst work needs attention without creating a second authoritative store.

```text
Durable Investigations
        ↓
Operations Queue Projection
        ↓
Analyst Attention Items
```

The Operations Queue does not create work. It projects work already represented by authoritative investigation state.

## Architecture

`OperationsQueueService` reads Investigations through `InvestigationRepository` and returns immutable `OperationsQueueItem` values. Queue items are never persisted, and no queue fields are added to Investigation records.

Each item carries a deterministic ID, Investigation identity and title, controlled item/source type, priority, reason, source identity and status, and the source timestamps needed by later presentation layers. Queue identity is derived from Investigation ID, source type, and source ID; it never uses a random UUID or mutable list position.

## Queue item types

The controlled Slice 1 vocabulary is:

- `response_action`
- `uncovered_finding`

One nonterminal Response Action produces one queue item, including when the Action references multiple Findings. An active Finding produces one uncovered-Finding item only when no open Response Action references it.

## Response Action inclusion

`proposed`, `approved`, and `in_progress` Actions are queued with deterministic lifecycle-specific reasons. `completed` and `dismissed` Actions are excluded. Response Action priority is inherited without scoring or interpretation.

Response Actions linked to superseded Findings remain queued while their own lifecycle is nonterminal. Finding and Action lifecycles remain independent.

SOC-Forge records analyst-controlled response work. The queue does not approve, start, complete, dismiss, assign, or execute an Action, and SOC-Forge does not execute remediation.

## Finding coverage

An active Finding is covered when at least one `proposed`, `approved`, or `in_progress` Response Action explicitly references it. One open multi-Finding Action covers every linked active Finding. Terminal Actions do not provide current coverage, so an active Finding becomes uncovered when all linked Actions are completed or dismissed.

Superseded Findings never produce uncovered-Finding items. Dismissing or completing an Action does not resolve its Findings.

Findings carry analyst confidence rather than an operational severity compatible with Response Action priority. Slice 1 therefore assigns uncovered Findings the explicit neutral priority `medium`; it does not reinterpret confidence or infer priority from prose.

## Deterministic ordering

Items sort by:

1. priority: `critical`, `high`, `medium`, `low`
2. source state: proposed Actions, approved Actions, in-progress Actions, uncovered Findings
3. source `updated_at` timestamp
4. Investigation ID
5. source ID

Timestamps are stable tie-breakers only. Slice 1 does not interpret age, overdue state, staleness, or an SLA.

## Summary

Summary counts are calculated from projected items. They include total and priority counts, Response Action and uncovered-Finding counts, and proposed, approved, and in-progress Action counts. No mutable counter state exists.

## Full and offline behavior

Queue membership depends only on durable Investigation state. It does not require an active `AnalysisResult`, load completed-analysis snapshots, or access source artifacts. Identical durable state produces identical queue membership in full and offline sessions.

## Read-only guarantee

Building, filtering, sorting, retrieving, or summarizing queue items does not modify Investigation revisions or repository bytes. It does not mutate Findings, Finding lifecycle, Response Actions or transition history, Evidence, Hypotheses, Decisions, annotations, analysis results, snapshots, or artifacts. Repository corruption follows the existing bounded repository error path and is never silently repaired or rewritten.

## Current limitations and non-scope

Slice 2 adds a read-only Analyst Console surface and Command Center summary. It still has no web UI, persistence, acknowledgement, queue assignment, due dates, timers, SLAs, aging, notifications, reminders, escalation, automation, external integrations, SOAR behavior, AI scoring, heuristic scoring, automatic Findings, automatic Actions, or remediation execution.


## Terminal Operations Queue

Command Center option 6 opens the Analyst Operations Queue. The Command Center summary and workspace are rebuilt from durable Investigation state each time they render. Existing options 1 through 5 and 0 retain their prior meanings.

The terminal workspace provides deterministic views for all attention items, Response Actions, uncovered Findings, and high/critical items. Cards retain the queue ID, priority, item type, Investigation identity/title, authoritative source ID/status, timestamps, and exact projection reason. An empty projection displays "No analyst attention items."

Opening an item delegates to the existing authoritative Response Action or Finding controller. Returning from that controller reprojects the queue so completed, dismissed, superseded, or newly uncovered work is reflected without storing queue state. The queue itself remains read-only, offline-capable, and independent of source analysis.

This terminal surface introduces no due dates, timers, aging, SLAs, notifications, assignments, acknowledgement state, AI scoring, automation, or remediation execution. SOC-Forge records analyst-controlled response work and does not execute remediation.


## Web Operations Queue

The web sidebar exposes Operations Queue as a first-class analyst workspace. GET /api/operations-queue returns the authoritative summary and deterministically ordered items; GET /api/operations-queue/{queue_item_id} returns one projected item. Both endpoints use Cache-Control: no-store and OperationsQueueService remains the sole projection authority.

The page displays Total, Critical, High, Medium, Low, Response Actions, Uncovered Findings, Proposed, Approved, and In Progress summary cards. Read-only filters match the terminal views: All, Response Actions, Uncovered Findings, and High/Critical.

Open Response Action and Open Finding first resolve the owning Investigation, then delegate to the existing source-detail workflow using investigation_id and source_id. Source IDs are never treated as globally unique. Returning through the Operations navigation reloads the projection, so authoritative Action transitions, new Actions, and Finding supersession determine membership without browser-side assumptions or background polling.

The web queue works without active source analysis, snapshots, artifacts, or timeline data. Cards are built with DOM creation and textContent, not unsafe analyst-content interpolation. No queue state is stored in localStorage.

The Operations Queue is a projection, not a task store.
Queue membership changes only when authoritative Investigation state changes.

Console and web use the same OperationsQueueService output, including item IDs, ordering, priorities, source types, reasons, and summary counts. Neither interface persists, acknowledges, assigns, dismisses, ages, scores, or executes queue work.

## Deterministic operations prioritization

Operations prioritization is a separate, immutable projection over current Operations Queue items. OperationsQueueService remains responsible for membership; OperationsPrioritizationService adds an explainable tier, operational state, and fixed basis strings, then orders the items. Nothing is persisted.

Response Actions retain their explicit critical, high, medium, or low priority. Uncovered active Findings retain neutral medium operational priority; Finding confidence is not converted into priority.

Within a priority tier, operational states are ordered:

1. in_progress
2. approved
3. proposed
4. uncovered_finding

Complete ordering is priority tier (critical, high, medium, low), operational state, updated_at, investigation_id, then source_id. The timestamp is an ascending deterministic tie-break only. It does not mean older or newer work is more urgent and does not introduce aging, staleness, due dates, overdue state, or SLAs. Filters preserve the relative order of included items.

Each Response Action basis states its explicit priority and lifecycle meaning. Each uncovered Finding basis states that the Finding is active, no open Response Action addresses it, and uncovered Findings use neutral medium operational priority. The basis is fixed code-defined language, not generated prose.

FULL and OFFLINE modes produce identical prioritization from identical durable queue state. The prioritizer reads no AnalysisResult, timeline, snapshots, source artifacts, or analysis payloads. It does not modify repository bytes, revisions, Findings, Actions, histories, evidence, reasoning, or any other authoritative state.

Operations prioritization is deterministic and explainable.
SOC-Forge does not use an opaque numeric score or AI model to rank queue items.

## Operational Summary

The Operational Summary is an immutable, read-only view of the current prioritized Operations Queue. It reports total attention items; critical, high, medium, and low counts; Response Action and uncovered Finding counts; proposed, approved, and in-progress Action counts; and the number of distinct Investigations represented.

Top Attention is the first item in deterministic Operations Queue order. Top Priority Work is bounded to the first three items in that same order. Each item retains the shared priority tier, reason, and priority basis; the summary neither reranks nor scans Investigation state independently.

The Operational Summary does not create or track work independently.
It summarizes the current deterministic Operations Queue.

The projection works from durable queue state in FULL and OFFLINE modes. Reading it does not persist state or mutate Investigations, Findings, Actions, revisions, histories, artifacts, or snapshots. It introduces no SLA, aging, deadline, assignment, acknowledgement, automation, activity feed, AI ranking, or remediation behavior.
