# Analyst Operations Queue

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

Slice 1 has no terminal or web UI, Command Center integration, persistence, acknowledgement, queue assignment, due dates, timers, SLAs, aging, notifications, reminders, escalation, automation, external integrations, SOAR behavior, AI scoring, heuristic scoring, automatic Findings, automatic Actions, or remediation execution.
