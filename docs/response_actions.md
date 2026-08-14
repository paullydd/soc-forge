# Response Actions

SOC-Forge v3.3 provides durable, analyst-controlled Response Actions. An action records response work proposed or reported during an investigation. Creating or transitioning an action never executes containment, remediation, commands, webhooks, or external API calls.

## Domain boundary

A `ResponseAction` belongs to exactly one durable `Investigation` and stores stable `finding_ids`. It contains an `ACT-` identifier, title, description, controlled action type, priority, lifecycle status, rationale, owner, creator, timestamps, and immutable transition history. The model is serialized inside the existing investigation repository record; no separate storage system is used.

Supported action types are `containment`, `credential_action`, `host_action`, `network_action`, `collection`, `validation`, `monitoring`, `communication`, and `other`. Priorities are `low`, `medium`, `high`, and `critical`.

## Lifecycle

New actions begin in `proposed`. Status changes are made only through the response-action service and follow this graph:

```text
proposed -> approved -> in_progress -> completed
    |          |             |
    +----------+-------------+-> dismissed
```

More precisely:

- `proposed` may become `approved` or `dismissed`.
- `approved` may become `in_progress` or `dismissed`.
- `in_progress` may become `completed` or `dismissed`.
- `completed` and `dismissed` are terminal.

Every successful transition appends one immutable record containing a durable transition ID, previous status, new status, author, bounded rationale, and timestamp. The action's current status must match the final history entry. Creation time and owner remain unchanged; update time advances to the transition timestamp. Completion means an analyst recorded that work as completed. It does not prove SOC-Forge performed remediation.

## Finding policy

Creation requires at least one unique, ACTIVE Finding from the same Investigation. Unknown, cross-investigation, duplicate, and already SUPERSEDED Finding references are rejected without changing repository bytes or revision.

If a referenced Finding is superseded later, the existing action remains linked to the original Finding as historical audit evidence. It may continue through its lifecycle. SOC-Forge does not dismiss it, rebind it, change its priority or rationale, or create a replacement automatically. An analyst may explicitly create a separate action against the active replacement Finding.

## Persistence and revisions

Creating an action or completing one valid lifecycle transition is one atomic Investigation mutation and increments revision exactly once. Invalid, stale, no-op, unknown-action, and terminal-state transitions perform no write and increment revision zero times. Listing and retrieval are read-only.

Existing Slice 1 actions without `transition_history` retain their persisted status and load with empty history. Existing investigations without `response_actions` load with an empty collection. Reads do not rewrite either record type, and no historical transitions are fabricated.

## Non-execution guarantee

Response Actions are workflow and audit records only. `approved` does not mean executed, `in_progress` does not represent an automation job, and `completed` does not mean SOC-Forge performed remediation. The action service does not invoke the pipeline, detections, subprocesses, shells, networks, integrations, or source `AnalysisResult` mutation.

## Current scope

Slice 2 provides the model, lifecycle rules, durable history, aggregate integrity, and create/get/list/transition service boundary. Console and web interfaces, Summary and Handoff integration, due dates, reminders, comments, permissions, automation, deletion, external integrations, and real response execution remain deferred.