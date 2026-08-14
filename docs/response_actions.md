# Response Actions

SOC-Forge v3.3 introduces a durable, analyst-controlled Response Action domain foundation. A response action records work proposed in response to one or more investigation Findings. Creating a record does not execute containment, remediation, commands, or external API calls.

## Domain boundary

A `ResponseAction` belongs to exactly one durable `Investigation` and stores stable `finding_ids`. It contains an `ACT-` identifier, title, description, controlled action type, priority, status, rationale, owner, analyst attribution, and deterministic creation/update timestamps. The immutable model is serialized inside the existing investigation repository record; no separate storage system is used.

Supported action types are `containment`, `credential_action`, `host_action`, `network_action`, `collection`, `validation`, `monitoring`, `communication`, and `other`. Priorities are `low`, `medium`, `high`, and `critical`. The domain reserves `proposed`, `approved`, `in_progress`, `completed`, and `dismissed`; Slice 1 creates only `proposed` records unless an explicit status is supplied for domain-level compatibility. Lifecycle transitions are deferred.

## Finding policy

Creation requires at least one unique, ACTIVE Finding from the same Investigation. Unknown, cross-investigation, duplicate, and already SUPERSEDED Finding references are rejected without changing repository bytes or revision. If a referenced Finding is superseded later, the existing action retains its original relationship as historical audit evidence.

## Persistence and revisions

Successful creation atomically appends one action and increments the Investigation revision exactly once. Rejected creation increments it zero times. Existing records without `response_actions` load as an empty tuple and are not rewritten merely by being read. Action IDs and timestamps survive save/reload unchanged. Listing and retrieval are read-only.

## Current scope

Slice 1 provides the model, aggregate integrity rules, persistence compatibility, and create/get/list service boundary only. It adds no console or web interface, automatic Finding-to-action creation, status-transition workflow, integrations, shell execution, or real containment/remediation behavior.