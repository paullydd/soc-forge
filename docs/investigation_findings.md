# Investigation Findings

An investigation finding is a durable, explicitly analyst-authored conclusion grounded in persisted investigation evidence and reasoning. It is not a detection, machine verdict, automated recommendation, or confirmation that an attack occurred.

## Domain Boundary

Machine analysis -> analyst-selected evidence -> hypotheses and decisions -> InvestigationFinding -> durable Investigation repository.

Detections describe machine-observed signals. Evidence records what an analyst selected and how it was classified. Hypotheses remain analyst assessments. Decisions record reasoning actions. Findings express a bounded analyst conclusion and cite at least one existing analyst-selected evidence item, hypothesis, or investigation decision.

## Controlled State

Status is one of `draft`, `substantiated`, `unsubstantiated`, or `inconclusive`. Confidence is `low`, `medium`, or `high`. High confidence remains an analyst assessment, not machine certainty.

## Relationships

Finding evidence IDs must name analyst-selected evidence in the same investigation. Scope-only references are not sufficient. Hypothesis and decision IDs must exist in the same investigation. Unknown, foreign, malformed, or duplicate relationship IDs are rejected. At least one evidence, hypothesis, or decision reference is required.

ATT&CK tactics and techniques are optional analyst-supplied context. Durable affected-entity references are deferred because current web entity IDs are intentionally transient transport identifiers.

## Content and Sensitivity

Titles, conclusions, authors, timestamps, and limitations are bounded. The service never copies raw event messages, command lines, usernames, hosts, IP addresses, or protected evidence values into finding prose. Analysts remain responsible for text they deliberately enter.

## Persistence and Revisions

Findings are frozen models stored in the existing `Investigation` aggregate. Create and material update operations use optimistic revision checks and increment revision exactly once. No-op updates preserve revision and bytes. Reads do not write.

Older records load with an empty findings tuple. Findings are not stored in completed-analysis snapshots and do not modify `AnalysisResult` or artifacts.

## Offline Behavior

Findings remain readable after restart and when source analysis is unavailable. The service accepts no `AnalysisResult`, performs no enrichment, and cannot rebind an investigation. Future Summary and Handoff slices may consume this state without changing its storage model.


## Console Workflow

Open a durable investigation and select **Investigation Findings**. The nested screen lists, creates, opens, and edits findings through `InvestigationFindingService`. Relationship prompts show numbered analyst-selected evidence, hypotheses, and decisions; no reference is selected automatically. Finding detail delegates evidence and reasoning review to the existing protected controllers. Back moves one level and no delete action exists.

## Web Workflow

The local Investigation Workspace includes an **Investigation Findings** section labeled as analyst-authored conclusions. Counts cover all controlled statuses. List, detail, create, and edit views use safe DOM construction. Relationship choices come from the durable investigation and protected evidence is not revealed by finding presentation.

Routes:

- `GET /api/investigations/{id}/findings`
- `GET /api/investigations/{id}/findings/{finding_id}`
- `POST /api/investigations/{id}/findings`
- `PUT /api/investigations/{id}/findings/{finding_id}`

Responses use `Cache-Control: no-store`. Reads and offline mutations do not require active analysis. Create and material updates increment revision once; no-op updates do not. Snapshot activation does not alter findings.

Terminal scrollback and browser presentation can retain analyst-authored finding text. Raw protected evidence remains behind the existing explicit evidence reveal flow. There is no delete operation. Durable affected-entity references remain deferred, as do Summary and Handoff integration.
