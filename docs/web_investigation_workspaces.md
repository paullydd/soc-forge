# Web Investigation Workspaces

Web routes call the shared investigation services. They do not implement independent lifecycle, validation, persistence, or analysis logic.

The local server builds one `InvestigationRepository`, one
`InvestigationWorkspaceService`, and one `InvestigationBootstrapAdapter`. The
default workspace root is `<analysis-output-root>/workspace`; callers and tests
can inject another root. The repository adds the single `investigations/`
directory beneath that root. The console uses the same path resolver, so both
interfaces can open the same local repository.

The active `AnalysisResult` is held only by the running web server after a
scenario completes or after an analyst explicitly loads a validated completed-
analysis snapshot. Creating a workspace requires that active result and explicit
case IDs. Durable metadata remains available after server restart. Timeline,
pivots, source evidence inspection, and handoff require either the matching
active result or explicit loading of the investigation's exact immutable
snapshot. The server does not rebuild an `AnalysisResult` from loose artifact
JSON and does not rerun analysis from an investigation route.

The server holds one active analysis at a time. Loading one investigation's
snapshot replaces the current process-local analysis. A different investigation
refuses source-dependent requests until its own matching snapshot is loaded.

## HTTP API

All modifying requests require `Content-Type: application/json`. Every update
and deletion includes `expected_revision` as a positive integer in the JSON
body.

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/investigations` | List typed workspace summaries |
| `POST` | `/api/investigations` | Create from active analysis case IDs |
| `GET` | `/api/investigations/{id}` | Read investigation, revision, and source-analysis availability |
| `POST` | `/api/investigations/{id}/source-analysis/load` | Validate and activate the exact completed-analysis snapshot |
| `DELETE` | `/api/investigations/{id}` | Delete workspace state only |
| `POST` | `/api/investigations/{id}/owner` | Assign, reassign, or clear owner |
| `POST` | `/api/investigations/{id}/status` | Apply a normal status transition |
| `POST` | `/api/investigations/{id}/reopen` | Explicitly reopen a closed workspace |
| `POST` | `/api/investigations/{id}/annotations` | Add an annotation |
| `PUT` | `/api/investigations/{id}/annotations/{annotation_id}` | Edit annotation text |
| `DELETE` | `/api/investigations/{id}/annotations/{annotation_id}` | Remove an annotation |
| `POST` | `/api/investigations/{id}/decisions` | Deprecated mutation; returns `410` |

Workspace reads and successful modifications return:

```json
{
  "investigation": {},
  "revision": 2,
  "source_analysis": {
    "source_analysis_id": "analysis-...",
    "available": false,
    "status": "unavailable"
  }
}
```

Creation additionally requires `investigation_id` and a non-empty `case_ids`
list. `title`, `owner`, and `initial_status` are optional and retain the
bootstrap and service semantics. Deletion returns `investigation_id` and
`deleted_revision`. Responses contain logical references, not raw events,
complete cases, repository filenames, or absolute paths.

## Revisions and Errors

The browser uses the revision returned by the server; it never predicts the
next revision. A stale write returns `409` with code `revision_conflict`, the
investigation ID, and the authoritative current revision. The bounded conflict
response does not contain the investigation aggregate. The browser fetches the
latest workspace separately, retains the unsent draft in transient memory, and
does not retry or merge automatically.

Investigation API errors use:

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The investigation changed in another session.",
    "investigation_id": "INV-001",
    "current_revision": 8
  }
}
```

Invalid JSON and request fields return `400`; missing investigations return
`404`; unsupported media types return `415`; duplicate IDs, stale revisions,
and invalid lifecycle transitions return `409`. Corrupt records return a
generic `500` response while details remain in the local server console.

## Local Security and Workflow

The web application remains loopback-bound by default, has no authentication,
and warns on non-loopback binding. It provides no multi-user guarantees,
cross-process locks, hosted security model, or CSRF middleware. Investigation
titles, owners, IDs, annotations, authors, and decision fields are treated as
untrusted text and escaped before insertion into generated markup. The server
does not enable permissive cross-origin behavior.

Deleting a workspace removes only investigation-owned JSON. It never deletes
or rewrites pipeline events, alerts, cases, hunts, reconstructions, or reports.

The local workflow is:

```text
Run or select scenario
  -> Open a case
  -> Create investigation
  -> Assign owner
  -> Add annotation
  -> Change status
  -> Exit browser
  -> Restart server
  -> Reopen durable workspace metadata
  -> Load Source Analysis
  -> Resume source-dependent investigation work
```

## Reasoning API

The web reasoning API is nested under the durable investigation resource:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/investigations/{id}/reasoning` | Shared reasoning summary and revision |
| `GET` | `/api/investigations/{id}/hypotheses` | Deterministic hypothesis summaries |
| `POST` | `/api/investigations/{id}/hypotheses` | Create an analyst-authored hypothesis |
| `GET` | `/api/investigations/{id}/hypotheses/{hypothesis_id}` | Persisted hypothesis, evidence relationships, and assessment history |
| `PUT` | `/api/investigations/{id}/hypotheses/{hypothesis_id}` | Edit only the statement |
| `POST` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/supporting-evidence` | Add a compatible supporting relationship |
| `DELETE` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/supporting-evidence/{evidence_id}` | Remove only the supporting relationship |
| `POST` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/contradicting-evidence` | Add a compatible contradicting relationship |
| `DELETE` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/contradicting-evidence/{evidence_id}` | Remove only the contradicting relationship |
| `POST` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/assess` | Assess an open hypothesis with an append-only decision |
| `POST` | `/api/investigations/{id}/hypotheses/{hypothesis_id}/reopen` | Reopen for further investigation |
| `GET` | `/api/investigations/{id}/reasoning/decisions` | List analyst reasoning decisions |
| `POST` | `/api/investigations/{id}/reasoning/decisions` | Record a controlled general decision |
| `GET` | `/api/investigations/{id}/reasoning/decisions/{decision_id}` | Read an immutable decision |

The legacy `POST /api/investigations/{id}/decisions` route is retained only as an explicit compatibility boundary and returns `410 legacy_decision_mutation_disabled`. Existing stored legacy decisions remain readable. New decisions use `/reasoning/decisions`, which accepts escalation, containment recommendation,
closure rationale, and investigative conclusion. Hypothesis assessment is
available only through the dedicated assessment route.

Requests use JSON and modifying requests require `expected_revision`.
Reasoning errors use the existing stable error envelope. Stale revisions return
the bounded `revision_conflict` response; the browser retrieves the latest
workspace separately. Decision list responses contain a rationale summary
bounded to 160 characters; decision detail retains the complete stored rationale
and references. Detail and reasoning mutation responses use
`Cache-Control: no-store`.

A supported or rejected state records current analyst assessment, not objective
certainty. Decisions document reasoning and do not execute containment,
remediation, or other response actions.


## Investigation Handoff

Each investigation detail page provides a compact, read-only handoff section. The browser can preview the current revision, acknowledge the sensitivity warning, export to the server-controlled analysis `handoffs` directory, inspect the manifest, and run offline validation. Existing bundles are replaced only after explicit overwrite confirmation and successful staged validation.

The browser retains export choices only in transient memory. It receives no absolute artifact paths and performs no handoff serialization, hashing, copying, or validation. Revision conflicts refresh the authoritative investigation without retrying export. See [Investigation Handoff Packages](investigation_handoff.md).

## Source Analysis Recovery

`POST /api/investigations/{id}/source-analysis/load` accepts an empty JSON
object. It loads the investigation's `source_analysis_id` from durable state,
validates the immutable snapshot through `CompletedAnalysisSnapshotStore`,
constructs `InvestigationQueryContext` to validate selected cases and evidence
references, and only then replaces the server's active analysis.

Successful responses contain the investigation and source-analysis IDs plus
event, alert, case, and reconstruction counts. They do not contain raw source
records. Missing, corrupt, unsupported, unsafe, or provenance-invalid snapshots
return controlled errors without paths, telemetry, command lines, or tracebacks.
Activation responses use `Cache-Control: no-store`.

Loading restores process-local source context. It does not modify, rebind, or
increment the durable investigation, and the browser does not retry failed
activation or source-dependent requests automatically.
