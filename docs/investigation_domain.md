# Investigation Domain

SOC-Forge places the investigation domain after deterministic analysis and before presentation or export:

```text
Pipeline
  -> AnalysisResult
  -> Investigation
  -> Presentation / Export
```

`soc_forge.pipeline` remains unaware of investigations. It owns event analysis and the generated alerts, cases, hunts, correlations, reconstructions, artifacts, and reports. The investigation domain references those results but does not embed, rewrite, or replace them.

## Object Relationships

`soc_forge.investigations.models` defines the reusable, versioned objects for future analyst work:

- `Investigation` is the aggregate root and identifies its source analysis.
- `WorkspaceMetadata` describes the analyst-facing workspace without providing persistence behavior.
- `EvidenceReference` points to an analysis result by logical artifact key and source identifier. It does not contain a mutable copy of the source event, alert, case, or reconstruction.
- `Hypothesis` distinguishes supporting and contradicting evidence by `EvidenceReference.reference_id`.
- `Decision` can refer to evidence references and hypotheses; `Annotation` identifies its target through a controlled target type and target ID.
- `TimelineSelection` records a scope using evidence-reference IDs, optional timestamps, and entity IDs without implementing timeline queries. An event is selected through an `EvidenceReference` whose source type is `event`.
- `HandoffManifest` describes future handoff membership only; it does not package or export files.

```text
Investigation
  |-- WorkspaceMetadata
  |-- EvidenceReference[]
  |     |-- analysis artifact key
  |     `-- source object ID
  |-- Hypothesis[] -------- supporting / contradicting EvidenceReference IDs
  |-- Decision[] ---------- EvidenceReference IDs and Hypothesis IDs
  |-- TimelineSelection[] - EvidenceReference IDs
  |-- Annotation[] -------- target object IDs
  `-- HandoffManifest ----- selected domain object IDs and artifact keys
```

## Ownership and Evolution

The models are frozen dataclasses with explicit identifiers, schema versions, tuple-based relationships, and JSON-compatible dictionary serialization. Callers own identifier generation. Investigation objects own analyst-authored context, while pipeline artifacts remain immutable source material.

Caller-provided lists are copied into tuples during construction. Domain objects do not retain mutable event, alert, case, reconstruction, or `AnalysisResult` payloads. Optional fields default to `None` or empty tuples; they do not introduce secrets, machine-specific paths, or process-dependent values.
## Identifier and Reference Integrity

Repeatable children use separate, investigation-local identifier namespaces:
evidence references, hypotheses, decisions, timeline selections, and annotations.
IDs must be unique within their own child type. The same value may be used by
different child types because their namespaces are unambiguous.

Investigation construction and deserialization enforce aggregate-wide integrity:

- hypothesis supporting and contradicting IDs must resolve to evidence references
- one evidence reference cannot be both supporting and contradicting for one hypothesis
- decision evidence and hypothesis IDs must resolve within the investigation
- timeline-selection evidence IDs must resolve within the investigation
- handoff IDs must resolve to owned children or declared artifact keys
- a handoff manifest's investigation ID must match its owning aggregate

Annotation targets are controlled. `investigation`, `evidence`, `hypothesis`,
`decision`, and `timeline_selection` are aggregate-owned and must resolve
internally. `case` and `analysis` are explicit external logical references;
their IDs are validated as nonblank but do not require aggregate membership.

> Investigation-owned references must resolve within the aggregate unless their reference type is explicitly classified as external.

The workspace service checks operation-specific decision and annotation
references before saving. Aggregate validation remains the final defense during
construction and repository loading. A persisted integrity failure is reported
through the repository's corrupt-record error contract.


## Schema Version Policy

`Investigation.schema_version` is the top-level schema version for the aggregate. Each nested model also carries an independent schema version so a serialized object remains self-describing when read outside the aggregate.

Version `1.0` is the current contract:

- versions must use the `<major>.<minor>` format
- readers reject unsupported major versions with a clear error
- additive `1.x` minor versions are expected to remain backward compatible
- removing fields, changing field meaning, or changing relationship identity requires a new major version

This slice does not implement migrations. A future persistence layer must select migrations before constructing these models; it must not silently reinterpret unsupported major versions.

The following behavior remains outside the domain model:

- persistence and repositories
- lifecycle transitions
- validation against a specific `AnalysisResult`
- timeline or entity queries
- UI and CLI behavior
- handoff packaging and export

## Local Investigation Repository

`soc_forge.investigations.repository.InvestigationRepository` provides local,
durable storage for the investigation aggregate. The caller supplies the
workspace root; the repository does not use a hidden profile directory or
global state.

> The investigation repository stores analyst-owned investigation state and references to analysis artifacts. It does not rewrite pipeline-generated artifacts.

### File Layout

Each investigation has one UTF-8 JSON record:

```text
<workspace-root>/
  investigations/
    <investigation-id>.json
```

The record is a repository envelope containing:

- repository schema version `1.0`
- a positive integer repository revision
- the serialized `Investigation`

It does not copy events, alerts, cases, reconstructions, reports, or binary
artifacts. Evidence remains connected to analysis output through logical
artifact keys and stable source IDs.

### Atomic Writes and Revisions

`save()` serializes the complete envelope deterministically, writes a temporary
file in the `investigations/` directory, flushes it, calls `os.fsync()`, and
uses `os.replace()` to replace the destination. A failed write or replacement
does not intentionally replace an existing valid record, and temporary files
are removed after handled failures when practical.

This provides atomic replacement for normal local use. It does not guarantee
that every filesystem or hardware failure is crash-consistent.

The first save creates revision `1`. Updating an existing investigation
requires its current `expected_revision` and increments the revision. A stale
revision raises a conflict error and no automatic merge occurs. Repository
revision metadata remains outside the frozen investigation aggregate.

The repository does not provide cross-process locks. Two local sessions can
observe the same files, but truly simultaneous writes are not serialized.
Optimistic revision checks reduce accidental overwrites; they do not provide
multi-user transaction semantics.

### Errors and Deletion

The repository uses explicit errors for invalid IDs, missing records, duplicate
first saves, stale revisions, and corrupt records. Investigation IDs cannot be
empty, absolute, contain `..`, or contain path separators. Stored JSON must be
an object with a supported repository envelope and a valid investigation
schema.

Deleting an investigation removes only its JSON record. It never deletes
pipeline artifacts referenced by that investigation. Temporary files are not
listed as investigations.

No database is introduced because this slice needs one inspectable local
record per aggregate, deterministic listing, and narrow optimistic conflict
detection. Search, multi-user concurrency, transactions across investigations,
and hosted operation are outside the current requirement.

## Investigation Workspace Service

`soc_forge.investigations.workspace_service.InvestigationWorkspaceService`
is the shared application boundary for future web and console workflows. It
receives an `InvestigationRepository` and a small clock callable through its
constructor. It does not select a storage root, read JSON directly, or use
global state.

Responsibilities remain separated:

- frozen domain models own investigation data and serialization validation
- the repository owns file layout, atomic replacement, revisions, and storage errors
- the workspace service owns creation and analyst workflow validation
- future presentation layers call the service instead of editing files directly

> The workspace service manages analyst-owned investigation workflow. It does not rerun analysis, rewrite generated cases, or alter pipeline-produced artifacts.

### Creation and Results

Creation accepts a caller-supplied investigation ID, title, source analysis ID,
case IDs, logical artifact keys, optional owner, initial status, and an
injected timestamp. Case IDs become stable `EvidenceReference` objects; case
or analysis payloads are not copied.

Modifying operations return `WorkspaceResult`, containing the new frozen
`Investigation` and its repository revision. Deletion returns
`WorkspaceDeletionResult`, containing the deleted investigation ID and its
last revision. Listing returns typed `InvestigationSummary` objects.

### Status Policy

The local analyst status vocabulary is:

```text
open
in_progress
escalated
closed
```

Allowed transitions are:

- `open -> in_progress`
- `open -> closed`
- `in_progress -> escalated`
- `in_progress -> closed`
- `escalated -> in_progress`
- `escalated -> closed`

A closed investigation can move to `in_progress` only through the explicit
reopen operation. Requesting the current status is idempotent and does not
change the timestamp or revision. Status does not imply containment,
remediation, severity, or response action.

### Owners, Annotations, and Decisions

An owner is an opaque local analyst label, not an authenticated username or
email address. Labels are trimmed when assigned; `None` clears ownership;
empty labels are rejected. Investigation ownership never changes generated
case ownership.

Annotations are plain-text analyst notes with caller-supplied IDs, controlled
target types, author labels, creation timestamps, and update timestamps.
Duplicate IDs and empty text are rejected. Editing preserves creation time and
position; removal affects only the selected annotation.

Decisions are append-only analyst records with caller-supplied IDs, type,
outcome, rationale, author, timestamp, and optional evidence or hypothesis
references. Duplicate IDs and empty rationales are rejected. Recording a
decision does not automatically change investigation status.

### Revisions and Local Concurrency

Every update and deletion requires the caller's expected repository revision.
A current revision succeeds and returns the next revision. A stale revision
raises `InvestigationConflictError`; the service does not retry, merge, or
silently replace another session's work.

Unchanged owner or status requests are idempotent after the expected revision
is verified. The repository still provides atomic local file replacement, but
there are no cross-process locks or multi-user transaction guarantees.

## Analysis Bootstrap Adapter

`soc_forge.investigations.bootstrap.InvestigationBootstrapAdapter` is the only
investigation-layer component that understands `AnalysisResult`. Its dependency
direction is deliberately one-way:

```text
Pipeline
  -> AnalysisResult
  -> InvestigationBootstrapAdapter
  -> InvestigationWorkspaceService
  -> InvestigationRepository
```

The workspace service, repository, and domain models do not import the
pipeline. The adapter calls the workspace service and never writes repository
files directly.

> The bootstrap adapter translates completed analysis output into investigation references. It does not rerun analysis or copy pipeline-owned evidence into the investigation aggregate.

### Source Analysis Identity

The adapter creates a frozen `AnalysisProvenance` manifest for every newly
bootstrapped investigation. Its derivation algorithm is
`sha256-canonical-json-v1`. The manifest records:

- provenance schema version `1.0`
- input basename normalized across Windows and POSIX separators
- SHA-256 digests of normalized events, alerts, cases, and reconstructions
- a SHA-256 digest of the sorted rule IDs present in completed alerts
- the sorted logical artifact keys present
- the resulting source-analysis ID

Nested mappings are normalized by sorted string keys before hashing. Sequence
order is retained because completed event and result order can be meaningful;
set-like values and artifact keys are sorted. The source-analysis ID is the
first 20 hexadecimal characters of the SHA-256 digest of the canonical
provenance manifest, prefixed with `analysis-`.

Absolute input paths, output paths, artifact paths, Python object
representations, and rendered HTML do not participate. Raw events, alerts,
cases, and reconstructions are hashed for identity but are not copied into the
investigation.

> The source-analysis identifier represents canonical completed-analysis provenance, not a filesystem location or presentation artifact.

Changing normalized event content, alert content, case membership, case
content, reconstruction content, observed rule IDs, or logical artifact keys
changes the source-analysis ID. Dictionary insertion order and artifact path
location do not.

The separate bootstrap ID hashes the source-analysis ID and sorted selected
case IDs. Selecting a different case set changes the bootstrap ID but does not
redefine the underlying source-analysis ID. Investigation ID and creation time
do not affect either identity.

Epic 1 records without `provenance` remain valid schema 1.x records. Their
existing `analysis_id` is retained as a legacy identifier and is not silently
reinterpreted as the canonical algorithm. Newly bootstrapped records store
both the source-analysis ID and its provenance metadata.

### Selection, Artifacts, and Titles

Callers must explicitly select at least one case. Every selected ID must exist
in the completed result. Duplicate selections are normalized, and selected IDs
are sorted for deterministic requests. The adapter does not infer related cases
or silently select every case.

The `cases` artifact key is required because persisted evidence references point
to completed case output. Other present artifact keys are optional. The adapter
passes only sorted logical keys; it does not persist their filesystem paths,
open reports, copy files, or inspect artifact contents.

A single-case request uses that case's title. A multi-case request uses the
title of the first case in deterministic case-ID order plus the number of
additional cases. A caller-supplied, nonblank, single-line title takes
precedence.

### Side Effects and Limitations

`build_creation_request()` is a pure mapping operation. It returns a frozen
`InvestigationBootstrap` containing only investigation creation values and
stable references. `bootstrap_investigation()` passes that request to the
workspace service, which creates the investigation-owned repository record.

The adapter does not mutate `AnalysisResult`, nested cases, artifact mappings,
or artifact contents. It does not rerun detection, correlation, case building,
or reconstruction. Logical artifact references can become stale if users move
or delete completed analysis artifacts; refreshing or repairing those
references is outside this slice.

## Analyst Console Integration

The analyst console uses the shared workspace service. It does not edit investigation JSON files or pipeline artifacts directly.

The console keeps the most recently completed in-process `AnalysisResult` available
for explicit case selection. Creating an investigation passes that completed result,
the selected case ID, and caller-supplied workspace metadata through
`InvestigationBootstrapAdapter`. The adapter creates the workspace through
`InvestigationWorkspaceService`; the console does not reconstruct analysis state
from generated JSON files.

The default local workspace root is:

```text
out/workspace/
  investigations/
    <investigation-id>.json
```

The console displays repository revisions after creation and each successful
modification. When a stale revision is detected, it does not overwrite the newer
record; it reloads and displays the current revision. Deleting a workspace removes
only the investigation record and leaves all referenced analysis artifacts intact.

This integration remains local and single-user in scope. Owner and author values
are labels, not authenticated identities. The console adds no persistence format,
pipeline behavior, report behavior, web route, or export capability.
