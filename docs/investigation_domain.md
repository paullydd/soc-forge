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
