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
