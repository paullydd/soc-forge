# Completed Analysis Snapshots

Completed analysis snapshots preserve the exact `AnalysisResult` required by source-dependent investigation features after the analyst console restarts.

## Architecture

```text
Input or scenario
  -> shared analysis pipeline
  -> AnalysisResult
  -> CompletedAnalysisSnapshotStore
  -> immutable snapshot

Durable investigation + matching snapshot
  -> validated AnalysisResult
  -> InvestigationQueryContext
  -> timeline, pivots, evidence inspection, and handoff
```

The snapshot store is independent of `InvestigationRepository`. It never runs detections, reconstructs an analysis through the pipeline, changes an investigation, or relaxes provenance validation.

## Storage and identity

Snapshots are stored locally under:

```text
<analysis-output>/analysis_snapshots/<source_analysis_id>/
```

The existing `source_analysis_id` is the only snapshot identity. Snapshot schema version `1.0` stores identity-bearing collections and all investigation-consumed `AnalysisResult` fields.

Each manifest contains collection counts, observed rule IDs, logical artifact keys, SOC-Forge version, file sizes, and SHA-256 digests. Absolute source paths are not stored. Snapshot creation timestamps are excluded from analysis identity.

## Immutable publication

Publication uses a staged directory and validates reconstructed provenance before publishing.

- A missing snapshot is published atomically.
- An existing byte-equivalent valid snapshot is accepted as already present.
- A corrupt or materially different snapshot using the same ID is rejected.
- Valid snapshots are never overwritten or repaired automatically.

Every distinct timestamped simulation run has a distinct source analysis ID and snapshot. Rerunning a scenario is not recovery.

## Recovery

From an open durable investigation, choose **Load source analysis snapshot**. SOC-Forge validates schema, paths, inventory sizes, SHA-256 digests, the recomputed source analysis ID, and selected case/evidence references before activating the result in process memory.

Recovery does not increment the investigation revision, rewrite repository bytes, alter source artifacts, or silently rebind the investigation.

Snapshots created before process loss can be recovered after restart. Analyses completed before snapshot support, or whose reusable source files were overwritten before a snapshot was created, cannot be recovered by this mechanism.

## Security

Snapshots contain sensitive telemetry including usernames, hosts, IP addresses, command lines, alerts, cases, and investigation context.

- Storage is local only.
- Traversal, absolute paths, symlinks, missing files, corruption, unsupported schemas, count mismatches, and provenance mismatches are rejected.
- No external resources are fetched.
- SHA-256 provides integrity checking, not cryptographic authenticity.
- Similar scenario names, case IDs, alerts, or rule sets never substitute for exact provenance.

The initial slice integrates console publication and explicit console recovery. Web investigation APIs continue to require a matching active analysis; explicit web snapshot activation is a later integration slice.
