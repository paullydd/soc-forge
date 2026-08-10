# Investigation Handoff Packages

## Purpose and Boundary

A handoff package is a read-only snapshot of one durable investigation revision
and its referenced analysis context. Creating a handoff does not modify the
investigation or analysis artifacts.

The reusable boundary is:

```text
Completed AnalysisResult + Durable Investigation
  -> InvestigationQueryContext
  -> InvestigationTimelineService
  -> InvestigationHandoffService
  -> deterministic directory bundle
```

The handoff service validates provenance, projects durable analyst state, uses
the shared scoped timeline, copies approved analysis artifacts, writes integrity
metadata, and validates the completed bundle. It does not run detections,
correlations, hunts, case construction, or the analysis pipeline. It does not
change evidence, hypotheses, decisions, annotations, status, ownership, or
repository state.

## Directory Contract

Slice 1 produces a plain directory rather than ZIP or TAR:

```text
<output-root>/<investigation-id>/
  manifest.json
  investigation.json
  evidence_index.json
  hypotheses.json
  decisions.json
  annotations.json
  timeline.json
  limitations.json
  source_artifacts/
    alerts.json
    cases.json
    events.json
    hunts.json
    reconstructions.json
    report.html
```

Only artifact files present in the completed analysis are copied. JSON uses
UTF-8, sorted keys, two-space indentation, and one trailing newline. Lists with
no semantic source order are sorted explicitly. Exports of identical analysis
content and the same investigation revision are byte-for-byte deterministic.

The default re-export policy is to fail if the target investigation directory
already exists. Callers must explicitly request overwrite. Export content is
built in a staging directory and published only after validation and the final
revision check.

## Manifest and Identity

`manifest.json` is schema version `1.0` and contains:

- deterministic handoff ID
- investigation and source-analysis IDs
- provenance algorithm and version
- exact investigation revision
- deterministic creation timestamp from the investigation snapshot
- owner and status
- selected case IDs
- logical artifact references
- the existing handoff identity manifest projection
- creation tool and package version
- limitations and the sensitive-data warning
- an inventory containing filename, logical type, byte size, and SHA-256 for
  every component except `manifest.json`

The handoff ID is SHA-256 derived from schema version, investigation ID,
source-analysis ID, revision, selected cases, selected evidence identity and
classification, evidence rationale, hypothesis IDs and states, decision IDs,
annotation IDs, and timeline-selection IDs. It does not include output paths,
temporary paths, dictionary insertion order, file ordering, or an export-only
clock value.

Workbench opaque entity IDs are not exported because they are transient browser
transport identifiers, not durable investigation references.

## Investigation and Evidence

`investigation.json` contains bounded workspace metadata, selected case IDs,
source-analysis ID, revision, and current query limitations. It is not the
repository envelope and contains no repository path.

`evidence_index.json` separates analyst-selected evidence from case-scope
references. Analyst selections retain classification, rationale, author,
selection timestamps, related case IDs, sensitive-field indicators, and a
bounded provenance summary. Scope references are not described as reviewed
analyst evidence. Raw event and alert payloads are not embedded in the evidence
index.

## Reasoning and Annotations

`hypotheses.json` preserves analyst statements, current states, author and
timestamps, supporting and contradicting evidence IDs, and assessment decision
references. A supported hypothesis remains an analyst assessment rather than an
objective fact.

`decisions.json` preserves every durable decision's stored type, outcome,
rationale, author, timestamp, and evidence or hypothesis references. Unknown
legacy decision types remain unchanged.

`annotations.json` preserves target identity, author, text, and timestamps.
Annotation text is explicitly marked sensitive analyst-authored content.

## Timeline

`timeline.json` is produced through the shared read-only timeline service. It
contains the complete deterministic scoped timeline, separated into timed and
untimed entries. Entries retain stable source and evidence identities, bounded
summary, machine or analyst context, case IDs, normalized entity fields, rule
and ATT&CK fields, evidence and reasoning overlays, relationship reason, and
sensitive-field indicators. Full command lines, raw source messages, annotation
bodies, and analyst rationale are not copied into timeline entries.

Persisted `TimelineSelection` metadata is included when present. Slice 1 does
not add selection mutation workflows. Transient entity transport IDs are
excluded from selection export.

## Artifact Policy and Path Safety

The artifact allowlist is:

- `alerts`
- `cases` (required)
- `events`
- `hunts`
- `reconstructions`
- `report`

Unknown logical keys fail export. Missing `cases` fails export; another missing
allowlisted artifact is recorded as a limitation. Artifact sources must be
regular, non-symlink files below the completed analysis output root. Fixed safe
destination names prevent caller-controlled filenames from entering the bundle.
Copied bytes are hashed and compared with their source.

Investigation IDs must be safe single path segments. Output roots and inventory
members are resolved and checked against their approved roots. Absolute member
paths, parent traversal, backslash member names, symlink escapes, and unexpected
files are rejected. Workspace repository files are never artifact candidates.

## Revision Consistency

The service loads one authoritative repository revision, constructs the bundle
from that immutable investigation snapshot, then reloads the record before
publication. A revision or aggregate change produces a controlled conflict and
the staged bundle is removed. This is a local consistency check, not locking or
transaction isolation.

## Integrity Validation

`validate_handoff_bundle(path)` requires no original repository. It verifies:

- manifest presence and supported schema
- required component presence
- safe inventory paths and absence of unexpected files
- recorded size and SHA-256 for every inventoried file
- investigation and analysis identity alignment
- hypothesis-to-evidence references
- assessment-decision references
- decision-to-evidence and decision-to-hypothesis references
- timeline hypothesis and decision references

The integrity manifest is not a digital signature and does not establish
authenticity against a malicious party who can rewrite both files and manifest.
Digital signing is outside Slice 1.

## Sensitive Data and Limitations

> This handoff may contain sensitive security telemetry and analyst-authored
> content. Review and redact before external sharing.

Slice 1 does not automatically redact content. It centralizes evidence,
hypothesis, decision, annotation, and timeline serializers so a later explicit
redaction policy can be applied without changing analysis or investigation
models.

The handoff foundation provides no upload, cloud sharing, email delivery,
authentication, digital signature, archive packaging, UI control, or hosted
behavior.
