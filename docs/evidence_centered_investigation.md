# Evidence-Centered Investigation

SOC-Forge keeps completed analysis immutable while allowing an analyst to record
how specific evidence is used inside an investigation:

```text
Pipeline
  -> AnalysisResult
  -> AnalysisEvidenceCatalog
  -> InvestigationEvidenceService
  -> InvestigationWorkspaceService
  -> InvestigationRepository
  -> Investigation
```

Only `AnalysisEvidenceCatalog` and the bootstrap adapter depend on the concrete
`AnalysisResult`. The evidence service, workspace service, repository, and
domain models remain pipeline-independent.

> Evidence selection records an analyst's use of existing completed-analysis evidence. It does not alter the original telemetry, alert, case, or reconstruction.

## Evidence Catalog

`AnalysisEvidenceCatalog` is a read-only adapter over one completed in-memory
analysis. It does not run pipeline stages, open artifact paths, read report
HTML, write files, or mutate source collections.

The initial catalog supports:

- normalized source events
- alerts
- cases
- individual reconstruction steps

Reports, arbitrary files, generated prose, annotations, decisions, hypotheses,
external intelligence, and hunts are not catalog evidence in this slice.

The public operations are:

- `list_candidates(analysis_result, case_ids=None, evidence_types=None)`
- `get_candidate(analysis_result, evidence_id)`
- `resolve_details(analysis_result, evidence_id)`

Filtering is limited to case IDs and supported evidence types. Candidate order
is deterministic by timestamp, evidence type, and evidence ID. There is no
search, ranking, pagination, fuzzy matching, scoring, or enrichment.

## Evidence Identity

Every candidate ID is a bounded SHA-256-derived identifier over:

- canonical completed-analysis provenance ID
- evidence type
- stable source identifier

Native event record IDs and alert IDs are used when present. An event without a
native record identifier receives a source ID derived from canonical event
content. Alerts without native IDs receive a source ID derived from canonical
alert content. Cases use their stable case IDs. Reconstruction-step source IDs
include the owning case ID and canonical step content.

The evidence type participates in the digest, so identical source IDs in
different type namespaces remain unambiguous. Absolute paths, report content,
object identity, analyst state, and candidate presentation order do not
participate. IDs use truncated SHA-256 digests; collision resistance follows
the assumptions of a 96-bit truncated digest and is not a substitute for an
external evidence-signing system.

## Case-Scoped Discovery

A case-scoped catalog includes only relationships supported by completed
analysis:

- the selected case itself
- alerts matched to that case's existing item membership
- source events referenced by an explicit alert event-record field
- reconstruction steps carrying the selected case ID

Multiple selected cases produce a deduplicated deterministic union. Unrelated
alerts and events are excluded. Timestamp, entity, or field similarity is never
used to infer event-to-alert membership. A case item that cannot be resolved to
the completed alert collection is exposed as non-selectable with a limitation
reason. Alerts lacking explicit event references remain selectable but report
that source-event provenance is unavailable.

Context evidence outside the investigation's selected cases is not selectable
in this slice.

## Field Provenance and Sensitive Data

`EvidenceFieldProvenance` identifies the displayed field, source type, stable
source ID, source field, provenance kind, normalization status, and sensitivity
flag. Provenance kinds distinguish:

- raw source fields
- normalized event fields
- rule-generated interpretation
- case-derived context
- reconstruction-derived context

The catalog covers established fields such as timestamp, host, user, source IP,
process, command line, service, rule ID, severity, ATT&CK technique, case
membership, tactic, and reconstruction technique. `resolve_details()` returns
only these bounded fields; it does not return an unrestricted source payload.

Command lines, users, hosts, IP addresses, services, and related path-like
values are marked sensitive where present. The catalog does not redact them
automatically. Displays and future exports must review sensitive values before
sharing. Error messages contain logical IDs, not raw commands or absolute
paths. Analyst rationale is investigation-owned metadata and is never described
as source provenance.

## Analyst Selection

`InvestigationEvidenceService` provides:

- `select_evidence(...)`
- `update_evidence_rationale(...)`
- `remove_evidence(...)`

Selection requires a validated catalog candidate from the same source analysis
and within the investigation's case scope. It also requires a nonblank local
analyst label, nonblank rationale, current expected revision, and one controlled
classification:

- `supporting`: the analyst believes the evidence supports an investigative claim
- `contradicting`: the analyst believes the evidence weakens or disputes a claim
- `context`: relevant background without supporting or contradicting a claim

> Evidence classification represents analyst reasoning and must not be interpreted as machine-verified truth.

Duplicate selection raises a specific error. Classification or rationale
changes use the update operation. Successful mutations increment the repository
revision; failed validation and stale revisions do not modify the record.
Removal can fail aggregate integrity validation when another investigation
object already references the selected evidence.

Persisted selections contain stable references, classification, rationale,
author label, selection timestamps, source-analysis ID, case scope, and logical
provenance field names. They do not copy events, alerts, cases,
reconstructions, command-line payloads, or artifact files.

## Bootstrap Compatibility

Case references created during investigation bootstrap remain `scope`
references. They identify which completed cases bound the investigation but do
not carry classification, rationale, or analyst-review semantics.

Analyst-selected evidence uses the distinct `analyst_selection` origin.
Existing Epic 1 records omit the new optional fields and continue loading with
scope defaults. This is a backward-compatible schema 1.x extension.

The repository remains local and single-writer in scope. This slice adds no
locking, database, web routes, console menus, exports, or hosted behavior.
