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
- canonical source-content qualifier
Native event record IDs and alert IDs are used when present. An event without a
native record identifier receives a source ID derived from canonical event
content. Alerts without native IDs receive a source ID derived from canonical
alert content. Cases use their stable case IDs. Reconstruction-step source IDs
include the owning case ID and canonical step content.

Native identifiers are contextualized or content-qualified before they are used
as evidence identity. Materially different records are never silently merged
solely because they share a native identifier. Host, channel, provider, event
ID, timestamp, rule context, case context, and the canonical payload contribute
through the source-content qualifier when present; absolute paths do not.

Identical same-type duplicates deliberately deduplicate and merge proven case
relationships. If the bounded ID ever matches while canonical payloads differ,
catalog construction raises an explicit identity-collision error rather than
retaining one payload. Legacy pre-hardening evidence IDs remain lookup aliases:
one unambiguous match resolves to the hardened candidate, while multiple matches
raise an ambiguity error. Persisted records are not automatically migrated.
Because the legacy v1 provenance algorithm retained completed-analysis list
order, legacy alias reproduction requires the same collection order used when
the legacy record was created. Failed legacy resolution never rewrites or
guesses at persisted identity.

The evidence type participates in the digest, so identical source IDs in
different type namespaces remain unambiguous. Absolute paths, report content,
object identity, analyst state, and candidate presentation order do not
participate. IDs use truncated SHA-256 digests; collision resistance follows
the assumptions of a 96-bit truncated digest and is not a substitute for an
external evidence-signing system.

Candidate-detail HTTP responses use Cache-Control: no-store, including explicit
sensitive-value reveals. Evidence values are never placed in URLs. The web workbench likewise uses
opaque entity IDs for navigation, so source entity values appear only in
response bodies and not URL paths or query parameters.

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

The repository remains local and single-writer in scope. This slice adds no locking, database, web routes, exports, or hosted behavior.


## Analyst Console Evidence Workflow

The durable investigation workspace includes a focused evidence screen:

```text
Open investigation
  -> Browse evidence
  -> Inspect provenance
  -> Select and classify
  -> Record rationale
  -> Reopen later
  -> Review or update selection
```

Candidate discovery is limited to the investigation's selected cases and can
show all supported types or only events, alerts, cases, or reconstruction
steps. The catalog supplies deterministic ordering, stable identities,
relationships, sensitive-field labels, and bounded details. The console does
not perform free-text search, infer relationships, or display raw payloads.

Evidence discovery and source-detail inspection require the completed
`AnalysisResult` to be active in the current console session. Its catalog-
derived provenance ID must exactly match the investigation's source-analysis
ID. A different analysis is refused even when it contains matching case IDs.
General analysis-session restoration is not available yet. Persisted analyst
metadata remains reviewable when the matching analysis is unavailable, but
source details cannot then be resolved.

Sensitive field names are always identified. Displaying sensitive values, such
as command lines, requires explicit confirmation and uses bounded catalog
details. Declining keeps those values hidden. Terminal scrollback may retain
any sensitive values the analyst chooses to display, so the terminal session
must be handled as sensitive investigation material.

Selection requires a controlled supporting, contradicting, or context
classification, a nonblank rationale, an author label, and confirmation.
Bootstrap scope references are displayed separately and never counted as
analyst-selected or reviewed evidence. Selection updates preserve the source
evidence identity and original selection timestamp. Removal requires
confirmation and is refused while a hypothesis or decision still references
the evidence; relationships are never cascade-deleted.

Every mutation uses the currently displayed repository revision. On conflict,
the console does not retry or merge. It reloads the latest investigation,
reports the new revision, and displays a bounded copy of an attempted rationale
where practical so the analyst can re-enter it.

> The console resolves evidence through the shared catalog and records analyst selections through the evidence service. It does not derive identities or copy source payloads.


## Web Evidence Workflow

The durable web investigation workspace exposes the same evidence catalog and
selection service as the analyst console:

```text
Open investigation
  -> Browse evidence
  -> Inspect provenance
  -> Reveal sensitive value if required
  -> Select and classify
  -> Add rationale
  -> Reopen later
  -> Review or update selection
```

The Evidence section displays scope, selected, supporting, contradicting, and
context counts. Candidate filters are limited to `all`, `event`, `alert`,
`case`, and `reconstruction_step`. Discovery is constrained to relationships
proven for the investigation's selected cases; an empty filter result does not
cause the web layer to infer a relationship.

Candidate lists contain bounded metadata, sensitive-field names, and provenance
limitations. Detail responses contain only catalog-resolved bounded fields and
field-level provenance. Sensitive values are omitted by default and require an
explicit browser confirmation that requests `include_sensitive=true`. SOC-Forge
does not automatically redact values after reveal. Browser history, developer
tools, terminal logs, and screen captures can retain investigation data.

Bootstrap scope references are shown separately and are not classified as
analyst-reviewed evidence. Analyst selections require a controlled
`supporting`, `contradicting`, or `context` classification, nonblank
rationale, author label, and current revision. Updates cannot change source
identity or selection origin. Removal never cascades and fails while a
hypothesis or decision still references the evidence.

Candidate discovery and source-detail resolution require the server's active
completed analysis to match the investigation provenance exactly. Persisted
selection metadata remains available after a server restart without active
analysis, but source details report unavailable until the matching analysis is
run again. The server does not reopen arbitrary artifact paths.

On revision conflict, the API returns only a bounded error with the investigation
ID and authoritative current revision. The browser fetches the latest workspace
separately without automatic retry or silent merge and retains the attempted
selection fields in transient memory.
`localStorage` is not a source of truth.

The evidence routes are:

```text
GET    /api/investigations/{id}/evidence/candidates?type={type}
GET    /api/investigations/{id}/evidence/candidates/{evidence_id}
GET    /api/investigations/{id}/evidence/candidates/{evidence_id}?include_sensitive=true
GET    /api/investigations/{id}/evidence/selections
POST   /api/investigations/{id}/evidence/selections
PUT    /api/investigations/{id}/evidence/selections/{evidence_id}
DELETE /api/investigations/{id}/evidence/selections/{evidence_id}
```

Selection creation accepts `evidence_id`, `classification`, `rationale`,
`author`, and `expected_revision`. Updates accept only `classification`,
`rationale`, `author`, and `expected_revision`. Deletion requires
`expected_revision`. Selection responses separate `scope_references` from
`analyst_selections` and include classification counts plus the authoritative
revision.

Web and console selections share one durable repository representation.
Evidence chosen through either interface is immediately readable and editable
through the other, subject to revision checks.

The web server remains a local-only tool: loopback is the default, there is no
authentication, and non-loopback binding prints a warning. No permissive CORS
policy is added. Analyst and telemetry strings are rendered as text in the
evidence UI.

> Web evidence routes use the shared catalog and evidence service. They do not derive identities, infer relationships, or copy source payloads.

## Terminal Presentation

The terminal Evidence workspace uses the shared v3.2 breadcrumb, state panel, grouped menu, candidate cards, and selected-evidence cards. Candidate type choices, ordering, filtering, source-analysis checks, selection flow, and all sensitive-data confirmations remain unchanged. Classification is always textual as `SUPPORTING`, `CONTRADICTING`, or `CONTEXT`; color is supplementary.

Rendering is passive. The controller retains input and dispatch ownership, and only `InvestigationEvidenceService` may change selected evidence or investigation revision.
