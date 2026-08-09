# Timeline and Pivot Query Foundation

## Ownership

The read-only investigation query layer sits between a completed analysis and
future presentation code:

```text
AnalysisResult + Investigation
  -> InvestigationQueryContext
  -> InvestigationTimelineService / InvestigationPivotService
  -> frozen projections
```

Only `query_context.py` imports the concrete `AnalysisResult`. It validates
the investigation's source-analysis identity, selected cases, and analyst
evidence references, then builds deterministic in-memory indexes. The context
is never persisted and does not copy raw analysis payloads into investigation
state. Timeline and pivot services do not run pipeline stages or write
workspace or artifact data.

> Timeline and pivot results explain relationships already present in completed
> analysis and analyst-owned investigation state. They do not create new
> detections, correlations, or conclusions.

> Analyst reasoning overlays are contextual annotations on source activity and
> must remain distinguishable from telemetry and machine-generated findings.

## Canonical Timeline

`InvestigationTimelineService.timeline(context, filters=...)` returns frozen
`InvestigationTimelineEntry` projections in timed and untimed collections.
The initial entry types are event, alert, case, reconstruction step, analyst
evidence selection, hypothesis creation, hypothesis assessment, hypothesis
reopening, analyst decision, and annotation.

The default machine scope contains only selected cases, their explicit alert
members, source events explicitly referenced by those alerts, and reconstruction
steps owned by those cases. Shared hosts, users, or nearby timestamps do not
expand timeline scope. Analyst hypotheses, decisions, evidence selections, and
annotations belong to the investigation and are projected as analyst context.

Summaries are whitespace-normalized and bounded to 240 characters. Full command
lines, raw messages, evidence rationale, decision rationale, and annotation
bodies are not included. Sensitive field names and logical IDs remain available
for later explicit detail resolution.

## Time and Ordering

Parseable timestamps are converted to timezone-aware UTC and rendered with a
`Z` suffix. Naive timestamps are treated as UTC because existing normalized
SOC-Forge events use UTC semantics. Invalid, missing, or semantically unavailable
timestamps are never invented; those entries are returned in
`untimed_entries`.

Timed entries sort by:

1. UTC timestamp
2. entry-type precedence
3. stable entry ID

Precedence is event, alert, case, reconstruction step, analyst evidence
selection, hypothesis creation, hypothesis assessment, hypothesis reopening,
analyst decision, then annotation. Untimed entries use precedence and stable ID.

## Filters

`InvestigationTimelineFilters` supports time range, entry type, host, user, IP,
process, rule ID, ATT&CK tactic, ATT&CK technique, severity, evidence
classification, hypothesis ID, and case ID. Multiple populated fields use AND
semantics. Text identity uses the normalization rules below; controlled metadata
matching is case-insensitive. Unsupported filters and invalid ranges fail with
narrow query errors. There is no free-text, Boolean, fuzzy, ranked, natural
language, SQL, SPL, or similar query language.

## Entities and Normalization

`InvestigationEntity` supports host, user, IP, process, service, rule, ATT&CK
technique, case, evidence, and hypothesis.

- Host and service comparisons trim and case-fold while retaining display text.
- User comparisons trim and case-fold but preserve domain-qualified identity;
  `DOMAIN\\alice` and `OTHER\\alice` remain distinct.
- IP values must parse as IPv4 or IPv6 and use compressed canonical text.
  Invalid IP strings are not promoted to entity identities.
- Process projections retain the display path, a case-folded normalized path,
  and a case-folded basename. A basename pivot can match an observed full path.
- Rule identity is the exact rule ID.
- ATT&CK identity uses the canonical upper-case technique ID.
- Case, evidence, and hypothesis identities use their stable logical IDs.

No fuzzy similarity or silent domain removal is performed.

## Pivots and Relationships

`InvestigationPivotService` provides events, alerts, cases, evidence,
hypotheses, entity timelines, related entities, and hypothesis-to-evidence
queries. Each `PivotMatch` includes a source ID, relationship type, reason,
analysis provenance, case membership, timestamps where present, and limitations.

Relationships are limited to explicit source fields, alert/event references,
case membership, reconstruction ownership, analyst evidence selection,
hypothesis evidence IDs, and decision references. Time proximity and shared
entities do not establish a new attack relationship. Entity pivots may explore
outside the selected-case timeline, but only by direct field equality.

Related entities aggregate directly co-observed source records. Results include
source IDs, count, first seen, and last seen, and are deterministically bounded
to 100 entities. Other pivot results are bounded to 200 matches. Context indexes
are transient, read-only, and scoped to one analysis/investigation pair.

## Reasoning Overlays

Machine entries can indicate analyst selection and supporting, contradicting, or
context classification without changing the source entry. Hypothesis overlays
expose hypothesis IDs and their explicit evidence relationship. Decision
overlays expose decision IDs and types, not rationale. Hypothesis state remains
analyst context and is never presented as machine certainty.

Legacy evidence IDs are resolved through the existing Epic 2 catalog policy.
Ambiguous legacy identities retain the existing controlled ambiguity error.
The query context requires the matching completed analysis; persisted reasoning
without source analysis remains available through existing workspace and
reasoning services rather than this source-query layer.

## Limitations

This slice is an in-memory local query foundation. It adds no persistence,
database, locking, UI, HTTP routes, exports, detections, correlations, case
construction, causal inference, risk scoring, graph centrality, enrichment, or
hosted behavior.


## Analyst Console Workbench

Open a durable investigation from **Investigation Workspaces**, then choose
**Timeline and Pivot Workbench (Read Only)**. The workbench requires the active
completed analysis whose provenance matches the investigation. It does not
rerun analysis or substitute another result. If the analysis is unavailable or
does not match, the durable workspace remains intact and the query session does
not open.

The console workflow is:

```text
Open investigation
  -> Timeline and Pivot Workbench
  -> Review chronology
  -> Filter to host/user/rule
  -> Pivot into entity
  -> Inspect related evidence
  -> Return to timeline
```

The canonical timeline keeps service ordering unchanged and presents timed and
untimed entries in separate sections. Compact rows distinguish telemetry and
machine findings from analyst reasoning context. They show bounded summaries,
stable identifiers, evidence classifications, reasoning-overlay indicators,
and sensitive-field warnings without displaying command lines, raw messages,
annotation bodies, or analyst rationale.

Timeline filters cover time range, entry type, host, user, IP, process, rule,
ATT&CK tactic and technique, severity, evidence classification, hypothesis,
and case. Filters retain the query service's AND semantics. They are transient
to one workbench session, can be adjusted or cleared, and are never stored in
the investigation.

The entity browser presents query-layer identities for hosts, users, IPs,
processes, services, rules, ATT&CK techniques, cases, evidence, and hypotheses.
Pivots render only service-provided matches and relationship explanations.
Related entities mean directly co-observed source records; the console does not
describe them as causal or infer relationships from timing or similarity.

Evidence overlays remain explicitly labeled Supporting, Contradicting, or
Context. Hypothesis overlays retain their analyst-authored relationship and
state without becoming machine certainty. Decision overlays show ID and type,
including unknown legacy types, but omit rationale. Evidence, hypothesis, and
decision details delegate to the existing detail controllers rather than
copying their resolution or sensitive-value handling.

The workbench provides an explicit refresh action. If the durable investigation
revision changes during a session, further queries pause until refresh. If the
active analysis changes to mismatched provenance, the analyst must leave and
reopen the workbench with the matching completed analysis.

> The analyst console workbench is a read-only consumer of the shared
> investigation query layer. It does not create relationships, detections,
> cases, evidence selections, hypotheses, or decisions.

Opening, filtering, pivoting, viewing details, and refreshing do not change the
investigation revision, repository record, analysis result, or artifact files.
Sensitive source values remain governed by the existing evidence detail
confirmation. Analysts should remember that terminal scrollback can retain any
values they explicitly choose to reveal.
