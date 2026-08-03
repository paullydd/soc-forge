# Hypotheses and Decisions

SOC-Forge keeps analyst reasoning in the investigation layer:

    Pipeline-owned analysis
      -> provenance-aware analyst-selected evidence
      -> InvestigationReasoningService
      -> InvestigationWorkspaceService
      -> InvestigationRepository

The pipeline, detections, cases, reconstructions, and reports remain unaware of
hypotheses and decisions.

> A hypothesis is an analyst-authored investigative statement, not an automatically generated conclusion.

Machine finding is not the same as analyst conclusion. Evidence selection is
not the same as hypothesis assessment. Hypothesis state is not investigation
status. A decision is not an automated response.

## Hypothesis States

- open: the statement remains under investigation.
- supported: the analyst assesses that current evidence supports it.
- rejected: the analyst assesses that current evidence contradicts it.
- inconclusive: current evidence is insufficient or materially mixed.

New hypotheses begin open. An open hypothesis can be assessed as supported,
rejected, or inconclusive. An assessed hypothesis must be explicitly reopened
before another terminal assessment. Reopening records why review resumed.
Requesting the current state is idempotent and creates no revision or decision.

> A supported hypothesis reflects the analyst's assessment of the current evidence. It does not establish objective or legal certainty.

Hypotheses are durable and cannot be deleted through this service. Corrections
occur through statement editing, relationship changes, reopening, and
Editing a statement preserves its creation timestamp, state, and evidence
relationships while recording the editing analyst as the current author.

reassessment. This preserves the reasoning history.

## Evidence Relationships

Only analyst-selection evidence may be attached to a hypothesis. Bootstrap scope
references establish investigation scope but do not prove analyst review.

Relationship and classification must agree:

- supporting relationship requires supporting classification
- contradicting relationship requires contradicting classification
- context evidence cannot be attached as supporting or contradicting

One evidence reference cannot be both supporting and contradicting for the same
hypothesis. Adding an existing relationship and removing a missing relationship
fail explicitly. Relationship changes update the hypothesis timestamp but never
change its state automatically.

Evidence referenced by a hypothesis or decision cannot be removed. Relationships
must be removed explicitly first. Nothing is cascade-deleted and evidence
removal never changes hypothesis state.

## Assessments and Reopening

Moving an open hypothesis to a terminal assessment requires nonblank rationale,
an opaque analyst label, a caller-supplied decision ID, and the current revision.

The service updates hypothesis state and appends a hypothesis-assessment decision
in one aggregate save. The decision links the hypothesis and its current
supporting and contradicting evidence. Previous decisions are never overwritten.

Reopening follows the same append-only approach. It returns the hypothesis to
open, preserves evidence relationships and earlier assessments, and appends a
decision with outcome reopened. Assessment and reopening do not alter
investigation status.

## Decision Types

The initial controlled vocabulary is:

- hypothesis assessment
- escalation
- containment recommendation
- closure rationale
- investigative conclusion

Every decision has a caller-supplied ID, type, outcome, nonblank rationale,
author, timestamp, and optional evidence or hypothesis references. Referenced
IDs must exist. Decisions are append-only.

> Decisions record analyst reasoning and recommended disposition. They do not perform containment, remediation, or response actions.

Containment recommendations record what an analyst recommends. They do not
claim an action occurred.

## Queries

The reasoning-summary query returns deterministic ordering, state counts,
hypotheses lacking evidence, mixed-evidence hypotheses, decision count, and the
last reasoning update. It does not rank hypotheses, calculate confidence, or
infer truth.

## Concurrency

Every modifying operation requires the expected revision. Stale revisions use
the existing conflict contract. There is no retry, automatic merge, or cascade.
Failed validation does not save or increment the revision. The existing local
single-writer limitation remains.

## Known Limits

- No hypothesis or decision web controls exist in Slice 2.
- No hypothesis deletion or archival workflow exists.
- No machine-generated hypotheses, confidence scoring, or automated conclusions.
- No containment, response execution, timeline pivots, handoff export, or
  hosted multi-user behavior.
- Analyst labels are opaque local metadata rather than authenticated identities.


## Analyst Console Workflow

The durable investigation workspace exposes **Hypotheses and Decisions** as a
separate reasoning area. Its summary is produced by the shared reasoning
service and shows hypothesis state counts, evidence gaps, mixed-evidence
hypotheses, decision totals, and the latest reasoning update.

The terminal workflow is:

```text
Open investigation
-> Open Hypotheses and Decisions
-> Create hypothesis
-> Attach selected evidence
-> Assess with rationale
-> Reopen if new evidence emerges
-> Review durable decision history
```

Hypotheses are analyst-authored plain text. Creation and later relationship
changes offer only durable analyst-selected evidence. Supporting relationships
offer supporting-classified evidence, contradicting relationships offer
contradicting-classified evidence, and context or bootstrap scope references are
excluded. Relationship removal leaves the selected evidence in the
investigation.

Open hypothesis statements can be edited without changing their IDs, state,
creation time, evidence relationships, or decision history. Assessment records
supported, rejected, or inconclusive with a rationale and an append-only
assessment decision. Reopening is explicit, preserves prior evidence and
decisions, and records another assessment-history entry.

The general decision form supports escalation, containment recommendation,
closure rationale, and investigative conclusion. It cannot create a hypothesis
assessment. General decisions may reference existing hypotheses and
analyst-selected evidence, remain read-only after creation, and never execute a
response action or change investigation status.

Hypotheses, decisions, and persisted evidence metadata remain viewable without
an active analysis. Underlying source detail still requires the existing
evidence workspace, a matching active analysis provenance identity, and the
sensitive-value reveal confirmation. The console does not open artifact paths
directly or substitute a different analysis.

On a revision conflict, the console does not retry or merge. It reloads and
shows the authoritative revision and keeps the analyst's drafted statement or
rationale visible where practical. Analyst reasoning and evidence values may
remain in terminal scrollback and should be handled as sensitive telemetry.

> The console records analyst-authored reasoning through the shared reasoning service. It does not generate conclusions from alerts or cases.

## Web Reasoning Workflow

The local web investigation detail screen includes a **Hypotheses and
Decisions** section with reasoning counts, hypothesis creation and inspection,
assessment and reopening, and append-only decision history.

```text
Open investigation
-> Create hypothesis
-> Attach selected evidence
-> Assess with rationale
-> Reopen if new evidence emerges
-> Review durable decision history
```

The browser offers only persisted analyst-selected evidence. Supporting pickers
show supporting-classified selections, contradicting pickers show
contradicting-classified selections, and scope or context references are not
offered for hypothesis relationships. General decisions may reference existing
hypotheses and analyst-selected evidence.

All reasoning mutations send the authoritative workspace revision. A conflict
returns HTTP 409 with the latest durable workspace; the browser reloads it
without retrying or merging and retains the drafted statement or rationale in
memory where practical. Drafts are not stored in local storage.

Hypotheses, decisions, and persisted evidence metadata remain readable when no
matching analysis is active. Source payload inspection remains in the evidence
workspace and requires matching analysis provenance.

Reasoning responses use `Cache-Control: no-store`. Analyst-authored text is
rendered through safe DOM text nodes, IDs are URL-encoded, and rationale is
never placed in a URL. Reasoning may still remain visible in browser history,
developer tools, or screenshots and should be handled as sensitive content.

> Web reasoning routes use the shared reasoning service. They do not infer conclusions, alter analysis output, or perform response actions.
