# Investigation Summary

The investigation summary is a deterministic, read-only projection of one durable investigation. It condenses existing machine findings and analyst-authored reasoning for presentation without creating conclusions, changing investigation state, or rerunning analysis.

## Ownership

```text
InvestigationWorkspaceService
  + optional matching AnalysisResult
  -> InvestigationQueryContext
  -> InvestigationTimelineService
  -> InvestigationSummaryService
  -> immutable InvestigationSummary
  -> web presentation
```

`InvestigationSummaryService` owns summary composition. It loads durable state through `InvestigationWorkspaceService`, validates an optional completed analysis with `InvestigationQueryContext`, and delegates chronology to `InvestigationTimelineService`.

The service does not run detections, build cases, infer attacks, generate scores, call an LLM, create hypotheses, or mutate the repository, investigation revision, analysis result, or artifacts.

## Public API

```python
service = InvestigationSummaryService(workspace_service)
summary = service.summarize(investigation_id, analysis=None)
```

The result and all nested models are frozen dataclasses. `to_dict()` provides a deterministic structured representation. No generation timestamp is included.

## Full And Offline Modes

**Full mode** requires the exact matching `AnalysisResult`. It includes selected case titles, relevant rules, severity and ATT&CK context, source-evidence sensitivity indicators, and the existing canonical timeline projection.

**Offline mode** requires only durable investigation state. It includes identity, owner, status, revision, source-analysis ID, annotations and counts, persisted evidence metadata, hypotheses, assessments, and decisions. Case, rule, ATT&CK, source-detail, and timeline context are omitted and named as limitations.

A missing, mismatched, or reference-incompatible analysis produces a bounded offline summary. The service never substitutes a similar scenario, case ID, rule set, or active analysis.

## Machine And Analyst Attribution

Summary entries label their ownership:

- `machine`: cases, alerts, reconstructions, rule metadata, severity, and ATT&CK mappings.
- `analyst`: evidence classifications and rationales, hypotheses, assessments, decisions, and annotations.

Hypothesis state is described as an analyst assessment. A supported hypothesis is never presented as a confirmed attack.

## Narrative Policy

The narrative is template-based and deterministic. It uses investigation identity, selected case titles, bounded counts, analyst hypothesis states, and timeline counts already represented by the structured summary.

It does not quote raw event messages, command lines, full annotations, full evidence rationales, or full decision rationale. It does not introduce causal language or recommendations that are absent from durable state.

## Ordering And Bounds

Case IDs, evidence, hypotheses, decisions, classifications, rule IDs, severity values, ATT&CK values, and limitations use deterministic ordering. Reordering source or investigation collections does not change semantic output.

- Evidence and decision rationale summaries: 160 characters.
- Hypothesis statements and case titles: 160 characters.
- Narrative: 640 characters.
- Timeline milestones: at most six existing timed entries.

Full details remain available through their existing investigation workflows.

## Sensitive Data And Limitations

Summaries can contain case titles, source IDs, host or identity context present in bounded query projections, and analyst-authored reasoning. The top-level result conservatively marks that it may contain sensitive content. Each selected evidence summary indicates whether source-sensitive fields are known in full mode; offline mode reports that value as unknown.

The summary does not automatically reveal protected evidence values. Consumers must continue using the existing explicit evidence-detail reveal workflow for sensitive source fields.

Timeline limitations from the canonical timeline service are preserved. Offline mode explicitly identifies unavailable machine context. The web adapter exposes the projection at `GET /api/investigations/{id}/summary`. It selects only the exact matching process-local analysis; otherwise the service returns its bounded offline projection. The browser does not reveal protected evidence values and delegates detail navigation to the existing evidence, reasoning, and timeline workflows. The summary adds no export format, report integration, or handoff change.
