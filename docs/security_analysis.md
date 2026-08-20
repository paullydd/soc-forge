# Security Analysis

Security Analysis describes patterns and activity across SOC-Forge data.
Detection owns what can fire and what fired; Investigations own what evidence
supports for one issue; Operations owns what work needs attention.

## Threat Activity Overview

Threat Activity Overview is a deterministic, immutable, read-only projection.
It describes observed or recorded security activity. It does not rank analyst
work or measure detection coverage.

The durable Investigation repository supplies analyst-authored Investigations,
Findings, Response Actions, status, explicit Finding ATT&CK mappings, and
timestamps. The active completed AnalysisResult, when present, supplies current
machine alerts, cases, hunts, reconstructions, explicit alert ATT&CK mappings,
and alert timestamps. Saved snapshots and arbitrary output directories are not
scanned or activated. No overview state or activity index is persisted.

## FULL and OFFLINE

FULL means current machine analysis is active. OFFLINE means only durable
Investigation state is available. Durable counts remain usable, while machine
counts say Unavailable; missing machine context is never presented as zero.

## Observed ATT&CK activity

Each alert and Finding contributes at most one machine or analyst observation
per distinct explicit mapping it carries. Mappings are not inferred from rule
IDs or the catalog. Coverage describes what rules can represent; Threat
Activity describes what machine analysis and analyst Findings recorded.

## Recent activity, attribution, and safety

The bounded list uses alert timestamps, Finding updates, and Response Action
transition timestamps. It is reverse-chronological with stable tie-breaks and
[MACHINE]/[ANALYST] labels. Building and rendering use repository reads only.
They do not mutate or persist. Drill-down, Entity Explorer, Cross-Investigation
Analysis, and Temporal Analysis remain deferred.
