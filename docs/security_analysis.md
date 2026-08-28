# Security Analysis

See the [v3.6 product walkthrough](walkthrough.md) for the current end-to-end interface tour.

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
They do not mutate or persist. Entity Explorer, Cross-Investigation Analysis,
Temporal Analysis, and Hunt Workspace use their own bounded deterministic views.

## Entity Explorer

Entity Explorer shows where structured entity values have been observed. Repeated observations do not establish a shared attacker or campaign.

Supported types are host, user, IP address, and process. Host and user comparison is trimmed and case-insensitive but does not merge account formats. IP values use validated compressed textual form with no subnet expansion. Processes use a case-insensitive Windows-path basename for exact matching while preserving the source display value. There is no fuzzy matching, alias resolution, identity stitching, or asset identity inference.

FULL mode combines the active AnalysisResult evidence catalog with durable Investigation links. Machine observations come from current normalized events, alerts, cases, and reconstruction steps that contain explicit structured entity fields. Analyst observations require an explicit selected-evidence link; Findings inherit only entities from their structured evidence references, and Response Actions inherit only through explicit Finding IDs. Prose is never parsed. OFFLINE mode reads durable state only and does not invent entity values from opaque evidence IDs or auto-load snapshots.

Related entities were explicitly co-observed in the same structured record. Counts mean Observed together N times; they are not relationship strength or causation. ATT&CK counts aggregate only mappings carried by matching observations and do not use Detection Coverage.

Protected evidence detail fields are not resolved for display. Current machine entity references use the evidence catalog's published structured references, and non-sensitive process details follow the existing machine-display policy. The explorer performs no reveal action, persistence, background indexing, enrichment, scoring, correlation, or mutation. Direct drill-down remains deferred until destination controllers expose a clean navigation contract.
## ATT&CK Activity Analysis

ATT&CK Activity describes explicit ATT&CK behavior observed or recorded in current SOC-Forge state. It does not measure detection completeness or establish campaign relationships.

One observation is one unique explicit ATT&CK mapping attached to one authoritative source object. Repeated identical mappings within the same source are deduplicated by source type, stable source ID, tactic, technique ID, and technique name. Distinct source objects remain distinct observations. Alert, explicitly mapped Case, and Reconstruction step observations are [MACHINE]; durable Finding observations are [ANALYST]. A Finding stores tactics and techniques as independent collections, so each explicit tactic and technique is counted independently rather than inventing a pairing.

FULL mode combines durable Findings with the active AnalysisResult. OFFLINE uses durable Findings only and never loads snapshots or scans output directories. Tactic and technique groups expose machine/analyst counts, source counts, distinct Investigation membership, and bounded recent observations. Technique names are shown only when explicit.

Detection Coverage describes potential ruleset representation. ATT&CK Activity describes current observed or recorded mappings and never consults coverage to manufacture observations, calculate percentages, or claim effectiveness. Shared techniques across Investigations do not imply a shared attacker, campaign, cause, or attack. The workspace is a read-only projection with no persistence, external ATT&CK lookup, scoring, enrichment, or mutation. Cross-navigation remains deferred because destination controllers do not expose a clean navigation contract.

## Cross-Investigation Analysis

Cross-Investigation Analysis surfaces shared structured observations across at least two distinct Investigations. It does not establish that Investigations are part of the same attack, campaign, attacker activity, incident, or cause.

The immutable projection supports `shared_entity`, `shared_attack_tactic`, and `shared_attack_technique`. Entity observations and their exact host, user, IP, and process normalization come from EntityObservationService. ATT&CK tactics and techniques come from AttackActivityService and must be explicit recorded mappings; Detection Coverage and prose are not consulted. Repetition within only one Investigation never creates a relationship, and there is no fuzzy matching, alias merging, temporal correlation, or scoring.

Relationship IDs are deterministic and independent of display position: `XINV:ENTITY:<type>:<normalized-value>`, `XINV:ATTACK:TACTIC:<normalized-tactic>`, and `XINV:ATTACK:TECHNIQUE:<technique-id-or-key>`. Results order by distinct Investigation count descending, explicit source-observation count descending, relationship type, then normalized key. Counts are convenience facts, not confidence, importance, strength, risk, or similarity scores. A source is deduplicated within each relationship and is not multiplied because another projection can display it.

FULL reads durable analyst state plus the active AnalysisResult. OFFLINE reads durable structured Investigation state only and never loads snapshots or scans output directories. An observation without an explicit Investigation ID cannot contribute cross-Investigation membership; the projection does not fabricate an association. Supporting observations are bounded and display timestamp, attribution, source type and ID, Investigation ID, and safe title only.

The service and terminal presentation are read-only. They do not reveal protected evidence, persist relationships, create indexes, mutate repositories, Findings, Evidence, Response Actions, AnalysisResult, alerts, artifacts, or snapshots. Pair analysis and cross-navigation are deferred: pair scoring is outside scope, and current destination controllers do not expose a clean navigation contract.


## Temporal Analysis

Temporal Analysis orders timestamped security and analyst activity across current SOC-Forge state. Temporal proximity does not establish a shared attack, attacker, campaign, or causal relationship. It is a cross-state chronology and does not replace the authoritative Investigation Timeline for one Investigation.

FULL combines current normalized events, alerts, cases, and reconstruction steps with durable selected evidence, hypotheses, decisions, Findings, and Response Action lifecycle history. OFFLINE includes durable analyst activity only and never restores snapshots or scans output directories. Response Action creation and each explicit transition are separate entries. Findings contribute creation and explicit supersession; repository saves do not manufacture update events.

The primary view is ascending by timestamp, then attribution/category, Investigation ID, source ID, and deterministic entry ID. Recent activity is a bounded exact reversal. Untimed authoritative objects remain in a separate section. Filters support one exact Investigation, source type, ATT&CK tactic, or technique ID while preserving chronology. Entity filtering and custom time windows are deferred because current timestamped sources do not expose one consistent safe structured-entity contract.

The projection uses safe titles, summaries, and explicit ATT&CK metadata only. It does not resolve protected evidence, infer from prose or Detection Coverage, persist an index, score proximity, construct attack chains, mutate source state, or change Investigation Timeline semantics.


## Hunt Workspace

Hunt Workspace searches and reviews current structured SOC-Forge state. Projection-based hunts do not create durable Hunt records or rerun detection unless an existing authoritative Hunt workflow explicitly does so.

Existing Hunts are pipeline-generated HuntFinding detector outputs stored in the active AnalysisResult and optional hunts.json artifact. The workspace preserves their authoritative ID, title, severity, category, summary, confidence, structured entities, evidence count, timestamps, and technique IDs without rewriting the artifact or relabeling guidance.

Entity hunts are ephemeral exact searches delegated to Entity Explorer normalization and observations. ATT&CK technique hunts delegate to ATT&CK Activity and include explicit observed mappings only. Investigation hunts delegate to Temporal Analysis using its ordering and attribution. Results are deterministic, bounded to 25, and review-oriented; counts are not scores.

FULL exposes current pipeline Hunt findings and machine observations. OFFLINE reports machine Hunt context unavailable while retaining durable analyst projections supported by the delegated services. No snapshots or output directories are loaded. There is no query language, saved hunt, persistence, detection rerun, external enrichment, campaign inference, or mutation. Cross-navigation remains deferred until destination controllers expose stateless contracts.
