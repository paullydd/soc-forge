# Web UI

SOC-Forge includes a lightweight local web UI for the primary guided portfolio demo, for reviewing generated investigation artifacts from the `out/` directory, and for ingesting an analyst's own telemetry file directly from the browser. Demo scenarios and uploaded files both run through the same shared analysis pipeline used by CLI file analysis.

## Run It

```bash
cd soc-forge
source .venv/bin/activate
python -m soc_forge.web.app --port 8765
```

Then open:

```text
http://127.0.0.1:8765
```

If you reinstall the editable package after this change, this command is also available:

```bash
soc-forge-web --port 8765
```

## Generate Data First

The web UI can generate demo artifacts directly through the built-in scenario switcher. It can also read existing SOC-Forge output files if you run an analysis first:

```bash
python -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
python -m soc_forge.cli --input out/attack_chain_events.jsonl --out out/alerts.json --html out/report.html
```

For the process-focused detection lab demo:

```bash
python -m soc_forge.cli --simulate detection_lab --sim-output out/detection_lab_events.jsonl
python -m soc_forge.cli --input out/detection_lab_events.jsonl --out out/alerts.json --html out/report.html
```

## Scenario Switcher

Use the top-right scenario selector to generate and load demo artifacts directly from the browser:

- `Detection Lab`: Office -> PowerShell -> credential dumping -> browser credential access
- `Attack Chain`: external RDP logon -> discovery commands -> scheduled task -> new privileged account -> log clearing

The switcher refreshes `out/alerts.json`, `out/cases.json`, `out/hunts.json`, `out/reconstructions.json`, and `out/report.html` using the shared pipeline.

## Load Your Own Telemetry

Open the collapsed **Load Telemetry File** panel on the Command Center to analyze your own data without leaving the browser. Choose a `.jsonl`, `.csv` (Windows Security export), or `.evtx` file and select `Upload & Analyze`; format auto-detects from the extension, or you can force it with the format dropdown.

The upload posts to `POST /api/ingest`, which saves the file under `out/uploads/` and runs it through the exact same `soc_forge.pipeline` path as `soc-forge --input`, replacing the current workspace (`out/alerts.json`, `out/cases.json`, `out/hunts.json`, `out/reconstructions.json`, `out/report.html`) with the new analysis, the same way the scenario switcher does. A malformed or unparsable file returns a bounded error with ingest diagnostics instead of a stack trace; the upload is capped at 50 MB and restricted to the three supported extensions.

This does not change the loopback-only default or the optional shared-secret auth token - it is gated by the same `require_auth()` check as every other route, and only widens what an already-authorized user can do.

## Guided Demo

Open the collapsed **Demo / Lab controls** on the Command Center and use `Start Guided Demo` to run the selected scenario through the current portfolio path:

- Generate authoritative scenario artifacts
- Review Command Center workload and attention
- Open the selected Case
- Review its bounded relationship graph
- Review Detection Health inside the consolidated Detection Workspace
- Open the existing HTML report

## What It Shows

- Command Center workload, Top Attention, recent activity, and supporting security context
- Grouped navigation for Operations, Investigations, Cases, Detection, Security Analysis, Reporting, and System
- Case browser with sorting and search
- Case quality brief, findings, containment guidance, evidence, and timeline
- Investigation graph with primary path highlighting, entity nodes, relationship confidence, severity styling, and evidence summaries
- Detection Overview, Alerts, Rules, explicit ATT&CK coverage/activity separation, and Health
- Durable Investigation Summary, Findings, Evidence, Timeline, Response, and Handoff tabs
- Security Analysis Overview, exact entity discovery, ATT&CK observations, Relationships, Timeline, and Hunts
- Read-only Operations prioritization with authoritative Investigation destinations
- Reporting views for reports, Investigation presentations, executive context, and supported artifacts
- Read-only System status, configuration, health, storage, environment, and release identity

FULL combines current machine analysis with durable analyst state. OFFLINE is valid durable analyst state, not failure. UNKNOWN means a safe read-only check could not determine a fact. Response Actions record analyst-controlled work and do not execute remediation.

## Core API Endpoints

The local server exposes workspace endpoints and one local demo-generation endpoint:

```text
GET /api/workspace
GET /api/summary
GET /api/investigations/{id}/summary
GET /api/cases
GET /api/alerts
GET /api/hunts
GET /api/detection-scorecard
GET /api/reconstructions
GET /api/operations-queue
GET /api/security-analysis
GET /api/security-analysis/entities
GET /api/reporting
GET /api/system
GET /api/scenarios
POST /api/scenario
GET /artifact?file=report.html
GET /artifact?file=detection_lab_report.html
GET /artifact?file=cases.json
GET /artifact?file=alerts.json
GET /artifact?file=hunts.json
GET /artifact?file=reconstructions.json
```

Investigation, evidence, reasoning, Finding, Response Action, Handoff, and query-workbench routes are documented in their focused references below. Reporting exposes only the supported artifact allowlist; the former sidebar output links are not primary navigation.

`POST /api/scenario` requires `Content-Type: application/json` and supports `detection_lab` and `attack_chain`.

## Local Safety

The server is local-only by default and binds to `127.0.0.1`. By default it does not include authentication, sessions, cookies, TLS, or role-based access control. If you explicitly bind it to a non-loopback host, SOC-Forge prints a console warning because generated artifacts may expose investigation data, unless you have also configured an auth token (see below).

Generated HTML and JSON artifacts can contain usernames, hosts, IP addresses, command lines, and investigation notes. Review and redact artifacts before sharing them.

### Optional authentication

Set a shared secret to require credentials for every request:

```bash
python -m soc_forge.web.app --port 8765 --auth-token "$(openssl rand -hex 32)"
# or
export SOC_FORGE_WEB_TOKEN="$(openssl rand -hex 32)"
python -m soc_forge.web.app --port 8765
```

When a token is set, the server challenges with HTTP Basic Auth (`WWW-Authenticate: Basic`); the browser will prompt for credentials on first access. Any username works — only the password (the token) is checked, using a constant-time comparison. This is plaintext-equivalent HTTP Basic Auth with no TLS, so it is meant to add a barrier on a shared or non-loopback host, not to replace a real reverse proxy with TLS if you expose this beyond your own machine.


### Durable Investigation Evidence

The Investigations view includes an Evidence section for case-scoped candidate
browsing, bounded provenance inspection, analyst classification and rationale,
and durable selection management. Scope references and analyst-selected
evidence are displayed separately.

Candidate and source-detail access requires the matching completed analysis to
remain active. Persisted selection metadata remains visible when it is not
active. Sensitive values are hidden by default and require an explicit reveal;
revealed values can remain in developer tools or screen captures. Candidate
detail responses, including sensitive reveals, send Cache-Control: no-store.
SOC-Forge does not automatically redact displayed values.

Evidence requests use the current workspace revision. A conflict refreshes the
latest authoritative workspace without automatic retry. The browser keeps
unsent evidence form values only in memory where practical.

Additional local routes:

```text
POST   /api/investigations/{id}/source-analysis/load
GET    /api/investigations/{id}/evidence/candidates?type={type}
GET    /api/investigations/{id}/evidence/candidates/{evidence_id}
GET    /api/investigations/{id}/evidence/candidates/{evidence_id}?include_sensitive=true
GET    /api/investigations/{id}/evidence/selections
POST   /api/investigations/{id}/evidence/selections
PUT    /api/investigations/{id}/evidence/selections/{evidence_id}
DELETE /api/investigations/{id}/evidence/selections/{evidence_id}
```

## Investigation Reasoning

Analyst decisions are created through `InvestigationReasoningService`. Legacy records may remain readable, but legacy public mutation paths do not bypass the controlled reasoning contract. The older `/decisions` mutation route returns `410`; the Hypotheses and Decisions section is the only decision-creation UI.

The web investigation workspace exposes analyst-authored hypotheses separately
from alerts, cases, and other machine findings. It displays the shared reasoning
summary, controlled hypothesis states, compatible selected evidence,
append-only assessments, reopening history, and broader analyst decisions.

The browser continues to show persisted reasoning after a server restart or
when source analysis is unavailable. Source details remain governed by the
existing evidence provenance and sensitive-value reveal flow. All reasoning
requests use optimistic revisions and no automatic conflict retry.

See [Hypotheses and Decisions](hypotheses_and_decisions.md) and
[Web Investigation Workspaces](web_investigation_workspaces.md) for the full
workflow and route contracts.


## Web Timeline and Pivot Workbench

Open an investigation and use **Timeline and Pivot Workbench - Read Only** to
review the canonical chronology or browse normalized entities. Timed and
untimed entries are separate. Entry type, severity, and evidence classification
use controlled browser selections. Data-dependent host, user, IP, process, rule
ID, ATT&CK tactic, ATT&CK technique, hypothesis ID, and case ID filters remain
text inputs, while the server remains authoritative for validation of every
filter. Multiple filters use shared AND semantics and remain only in browser
memory.

Entity pivots expose events, alerts, cases, evidence, hypotheses, related
entities, and the entity timeline. Relationship reasons come directly from the
shared query service. Evidence classifications remain analyst overlays;
hypothesis states remain analyst assessments; decision lists show ID and type
without rationale. The UI navigates to existing evidence, hypothesis, and
decision details instead of duplicating those contracts.

The workbench requires the matching active completed analysis. It does not
rerun analysis. Each response includes the current investigation revision; a
revision difference displays **Workbench data may be stale** and the analyst
can refresh explicitly. Workbench responses use `Cache-Control: no-store`,
render untrusted values with safe DOM text insertion, and never persist source
content in local storage.

Entity lists return an opaque `entity_id` derived by the query adapter from the
investigation ID, source-analysis provenance, entity type, normalized identity,
and optional secondary identity. The browser reuses that ID and does not hash or
normalize entities itself. IDs are transient workbench transport identifiers,
not durable evidence or entity references. The same logical entity receives a
different ID in another investigation. Display and normalized values remain
response-body fields. Legacy raw-value routes return `410 Gone`.

> Workbench entity identifiers are scoped to both the durable investigation and
> its matching completed analysis. An entity identifier issued for one
> investigation is not valid in another investigation, even when both reference
> the same analysis.

> Web workbench entity navigation uses opaque entity identifiers. Hostnames,
> usernames, IP addresses, process paths, and other source entity values are not
> embedded in workbench request URLs or query parameters.

Read-only routes:

```text
GET /api/investigations/{id}/timeline
GET /api/investigations/{id}/timeline/{entry_id}
GET /api/investigations/{id}/entities?type={entity_type}
GET /api/investigations/{id}/entities/{entity_id}
GET /api/investigations/{id}/entities/{entity_id}/events
GET /api/investigations/{id}/entities/{entity_id}/alerts
GET /api/investigations/{id}/entities/{entity_id}/cases
GET /api/investigations/{id}/entities/{entity_id}/evidence
GET /api/investigations/{id}/entities/{entity_id}/hypotheses
GET /api/investigations/{id}/entities/{entity_id}/timeline
GET /api/investigations/{id}/entities/{entity_id}/related
```

> The web workbench is a read-only presentation of shared timeline and pivot
> query results. It does not create new relationships, detections, cases,
> evidence selections, hypotheses, or decisions.


## Web Investigation Handoff

The investigation detail view includes **Investigation Handoff - Read Only**. It supports preview, explicit sensitive-data acknowledgement, export to the fixed analysis-local `handoffs` root, explicit overwrite, bounded manifest inspection, and offline integrity validation. All handoff responses use `Cache-Control: no-store`, and the browser receives safe relative bundle identifiers rather than absolute filesystem paths.

Routes:

```text
GET  /api/investigations/{id}/handoff/preview
POST /api/investigations/{id}/handoff/export
GET  /api/investigations/{id}/handoff/manifest
POST /api/investigations/{id}/handoff/validate
```

Export accepts only the expected revision, the controlled `handoffs` root, explicit overwrite, and sensitive-data acknowledgement. Conflicts refresh the investigation separately without automatic retry. Manifest inspection and validation use the deterministic bundle at the controlled server root and do not accept a path query parameter.

Web handoff controls delegate construction and validation to the shared `InvestigationHandoffService`. The browser does not serialize, hash, copy, or validate handoff files independently. There is no archive/download, upload, sharing, automatic redaction, or signing capability in this slice.

## Completed Analysis Activation

Durable investigation metadata remains readable without an active source
analysis. The investigation detail shows whether its source analysis is
available in the current server session. **Load Source Analysis** calls:

```text
POST /api/investigations/{id}/source-analysis/load
```

The route validates the exact immutable snapshot and selected investigation
references before activation. Loading restores process-local analysis context;
it does not modify, rebind, or increment the durable investigation. The server
holds one active analysis, so loading another investigation's snapshot replaces
the current in-memory value. Failed source-dependent requests and failed loads
are not retried automatically. Snapshot paths and source payloads are never
placed in URLs or browser storage.


## Investigation Summary

Opening a durable investigation loads a compact summary near the top of the workspace. When the exact source analysis is active, full mode includes bounded machine context and canonical timeline milestones. Otherwise offline mode shows durable analyst-owned state and explicit limitations. Loading the source analysis refreshes the same summary without changing the investigation revision.

Evidence, hypothesis, decision, and timeline actions open the existing investigation workflows. Summary content is rendered as untrusted text, sensitive evidence values are not automatically revealed, and the route is read-only with `Cache-Control: no-store`.

## Response Actions

The local Investigation Workspace exposes durable Response Actions with authoritative counts, ACTIVE-Finding selection, safe list/detail/history rendering, and controlled lifecycle forms. Routes are investigation-scoped under `/api/investigations/{investigation_id}/response-actions`, remain usable when source analysis is unavailable, require optimistic revisions for mutations, and use `Cache-Control: no-store` for reads. The interface records analyst workflow and does not execute containment or remediation. The same durable Actions appear in FULL and OFFLINE Investigation Summary views and in Handoff preview/export. Handoff reads remain non-mutating and never execute remediation.
Handoff preview and export remain available in OFFLINE investigations. The preview explicitly labels source analysis as unavailable, exports only durable investigation state, and records analysis-derived timeline entries and source artifacts as unavailable rather than reconstructing them.


## Analyst Operations Queue

Operations Queue is a top-level web workspace backed by the same deterministic OperationsQueueService used by the Analyst Console. It presents authoritative summary cards and read-only filters for all items, Response Actions, uncovered Findings, and high/critical work.

Each card retains stable Investigation and source identifiers, source state, operational priority, deterministic reason, and update time. Open Response Action and Open Finding reuse the durable Investigation detail workflows and scope lookup by both Investigation ID and source ID.

The queue is requested with no-store caching whenever the page opens or refreshes. Returning to Operations after a source mutation requests a new projection; the browser does not manually add or remove cards and does not use localStorage or background polling. Offline durable Investigation state is sufficient.

Queue controls never acknowledge, assign, dismiss, complete, snooze, or escalate queue items. Any permitted mutation occurs only in the authoritative Finding or Response Action workspace. SOC-Forge records analyst-controlled response work and does not execute remediation.

Operations Queue API items also expose priority_tier, priority_basis, and operational_state, plus the identical top item used by terminal prioritization. Cards render each basis entry with DOM creation and textContent; filters retain the server-provided order and never re-rank locally.

The web interface uses no score, gauge, AI language, aging, or SLA interpretation. A fresh no-store request rebuilds membership and prioritization from durable Investigation state in FULL or OFFLINE mode without persisting browser queue state.

## Operational Summary

The Operations Queue API returns operational_summary alongside the existing queue payload. It contains deterministic counts, distinct Investigations represented, Top Attention, and the first three items in authoritative priority order. The browser renders these server-provided fields and never recalculates counts or ranking.

Summary cards and Top Priority Work use safe DOM creation and textContent. The view remains read-only and offline-capable, with no local queue state, mutation controls, SLA, aging, activity feed, automation, or AI ranking.

The Operational Summary does not create or track work independently.
It summarizes the current deterministic Operations Queue.
