# Web UI

SOC-Forge includes a lightweight local web UI for the primary guided portfolio demo and for reviewing generated investigation artifacts from the `out/` directory. Demo scenarios run through the same shared analysis pipeline used by CLI file analysis.

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
- `Attack Chain`: RDP -> scheduled task -> new privileged account -> log clearing

The switcher refreshes `out/alerts.json`, `out/cases.json`, `out/hunts.json`, `out/reconstructions.json`, and `out/report.html` using the shared pipeline.

## Guided Demo

Use `Start Demo` to run the selected scenario and step through the current portfolio path:

- Generate scenario artifacts
- Review the dashboard
- Open the highest-risk case
- Review the investigation graph
- Review the Detection Engineering Scorecard
- Open the HTML incident report

## What It Shows

- Overview metrics for cases, alerts, correlations, hunts, and case quality
- Highest-risk case summary
- Rule activity and MITRE tactic counts
- Case browser with sorting and search
- Case quality brief, findings, containment guidance, evidence, and timeline
- Investigation graph with primary path highlighting, entity nodes, relationship confidence, severity styling, and evidence summaries
- Detection engineering scorecard with quality, MITRE coverage, evidence context, correlation depth, and demo readiness
- Alert table
- Hunt finding review
- Durable investigation evidence browsing, provenance review, and analyst selection management
- Links to generated HTML and JSON artifacts

## API Endpoints

The local server exposes workspace endpoints and one local demo-generation endpoint:

```text
GET /api/workspace
GET /api/summary
GET /api/cases
GET /api/alerts
GET /api/hunts
GET /api/detection-scorecard
GET /api/reconstructions
GET /api/scenarios
POST /api/scenario
GET /artifact?file=report.html
GET /artifact?file=detection_lab_report.html
GET /artifact?file=cases.json
GET /artifact?file=alerts.json
GET /artifact?file=hunts.json
GET /artifact?file=reconstructions.json
```

`POST /api/scenario` requires `Content-Type: application/json` and supports `detection_lab` and `attack_chain`.

## Local Safety

The server is local-only by default and binds to `127.0.0.1`. It does not include authentication, users, sessions, cookies, TLS, or role-based access control. If you explicitly bind it to a non-loopback host, SOC-Forge prints a console warning because generated artifacts may expose investigation data.

Generated HTML and JSON artifacts can contain usernames, hosts, IP addresses, command lines, and investigation notes. Review and redact artifacts before sharing them.


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
untimed entries are separate. Controlled filters support time, entry type,
host, user, IP, process, rule, ATT&CK tactic and technique, severity, evidence
classification, hypothesis, and case. Multiple filters use shared AND
semantics and remain only in browser memory.

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

Read-only routes:

```text
GET /api/investigations/{id}/timeline
GET /api/investigations/{id}/timeline/{entry_id}
GET /api/investigations/{id}/entities?type={entity_type}
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/events
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/alerts
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/cases
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/evidence
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/hypotheses
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/timeline
GET /api/investigations/{id}/entities/{entity_type}/{entity_value}/related
```

> The web workbench is a read-only presentation of shared timeline and pivot
> query results. It does not create new relationships, detections, cases,
> evidence selections, hypotheses, or decisions.
