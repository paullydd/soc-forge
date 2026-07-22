# Web UI

SOC-Forge includes a lightweight local web UI for the primary guided portfolio demo and for reviewing generated investigation artifacts from the `out/` directory. Demo scenarios run through the same shared analysis pipeline used by CLI file analysis.

## Run It

```bash
cd /home/pauly/projects/soc-forge
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
GET /artifact?file=cases.json
GET /artifact?file=alerts.json
GET /artifact?file=hunts.json
GET /artifact?file=reconstructions.json
```

`POST /api/scenario` requires `Content-Type: application/json` and supports `detection_lab` and `attack_chain`.

## Local Safety

The server is local-only by default and binds to `127.0.0.1`. It does not include authentication, users, sessions, cookies, TLS, or role-based access control. If you explicitly bind it to a non-loopback host, SOC-Forge prints a console warning because generated artifacts may expose investigation data.

Generated HTML and JSON artifacts can contain usernames, hosts, IP addresses, command lines, and investigation notes. Review and redact artifacts before sharing them.
