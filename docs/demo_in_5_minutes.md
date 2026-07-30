# SOC-Forge Demo In 5 Minutes

This is the quickest portfolio demo path for SOC-Forge. It uses the local web UI because that path runs a scenario through the shared analysis pipeline and shows the dashboard, generated cases, investigation graph, detection engineering scorecard, and HTML report without jumping between tools.

## 1. Activate The Environment

```bash
cd soc-forge
source .venv/bin/activate
```

## 2. Start The Web UI

```bash
python -m soc_forge.web.app --port 8765
```

Open:

```text
http://127.0.0.1:8765
```

## 3. Run The Guided Demo

In the top toolbar:

```text
Scenario: Detection Lab
Button: Start Demo
```

Step through:

```text
Generate -> Dashboard -> Case -> Graph -> Scorecard -> Report
```

What to point out:

- Overview shows cases, alerts, correlations, hunts, and average case quality
- Highest-risk case summarizes credential-access activity in plain analyst language
- Case view shows key findings, containment guidance, evidence, timeline, and entities
- Graph view highlights the primary investigation path and relationship confidence
- Scorecard shows rule quality, MITRE coverage, evidence context, correlation depth, demo readiness, and rule inventory
- Final report opens the generated HTML incident report

## 4. Optional Attack-Chain Story

For the deeper incident narrative, switch to `Attack Chain` and click `Start Demo` again.

Expected story:

```text
RDP logon
  -> suspicious scheduled task
  -> service-style admin account creation
  -> privileged group assignment
  -> audit log clearing
```

## 5. Optional Terminal Analyst Console

```bash
python analyst_console.py
```

Recommended path:

```text
Investigations -> Investigation Workspace
```

Use this if you want to show replay, entity profiles, relationship explorer, attack path, next actions, closure, and investigation bundle export from the terminal workflow.

## 6. Checked-In Artifacts

If you do not want to rerun anything, inspect:

```text
samples/attack_chain_demo/
docs/screenshots/
```

Important sample files:

```text
attack_chain_events.jsonl   Demo source events
alerts.json                 Rule and correlation alerts
cases.json                  Generated investigation cases
reconstructions.json        Attack reconstruction output
hunts.json                  Hunt output
report.html                 Static HTML report
```

## One-Sentence Pitch

SOC-Forge turns raw security events into correlated SOC cases with detection engineering quality checks, analyst-ready case briefs, investigation graphs, and exportable reports.
