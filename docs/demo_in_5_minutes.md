# SOC-Forge Demo In 5 Minutes

This is the quickest portfolio demo path for SOC-Forge. It uses the local web UI because that path runs a scenario through the shared analysis pipeline and shows the Command Center, generated Cases, bounded graph, consolidated Detection Health, and existing HTML report without jumping between tools.

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

On the Command Center, open **Demo / Lab controls**:

```text
Scenario: Detection Lab
Button: Start Guided Demo
```

Step through:

```text
Generate -> Command Center -> Case -> Graph -> Detection Health -> Report
```

What to point out:

- Command Center shows current workload, authoritative Top Attention, and bounded recent activity
- Case view summarizes generated activity in analyst-readable form
- Case view shows key findings, containment guidance, evidence, timeline, and entities
- Graph view highlights the primary investigation path and relationship confidence
- Detection Health preserves the existing rule-quality scorecard while Detection separates configured coverage from observed ATT&CK activity
- Final report opens the generated HTML incident report

After the guided path, use the grouped sidebar to show Operations, durable Investigations, Security Analysis, Reporting, and read-only System inspection. OFFLINE and UNKNOWN remain valid non-failure states, and Response Actions never execute remediation.

## 4. Optional Attack-Chain Story

For the deeper incident narrative, switch to `Attack Chain` and click `Start Demo` again.

Expected story:

```text
RDP logon from an external-looking source address (initial access)
  -> account and group discovery commands (whoami, net localgroup)
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
Investigations -> Investigation Workspaces -> Open investigation
```

Use this if you want to show replay, entity profiles, relationship explorer, attack path, Response Actions, status closure, and Investigation Handoff export from the terminal workflow.

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
