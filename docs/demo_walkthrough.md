# SOC-Forge Attack Chain Demo

This walkthrough demonstrates SOC-Forge as an analyst-facing investigation workflow, not just a rule runner.

The demo scenario simulates this chain:

```text
RDP logon
  -> suspicious scheduled task
  -> service-style admin account creation
  -> privileged group assignment
  -> audit log clearing
```

## 1. Prepare the Environment

```bash
cd soc-forge
source .venv/bin/activate
```

## 2. Generate Demo Events

```bash
python -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
```

## 3. Analyze the Events

```bash
python -m soc_forge.cli   --input out/attack_chain_events.jsonl   --out out/alerts.json   --html out/report.html
```

Expected high-level output:

```text
Saved alerts to: out/alerts.json
Saved HTML report to: out/report.html
Correlated alerts: 4
```

## 4. Open the Analyst Console

```bash
python analyst_console.py
```

Then navigate:

```text
Investigations -> Investigation Workspace
```

Recommended demo flow:

1. Press `S` and sort by risk.
2. Open `New privileged account followed by log clearing`.
3. Open `Investigation Replay` and use Auto Play.
4. Open `Timeline` and confirm readable event names.
5. Open `View Investigation Graph`.
6. Open `View Entity Profiles` and inspect `198.51.100.77`, `svc-backup-admin`, or `WS-ENG-01`.
7. Open `Relationship Explorer` and inspect relationship evidence.
8. Open `View Attack Path`.
9. Use `Next Actions`.
10. Use `Close Case`, then `Export`.

## 5. Expected Detection Output

The attack-chain scenario should produce 9 alerts:

```text
SOCF-005       Scheduled task created
SOCF-006       RDP logon detected (LogonType 10)
SOCF-007       New user account created
SOCF-008       User added to privileged group
SOCF-009       Audit logs cleared
SOCF-CORR-002  RDP -> scheduled task
SOCF-CORR-003  RDP -> privileged group change
SOCF-CORR-004  new account -> privileged group assignment
SOCF-CORR-005  new privileged account -> log clearing
```

The richest case is:

```text
CASE-18FA7129
New privileged account followed by log clearing (possible account abuse)
Risk Score: 400
Alerts: SOCF-007, SOCF-008, SOCF-009, SOCF-CORR-005
```

Expected graph entities include:

```text
198.51.100.77
alice
WS-ENG-01
WindowsUpdateCheck
svc-backup-admin
Administrators
```

## 6. Generated Artifacts

After analysis, review:

```text
out/attack_chain_events.jsonl
out/alerts.json
out/cases.json
out/reconstructions.json
out/report.html
```

After exporting a case from the console, review:

```text
out/investigation_bundle_case_<CASE_ID>/case_summary.txt
out/investigation_bundle_case_<CASE_ID>/closure_report.txt
out/investigation_bundle_case_<CASE_ID>/evidence.json
out/investigation_bundle_case_<CASE_ID>/lifecycle.json
```

## 7. Sample Artifacts Checked In

A generated sample is available under:

```text
samples/attack_chain_demo/
```

It includes:

```text
attack_chain_events.jsonl
alerts.json
cases.json
hunts.json
reconstructions.json
report.html
01_generate.txt
02_analyze.txt
```
