# SOC-Forge Attack Chain Demo

This walkthrough demonstrates SOC-Forge as an analyst-facing investigation workflow, not just a rule runner.

The demo scenario simulates this chain:

```text
RDP logon from an external-looking source address (initial access)
  -> account and group discovery commands (whoami, net localgroup)
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
Correlated alerts: 5
```

## 4. Open the Analyst Console

```bash
python analyst_console.py
```

Then navigate:

```text
Investigations -> Investigation Workspaces
```

Recommended demo flow:

1. Create an investigation from `New privileged account followed by log clearing`.
2. Open the investigation, then `Investigation Replay` and use Auto Play.
3. Open `Timeline and Pivot Workbench (Read Only)` and confirm readable event names.
4. Open `Entity Relationship Explorer (Read Only)`.
5. Choose `View Entity Profiles` and inspect `198.51.100.77`, `svc-backup-admin`, or `WS-ENG-01`.
6. Choose `Relationship Explorer` and inspect relationship evidence.
7. Choose `View Attack Path`.
8. Use `Response Actions` for recommended next steps.
9. Use `Change Status` to close, then `Investigation Handoff (Read Only)` to export.

## 5. Expected Detection Output

The attack-chain scenario should produce 14 alerts:

```text
SOCF-005       Scheduled task created
SOCF-006       RDP logon detected (LogonType 10)
SOCF-007       New user account created
SOCF-008       User added to privileged group
SOCF-009       Audit logs cleared
SOCF-011       Suspicious PowerShell execution (scheduled task command line)
SOCF-023       RDP logon from external source address (possible initial access)
SOCF-024       Account or group discovery command executed (x2: whoami, net localgroup)
SOCF-CORR-002  RDP -> scheduled task
SOCF-CORR-003  RDP -> privileged group change
SOCF-CORR-004  new account -> privileged group assignment
SOCF-CORR-005  new privileged account -> log clearing
SOCF-CORR-014  external initial access -> discovery
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
