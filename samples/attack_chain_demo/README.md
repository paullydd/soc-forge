# Attack Chain Demo Artifacts

This folder contains a checked-in SOC-Forge demo run for portfolio review. It lets someone inspect generated output without running the simulator first, which is useful for reviewers who want to see concrete alerts, cases, reconstructions, hunts, and HTML output immediately.

## Scenario

```text
RDP logon
  -> suspicious scheduled task
  -> service-style admin account creation
  -> privileged group assignment
  -> audit log clearing
```

## Files

```text
attack_chain_events.jsonl   Generated input events
alerts.json                 Rule alerts and correlated alerts
cases.json                  Generated case records
hunts.json                  Hunt analytics
reconstructions.json        Attack reconstruction output
report.html                 Static HTML report
01_generate.txt             Captured generation command/output
02_analyze.txt              Captured analysis command/output
demo_capture.txt            Demo notes/capture output
```

## Expected Output

The sample contains:

```text
9 alerts
4 correlated alerts
4 cases
```

The richest case is:

```text
CASE-18FA7129
New privileged account followed by log clearing (possible account abuse)
Risk Score: 400
Rules: SOCF-007, SOCF-008, SOCF-009, SOCF-CORR-005
```

## How To Recreate

From the repository root:

```bash
source .venv/bin/activate
python -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
python -m soc_forge.cli --input out/attack_chain_events.jsonl --out out/alerts.json --html out/report.html
```

For the full walkthrough, see `../../docs/demo_walkthrough.md`, `../../docs/demo_in_5_minutes.md`, and `../../docs/release_package.md`.
