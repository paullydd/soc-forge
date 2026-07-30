# Detection Engineering

SOC-Forge now includes a small detection engineering workflow around its YAML rules.

## What Changed

This phase added:

- `SOCF-011`: Suspicious PowerShell execution
- `SOCF-012`: Process launched from user-writable path
- `SOCF-013`: Office application spawned script interpreter
- `SOCF-014`: Credential dumping or LSASS access command
- `SOCF-015`: Browser credential store access
- `SOCF-016`: PsExec-style service execution
- `SOCF-017`: WMI process execution
- `SOCF-018`: Suspicious LOLBin script execution
- `SOCF-019`: Remote admin share execution
- `SOCF-020`: Suspicious archive staging of sensitive files
- Positive and negative fixtures for every YAML rule
- A fixture test that fails when a rule is added without a matching test fixture
- A `detection_lab` simulator scenario for process-chain and credential-access detections
- Case guidance for the new PowerShell, process-path, Office, LSASS, and browser credential detections

## Run The Quality Checks

```bash
source .venv/bin/activate
python -m soc_forge.cli --rule-quality
pytest -q tests/test_rule_fixtures.py tests/test_detection_engineering_rules.py
```

## Run The Detection Lab

```bash
python -m soc_forge.cli --simulate detection_lab --sim-output out/detection_lab_events.jsonl
python -m soc_forge.cli --input out/detection_lab_events.jsonl --out out/detection_lab_alerts.json --html out/detection_lab_report.html
```

Expected alerts:

```text
SOCF-011  Suspicious PowerShell execution
SOCF-012  Process launched from user-writable path
SOCF-013  Office application spawned script interpreter
SOCF-014  Credential dumping or LSASS access command
SOCF-015  Browser credential store access
SOCF-016  PsExec-style service execution
SOCF-017  WMI process execution
SOCF-018  Suspicious LOLBin script execution
SOCF-019  Remote admin share execution
SOCF-020  Suspicious archive staging of sensitive files
SOCF-CORR-006  Office spawned suspicious script interpreter
SOCF-CORR-007  Suspicious script execution followed by credential dumping
SOCF-CORR-008  Suspicious process followed by browser credential store access
SOCF-CORR-009  RDP logon followed by PsExec-style service execution
SOCF-CORR-010  WMI execution followed by suspicious command execution
SOCF-CORR-011  Credential access followed by archive staging
SOCF-CORR-012  Lateral movement followed by credential access
SOCF-CORR-013  Admin share execution followed by persistence or staging
```

## Fixture Standard

Each built-in YAML rule should have:

- One positive event that should fire the rule
- One negative event that should not fire the rule
- A matching `rule_id` and `rule_file` entry in `tests/fixtures/rule_fixtures.json`

This keeps rule development honest: a new rule must prove both that it detects the intended behavior and that it avoids at least one nearby benign case.

## Current Rule Coverage

Detection content now covers:

- Account lockout
- Privileged group changes
- Service installation
- Scheduled task creation
- RDP logon
- New user creation
- Privileged group assignment
- Audit log clearing
- Password spray-style failed logons
- Suspicious PowerShell
- Process execution from user-writable paths
- Office-to-script process chains
- LSASS and credential dumping behavior
- Browser credential store access
- PsExec-style remote service execution
- WMI process execution
- LOLBin proxy execution
- Remote admin share execution
- Archive staging for collection or exfiltration preparation
- Correlations that connect lateral movement, credential access, and collection into case narratives

## Endpoint Defense And Recovery Rules

- `SOCF-020`: archive staging, reconstructed as Collection (`T1560`)
- `SOCF-021`: security-control tampering, reconstructed as Defense Evasion (`T1562.001`)
- `SOCF-022`: recovery or shadow-copy deletion, reconstructed as Impact (`T1490`)

These process rules support native Windows Security Event ID 4688. Event ID 1 is accepted only when the event provider is `Microsoft-Windows-Sysmon`.

The rules identify specific command-line patterns and do not establish malware certainty. Legitimate endpoint administration, backup maintenance, and disaster-recovery testing can produce similar activity. Alternate syntax or tools can bypass string matching. Generated evidence may retain sensitive command-line arguments and should be reviewed or redacted before sharing.
