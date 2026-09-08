# Detection Engineering

See the [v3.6 product walkthrough](walkthrough.md) for the current end-to-end interface tour.

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
- A branch-coverage test that fails when any alternative inside a rule's match logic is never independently exercised by a fixture
- A `detection_lab` simulator scenario for process-chain and credential-access detections
- Case guidance for the new PowerShell, process-path, Office, LSASS, and browser credential detections

## Run The Quality Checks

```bash
source .venv/bin/activate
python -m soc_forge.cli --rule-quality
pytest -q tests/test_rule_fixtures.py tests/test_rule_branch_coverage.py tests/test_detection_engineering_rules.py
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
- A `match_overrides` entry for every additional alternative inside an `any` block in the rule's match logic or score modifiers, so each one is independently proven to work rather than merely assumed

This keeps rule development honest: a new rule must prove both that it detects the intended behavior and that it avoids at least one nearby benign case. See [Fixture And Branch Coverage](rule_quality.md#fixture-and-branch-coverage) for why the last point matters - it is what caught SOCF-005 and SOCF-006 shipping a dead match branch.

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
- RDP logon from an external-looking source address (initial access)
- Account or group discovery command execution (whoami, net user/group/localgroup)
- LOLBin-based ingress tool transfer via certutil or bitsadmin (command and control)
- Correlations that connect lateral movement, credential access, and collection into case narratives
- Correlation that connects external initial access to discovery activity
- Tar/bsdtar `--checkpoint-action` wildcard/option injection (privilege escalation)

## Endpoint Defense And Recovery Rules

- `SOCF-020`: archive staging, reconstructed as Collection (`T1560`)
- `SOCF-021`: security-control tampering, reconstructed as Defense Evasion (`T1562.001`)
- `SOCF-022`: recovery or shadow-copy deletion, reconstructed as Impact (`T1490`)
- `SOCF-023`: RDP logon from an external-looking source address, reconstructed as Initial Access (`T1133`). This is a heuristic on the address prefix (excludes common private/loopback/link-local ranges), not full IP validation or a claim the address is internet-routable.
- `SOCF-024`: account or group discovery command execution (whoami, net user/group/localgroup), reconstructed as Discovery (`T1087`)
- `SOCF-025`: certutil or bitsadmin used to download a remote file, reconstructed as Command and Control (`T1105`, Ingress Tool Transfer). `SOCF-011` (Suspicious PowerShell) also carries this technique for its download-cradle patterns (`Invoke-WebRequest`/`downloadstring`/`IWR`), alongside its existing Execution and Defense Evasion mappings.
- `SOCF-026`: tar/bsdtar `--checkpoint-action` wildcard/option injection, reconstructed as Privilege Escalation (`T1053.005`, Scheduled Task/Job: Scheduled Task) and Execution (`T1059`). Windows-telemetry translation of a real CTF technique: a privileged automated process (e.g. a scheduled backup) running `tar` against a directory an attacker can write filenames into, where a filename like `--checkpoint-action=exec=...` gets interpreted as a tar option instead of a filename. `tar.exe` (bsdtar) has shipped with Windows since 10/11, so the same mechanism applies.

Reconnaissance and Resource Development are deliberately not covered: both are pre-compromise, attacker-side activity (OSINT, infrastructure acquisition, capability development) that never touches the victim endpoint, so there is no honest way to detect them from Windows process/security telemetry. Exfiltration is also not covered - meaningful exfiltration detection needs network telemetry (destination, data volume) that SOC-Forge does not ingest; a process-level proxy would be too speculative to trust.

These process rules support native Windows Security Event ID 4688. Event ID 1 is accepted only when the event provider is `Microsoft-Windows-Sysmon`.

The rules identify specific command-line patterns and do not establish malware certainty. Legitimate endpoint administration, backup maintenance, and disaster-recovery testing can produce similar activity. Alternate syntax or tools can bypass string matching. Generated evidence may retain sensitive command-line arguments and should be reviewed or redacted before sharing.

## Detection Overview and Rule Catalog

The analyst console's Detection menu provides two read-only inspection views:

- Detection Overview summarizes the bundled rule set, including total, enabled,
  and disabled rules; unique explicitly declared ATT&CK tactics and techniques;
  and recently stored alerts.
- Rule Catalog lists the same bundled rules in rule-ID order and exposes their
  validated metadata, match definition, emitted alert fields, score modifiers,
  aggregation definition, tags, and ATT&CK mappings.

Both views load rules through the production rule loader from
`BUILTIN_RULES_PATH`. Recent detection information comes from the existing
stored alert files used by Alert Explorer. Viewing either screen does not execute
rules, generate alerts, enable or disable rules, or write repository state.

The overview handles an empty alert store explicitly. Invalid bundled rule data
uses the same validation failure path as other rule-loading workflows and is
reported as a bounded console error. Rendering follows shared terminal width,
`NO_COLOR`, `TERM=dumb`, and ASCII-fallback behavior.

Detection Overview and Rule Catalog inspect existing detection capability.
They do not run detections or modify rule state.

## Rule Explainability

Rule Catalog answers what a configured rule is. Rule Explainability answers how
that rule's configured logic works. Detection Lab remains the place where rules
are executed or tested against events.

Rule Explainability is an immutable projection over the same validated
`Rule` objects loaded from `BUILTIN_RULES_PATH`. It uses fixed templates to
show:

- nested all/any match logic and the exact `eq`, `contains`, `regex`, and
  `exists` operators;
- fields referenced by matching, aggregation, emit templates, and score
  modifier conditions;
- explicit grouping, distinct-count field, threshold, and time window;
- conditional score additions, severity bumps, detail updates, and reasons;
- explicit emitted detail fields and their source-field templates;
- explicit ATT&CK mappings and existing rule metadata.

Missing optional metadata remains absent. The screen does not infer
rule-specific limitations, telemetry availability, coverage, gaps, or
historical effectiveness. It displays only the bounded platform guidance that
configured logic does not establish detection completeness.

Rule Explainability is deterministic and based on configured rule metadata.
It does not use AI-generated reasoning and does not execute detections.

Rule Catalog detail offers an Explain Rule action that reuses this same service
and renderer. Explainability does not edit, enable, disable, persist, simulate,
or otherwise mutate a rule or repository state.

## Detection Lab Workflow

Detection Lab is the controlled terminal execution surface for:

- Analyze Telemetry File, using the production file-ingest and analysis path;
- Run Attack Simulation, listing all scenarios from the simulator's
  authoritative registry;
- Evaluate Rules Only, preserving the existing `AnalysisOptions.rules_only`
  semantics;
- View Last Lab Result, retaining only the latest successful result in the
  current controller session.

Detection Lab reuses the production detection pipeline.
It does not implement a separate detection engine.

The immutable Lab result projects actual `AnalysisResult` values: event and
loaded-rule counts, distinct YAML rules that triggered, total alerts, cases,
correlations, hunts, reconstructions, existing artifact paths, ingest warnings,
and explicit ATT&CK mappings from triggered-rule alert metadata. Counts are not
inferred from presentation text.

Rules Only continues to suppress the legacy detector exactly as the production
pipeline currently defines. The existing pipeline still performs its downstream
correlation, hunt, case, and reconstruction stages, so the Lab reports their
actual counts and does not incorrectly claim they were skipped.

Viewing Last Lab Result is passive and does not scan prior artifacts, rerun
detection, or create a `lab_results.json` store. Selecting a triggered rule
opens the existing deterministic Rule Explainability projection; returning to
the Lab result does not execute the rule again.

Simulations generate telemetry test data only. They do not execute attacks,
start Investigations, add monitoring, or change rule state.

## Detection Coverage and Gaps

Detection Coverage describes what the current ruleset explicitly represents.
It does not measure environmental visibility or overall security effectiveness.

Coverage loads the same validated `Rule` objects as Rule Catalog and Rule
Explainability. It groups only explicit rule ATT&CK metadata into deterministic
tactic and technique projections and reports:

- total, enabled, and disabled loaded rules;
- rules with and without explicit ATT&CK mappings;
- represented tactics and techniques;
- enabled and disabled rule IDs for each technique.

No tactic or technique is inferred from titles, descriptions, tags, events, or
alert prose. SOC-Forge has no configured expected ATT&CK baseline, so Coverage
does not calculate a global percentage or make an ATT&CK completeness claim.

Detection Gaps uses a deliberately bounded policy:

- an `UNMAPPED_RULE` gap identifies a loaded rule without explicit ATT&CK
  metadata;
- a `DISABLED_COVERAGE` gap identifies a technique represented only by
  disabled loaded rules.

Gap identifiers and ordering are deterministic. Multiple rules on one
technique are not treated as redundant or defective. An unmapped rule is not
declared broken.

Because no expected baseline exists, no missing-technique requirements are
fabricated. Coverage and Gaps make no sensor-health, telemetry-health,
historical-effectiveness, prevention, or data-availability claims. Opening
either workspace is read-only: it does not run detections, mutate rules or
configuration, write artifacts, or create operational state.
