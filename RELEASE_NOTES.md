# Release Notes

## v3.6.1

**Theme:** Close an Initial Access / Discovery detection gap with two new rules and a fuller Attack Chain demo scenario.

### Detection Engineering

- Added `SOCF-023`: RDP logon from an external-looking source address, mapped to Initial Access (`T1133`, External Remote Services). Heuristic on the address prefix (excludes common private/loopback/link-local ranges); not full IP validation.
- Added `SOCF-024`: account or group discovery command execution (`whoami`, `net user`/`group`/`localgroup`), mapped to Discovery (`T1087`, Account Discovery).
- Added `SOCF-CORR-014`: correlates external initial access with subsequent discovery activity on the same host into one case.
- ATT&CK tactic coverage of the bundled rule set now includes Initial Access and Discovery in addition to the eight tactics already covered.

### Attack Chain Demo Scenario

- Extended the Attack Chain simulator scenario to open with an external RDP logon and discovery commands (`whoami`, `net localgroup administrators`) before the existing persistence, privilege escalation, and defense evasion steps, so the demo now shows a complete kill chain from initial access through impact.
- Regenerated the checked-in `samples/attack_chain_demo/` artifacts and documentation to match (14 alerts, 5 correlated alerts, 6 cases).

### Security Hardening (carried in this release)

- Closed a shell command-injection path in the analyst console, added optional HTTP Basic Auth and security response headers to the web UI, added a request body size cap, switched EVTX record parsing to `defusedxml`, and added `bandit`/`pip-audit` plus pinned GitHub Actions to CI.

## v3.6.0

**Theme:** One coherent, accessible analyst web application across the established SOC-Forge workspaces.

### Shared Web Experience

- Reorganized the local web interface around one grouped application shell and shared dark analyst-console design system.
- Redesigned the Command Center to prioritize authoritative operational attention, recent attributed activity, and bounded supporting security context.
- Added consistent workspace hierarchy, tab behavior, focus treatment, metric presentation, analyst-readable UTC metadata, and desktop-first responsive layouts.

### Investigation, Detection, and Operations

- Consolidated the Investigation Workspace into Summary, Findings, Evidence, Timeline, Response, and Handoff tabs while preserving revisioned durable state and existing mutation boundaries.
- Consolidated alerts, deterministic rules, observed ATT&CK activity, coverage context, and health into one Detection Workspace without claiming complete ATT&CK coverage.
- Redesigned Operations as a read-only list/detail prioritization surface over authoritative Findings and Response Actions; it does not add queue-owned state or SOAR behavior.

### Security Analysis

- Added one Security Analysis Workspace for overview, exact entity exploration, observed ATT&CK activity, deterministic relationships, chronology, and Hunt projections.
- Made authoritative host, user, IP address, and process values discoverable while retaining the existing exact-match exploration semantics and explicit machine/analyst provenance.
- Preserved the boundaries that chronology is not causality and shared observations do not establish attacker or campaign identity.

### Reporting and System

- Added a Reporting Workspace for existing reports, durable Investigation Reports, deterministic executive context, and supported artifacts.
- Kept Reporting distinct from the structured, validated Investigation Handoff owned by Investigations.
- Added a read-only System Workspace for platform status, bounded configuration, asset health, known storage, environment, and release identity.

### State, Safety, and Validation

- OFFLINE remains a valid durable analyst state; unavailable machine context is not converted to zero activity.
- UNKNOWN means a safe read-only check could not determine a fact and is not treated as failure.
- Response Actions remain analyst-controlled workflow records. SOC-Forge does not execute remediation, provide live monitoring, integrate a SIEM, or generate AI conclusions.
- Refreshed current walkthrough and release documentation for the consolidated v3.6 navigation. Historical v3.5 screenshots remain archived; current v3.6 web capture is tracked as a manual documentation follow-up where reliable browser capture is unavailable.
- The release-preparation suite contains 1,449 tests before metadata and documentation updates, including exact packaged web-asset, rule-count, and isolated-wheel validation.

## v3.5.0

**Theme:** Deterministic analyst workspaces for detection engineering, security analysis, operations, reporting, and local platform inspection.

### Detection Engineering

- Added the Detection Overview, Rule Catalog, Rule Explainability, Detection Lab, Detection Coverage, and Detection Gaps terminal workspaces.
- Kept rule inspection deterministic and read-only, with explicit ruleset coverage rather than a global effectiveness percentage.

### Security Analysis

- Added FULL/OFFLINE Threat Activity, Entity Explorer, ATT&CK Activity, Cross-Investigation Analysis, Temporal Analysis, and Hunt Workspace projections.
- Preserved machine/analyst attribution and explicit boundaries between observation, chronology, overlap, causality, and attacker or campaign identity.

### Operations and Reporting

- Added deterministic Operations Queue prioritization, Operational Summary, Top Attention, uncovered-Finding handling, and terminal/web source navigation.
- Rebuilt Reporting around Report Center, Investigation Report, Executive Summary, and Export Center while keeping Investigation Handoff authoritative and separate.

### System and Terminal

- Added read-only Platform Status, Configuration, Rule / Asset Health, Repository & Storage, Environment, and About screens.
- Unified startup and System readiness signals and completed shared screen-clearing, width, no-color, ASCII-fallback, and cross-platform terminal behavior.
- Added a concise GitHub landing page, complete v3.5 visual walkthrough, and indexed versioned screenshot set across terminal and supported web workflows.

### Safety and Validation

- Response Actions remain analyst-controlled workflow records; SOC-Forge does not execute remediation.
- Read-only projections do not persist derived state or auto-load analysis snapshots.
- The release-candidate suite contains 1,412 tests, including isolated wheel installation and packaged rule/static-asset validation.

## v3.0.0

**Theme:** Durable, evidence-grounded investigation from deterministic analysis through validated handoff.

### Durable Investigation Workspaces

- Persistent local investigations with revision-aware ownership, status, annotations, and decisions.
- Consistent workspace workflows across the analyst console and local web UI.

### Evidence-Centered Investigation

- Stable evidence identities with field-level provenance and bounded sensitive-value handling.
- Analyst selection of supporting, contradicting, and contextual evidence without mutating completed analysis.

### Hypotheses and Decisions

- Analyst-authored hypotheses with controlled assessment, reopening, evidence relationships, and append-only decision history.
- Controlled investigation decisions remain distinct from machine-generated detections and cases.

### Timeline and Pivot Workbench

- Canonical investigation timelines, deterministic filtering, normalized entities, and explainable pivots.
- Evidence and reasoning overlays in read-only console and web workflows.
- Opaque web entity identifiers scoped to an investigation and its matching analysis.

### Investigation Handoff

- Deterministic directory bundles containing bounded investigation, evidence, hypothesis, decision, annotation, timeline, and source-artifact content.
- Artifact allowlisting, SHA-256 inventory, offline validation, tamper detection, and console/web parity.
- Handoff IDs identify an investigation revision and selected investigation identities; they are not a cryptographic content address for every bundle byte.

### Known Limitations

SOC-Forge remains a local, analyst-operated platform. It has no authentication, hosted multi-user support, live collection, automated response, automatic redaction, cryptographic signing, archive packaging, or cloud sharing. Local repository access is not protected by cross-process locking. Live desktop-browser automation remains limited. Process-basename pivots can intentionally broaden matches. Generated artifacts and handoffs may contain sensitive telemetry and analyst-authored content and must be reviewed before sharing.

## v2.3.0

**Theme:** Expanded endpoint detection coverage across collection, defense evasion, and impact.

### Highlights

- Added SOCF-020 archive staging coverage for collection behavior.
- Added SOCF-021 detection for Windows security-control tampering.
- Added SOCF-022 detection for recovery and shadow-copy deletion.
- Added native Windows Security Event ID 4688 paths and provider-qualified Sysmon Event ID 1 paths for the endpoint process rules.
- Corrected attack-step ownership for service execution, Collection, Defense Evasion, and Impact.
- Added reconstruction coverage for SOCF-020, SOCF-021, and SOCF-022.
- Included all 21 built-in YAML rules in wheel and source distributions.
- Added clean-installed-wheel validation that discovers built-in rules outside the source checkout and triggers SOCF-021.

### Detection Limits

These detections provide explainable investigation signals, not malware certainty or prevention. Legitimate administration, backup maintenance, and disaster-recovery testing may produce alerts. Alternate command syntax or tooling may bypass string-based matching. Command-line evidence can contain sensitive arguments and should be reviewed or redacted before sharing generated artifacts. Sysmon Event ID 1 support requires the `Microsoft-Windows-Sysmon` provider and does not imply complete Sysmon compatibility or live response capability.
