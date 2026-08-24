# Release Notes

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
