# Release Notes

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
