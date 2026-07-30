# Release Notes

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
