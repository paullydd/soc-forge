# SOC-Forge v3.5 Visual Walkthrough

This tour follows SOC-Forge from platform readiness through detection, durable Investigation reasoning, analysis, operations, reporting, and supported local web views. See the [screenshot index](screenshots/README.md) for the complete 51-file asset inventory.

> **Interpretation boundaries:** Findings are analyst-authored conclusions. Response Actions record analyst-controlled work; SOC-Forge does not execute remediation. Detection Coverage describes explicit ruleset representation, not complete security visibility. Cross-Investigation overlap does not establish the same attacker, campaign, or cause, and temporal proximity does not establish causality.

**Modes:** FULL combines current machine analysis with durable analyst state. OFFLINE presents durable analyst state only; it is not a failure mode and unavailable machine counts are not represented as zero.

## Startup and Command Center

![Startup readiness confirms the runtime, rules, Investigation workspace, analysis snapshots, and analyst services before entering the console](screenshots/v3.5/01-startup-screen.png)

*Startup readiness confirms the runtime, rules, Investigation workspace, analysis snapshots, and analyst services before entering the console.*

![Command Center combines current platform signals with a deterministic summary of operational attention](screenshots/v3.5/02-command-center.png)

*Command Center combines current platform signals with a deterministic summary of operational attention.*

## Detection Engineering

![The Detection menu groups engineering workflows separately from alert results](screenshots/v3.5/03-detection-engine.png)

*The Detection menu groups engineering workflows separately from alert results.*

![Detection Overview summarizes the loaded ruleset and recent triggered activity](screenshots/v3.5/04-detection-overview.png)

*Detection Overview summarizes the loaded ruleset and recent triggered activity.*

![Rule Catalog inventories enabled rules, severity, and explicit ATT&CK mappings](screenshots/v3.5/05-rule-catalog.png)

*Rule Catalog inventories enabled rules, severity, and explicit ATT&CK mappings.*

![Rule Detail exposes configured metadata, matching, aggregation, output, and score modifiers](screenshots/v3.5/06-rule-detail-password-spray.png)

*Rule Detail exposes configured metadata, matching, aggregation, output, and score modifiers.*

![Rule Explainability translates configured rule logic into deterministic analyst-readable sections without executing it](screenshots/v3.5/07-rule-explainability-password-spray.png)

*Rule Explainability translates configured rule logic into deterministic analyst-readable sections without executing it.*

![Coverage Summary counts explicit ruleset mappings; it is not a completeness or effectiveness score](screenshots/v3.5/08-detection-coverage-summary.png)

*Coverage Summary counts explicit ruleset mappings; it is not a completeness or effectiveness score.*

![Tactic coverage connects represented tactics to techniques and owning rules](screenshots/v3.5/09-attack-tactic-coverage.png)

*Tactic coverage connects represented tactics to techniques and owning rules.*

![Technique coverage distinguishes enabled and disabled rule ownership](screenshots/v3.5/10-attack-technique-coverage.png)

*Technique coverage distinguishes enabled and disabled rule ownership.*

![Detection Gaps states the configured baseline boundary and avoids inventing gaps when no baseline exists](screenshots/v3.5/11-detection-gaps.png)

*Detection Gaps states the configured baseline boundary and avoids inventing gaps when no baseline exists.*

![Detection Lab separates telemetry analysis, controlled simulations, rule-only evaluation, and the last result](screenshots/v3.5/12-detection-lab.png)

*Detection Lab separates telemetry analysis, controlled simulations, rule-only evaluation, and the last result.*

![Authoritative synthetic scenarios provide repeatable inputs; the Windows events are test data and do not execute PowerShell](screenshots/v3.5/13-attack-simulation-scenarios.png)

*Authoritative synthetic scenarios provide repeatable inputs; the Windows events are test data and do not execute PowerShell.*

![An Attack Chain result reports triggered rules and existing pipeline artifacts](screenshots/v3.5/14-attack-chain-detection-result.png)

*An Attack Chain result reports triggered rules and existing pipeline artifacts.*

![Triggered rules drill into the same authoritative explanation used by the catalog](screenshots/v3.5/15-triggered-rule-explainability.png)

*Triggered rules drill into the same authoritative explanation used by the catalog.*

![Alert Explorer owns alert listing and search](screenshots/v3.5/16-alert-explorer.png)

*Alert Explorer owns alert listing and search.*

![Alert listing preserves rule, severity, timestamp, and source context](screenshots/v3.5/16.1-alert-explorer-view-alerts.png)

*Alert listing preserves rule, severity, timestamp, and source context.*

![Alert Detail shows bounded evidence and ATT&CK mappings for analyst review](screenshots/v3.5/17-alert-detail-socf-008.png)

*Alert Detail shows bounded evidence and ATT&CK mappings for analyst review.*

![Alert search returns deterministic matches and supports authoritative detail navigation](screenshots/v3.5/18-search-results.png)

*Alert search returns deterministic matches and supports authoritative detail navigation.*

## Investigations

![Investigation navigation separates cases, durable workspaces, evidence and reasoning, Findings, and status management](screenshots/v3.5/19-investigation-workspaces.png)

*Investigation navigation separates cases, durable workspaces, evidence and reasoning, Findings, and status management.*

![The first Summary view establishes Investigation identity, revision, OFFLINE mode, and durable analyst assessment](screenshots/v3.5/20-investigation-summary.png)

*The first Summary view establishes Investigation identity, revision, OFFLINE mode, and durable analyst assessment.*

![The Summary continues through selected evidence, hypotheses, and append-only analyst decisions](screenshots/v3.5/20.1-investigation-summary.png)

*The Summary continues through selected evidence, hypotheses, and append-only analyst decisions.*

![Active and historical Findings remain distinct from linked Response Actions](screenshots/v3.5/20.2-investigation-summary.png)

*Active and historical Findings remain distinct from linked Response Actions.*

![Evidence review distinguishes scope references from analyst-selected evidence and records classification and rationale](screenshots/v3.5/21-selected-evidence.png)

*Evidence review distinguishes scope references from analyst-selected evidence and records classification and rationale.*

![Hypothesis Detail connects a statement, analyst assessment, evidence relationships, and assessment decisions](screenshots/v3.5/22-hypothesis-details.png)

*Hypothesis Detail connects a statement, analyst assessment, evidence relationships, and assessment decisions.*

![Decision Detail preserves author, timestamp, outcome, rationale, and referenced reasoning](screenshots/v3.5/23-analyst-decision.png)

*Decision Detail preserves author, timestamp, outcome, rationale, and referenced reasoning.*

![A Finding is an analyst-authored conclusion with explicit basis, confidence, ATT&CK context, and limitations](screenshots/v3.5/24-analyst-findings.png)

*A Finding is an analyst-authored conclusion with explicit basis, confidence, ATT&CK context, and limitations.*

![A Response Action records analyst-controlled work and immutable lifecycle history; SOC-Forge does not execute remediation](screenshots/v3.5/25-response-details.png)

*A Response Action records analyst-controlled work and immutable lifecycle history; SOC-Forge does not execute remediation.*

## Security Analysis

![Threat Activity describes broad recorded security state while preserving machine and analyst attribution](screenshots/v3.5/26-threat-activity-overview.png)

*Threat Activity describes broad recorded security state while preserving machine and analyst attribution.*

![Entity Explorer uses exact structured-field matches; repeated observations do not establish a shared attacker or campaign](screenshots/v3.5/27-entity-explorer.png)

*Entity Explorer uses exact structured-field matches; repeated observations do not establish a shared attacker or campaign.*

![ATT&CK Activity summarizes observed or recorded mappings, not Detection Coverage](screenshots/v3.5/28-att&ck-summary.png)

*ATT&CK Activity summarizes observed or recorded mappings, not Detection Coverage.*

![Technique Detail shows observation provenance and Investigation representation without inferring tactic pairings](screenshots/v3.5/29-att$ck%20technique-detail.png)

*Technique Detail shows observation provenance and Investigation representation without inferring tactic pairings.*

![Cross-Investigation Analysis reports shared structured observations only, never common attacker, campaign, or cause](screenshots/v3.5/30-cross-investigation-analysis.png)

*Cross-Investigation Analysis reports shared structured observations only, never common attacker, campaign, or cause.*

![Temporal Analysis orders recorded activity without claiming causality](screenshots/v3.5/31-chronological-activity.png)

*Temporal Analysis orders recorded activity without claiming causality.*

![Hunt by Investigation projects structured current state and keeps analyst activity attribution visible](screenshots/v3.5/32-hunt-results.png)

*Hunt by Investigation projects structured current state and keeps analyst activity attribution visible.*

## Operations Queue

![Queue summary and top work are deterministic projections of authoritative durable state](screenshots/v3.5/33-operations-queue.png)

*Queue summary and top work are deterministic projections of authoritative durable state.*

![Each attention item explains its source, priority basis, and authoritative navigation target](screenshots/v3.5/34-operations-queue-item.png)

*Each attention item explains its source, priority basis, and authoritative navigation target.*

![An uncovered active Finding opens in the authoritative Finding workflow; the queue does not own or mutate it](screenshots/v3.5/35-undercovered-finding.png)

*An uncovered active Finding opens in the authoritative Finding workflow; the queue does not own or mutate it.*

## Reporting

![Report Center discovers current human-readable analysis reports](screenshots/v3.5/36-report-center.png)

*Report Center discovers current human-readable analysis reports.*

![Investigation Report projects durable reasoning, response work, ATT&CK observations, and source limitations](screenshots/v3.5/37-investigation-report.png)

*Investigation Report projects durable reasoning, response work, ATT&CK observations, and source limitations.*

![Executive Summary deterministically combines operations, observed ATT&CK, recent analyst activity, and mode context](screenshots/v3.5/38-executive-summary.png)

*Executive Summary deterministically combines operations, observed ATT&CK, recent analyst activity, and mode context.*

## System

![Platform Status performs read-only capability checks; UNKNOWN is distinct from FAILED](screenshots/v3.5/40-platform-status.png)

*Platform Status performs read-only capability checks; UNKNOWN is distinct from FAILED.*

![Configuration displays the loaded source and effective values without mutation](screenshots/v3.5/41-configuration-summary.png)

*Configuration displays the loaded source and effective values without mutation.*

![Rule and Asset Health verifies loadability and packaged resources without write probes](screenshots/v3.5/43-rule-asset-health.png)

*Rule and Asset Health verifies loadability and packaged resources without write probes.*

![About states the v350 scope and the non-remediation safety boundary](screenshots/v3.5/44-about-soc-forge.png)

*About states the v3.5.0 scope and the non-remediation safety boundary.*

## Web Interface

![The local web Command Center provides dashboard triage over generated analysis artifacts](screenshots/v3.5/45-web-command-center.png)

*The local web Command Center provides dashboard triage over generated analysis artifacts.*

![The authoritative web Finding view safely renders analyst-authored conclusions and references](screenshots/v3.5/47-web-finding.png)

*The authoritative web Finding view safely renders analyst-authored conclusions and references.*

![Web Response Action detail preserves non-execution language, related Findings, and transition history](screenshots/v3.5/48-lifecycle-web.png)

*Web Response Action detail preserves non-execution language, related Findings, and transition history.*

![The web Operations Queue matches deterministic terminal membership, counts, order, and reasons](screenshots/v3.5/49-web-operations-queue.png)

*The web Operations Queue matches deterministic terminal membership, counts, order, and reasons.*

![Queue source navigation reaches the authoritative Finding detail without duplicating Finding data into the queue](screenshots/v3.5/50-web-undercover-finding.png)

*Queue source navigation reaches the authoritative Finding detail without duplicating Finding data into the queue.*

## Where to Go Next

- [Detection Engineering](detection_engineering.md)
- [Security Analysis](security_analysis.md)
- [Investigation Summary](investigation_summary.md)
- [Investigation Findings](investigation_findings.md)
- [Response Actions](response_actions.md)
- [Operations Queue](operations_queue.md)
- [Reporting](reporting.md)
- [System Workspace](system_workspace.md)
- [Investigation Handoff](investigation_handoff.md)

The source folder contains one additional valid asset, `46-web-investigation-workspace.png`, that records a superseded manual-validation defect state. It is retained for inventory integrity but intentionally omitted from the current product tour.
