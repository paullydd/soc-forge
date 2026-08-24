# Reporting workspace

SOC-Forge v3.5 Reporting is a read-only delivery workspace built from existing authoritative state. It does not introduce a report registry, a second operations model, persistence, mutation, AI-generated conclusions, or remediation execution.

## Navigation and ownership

The terminal Reporting menu contains:

1. Report Center
2. Investigation Report
3. Executive Summary
4. Export Center
0. Back

ATT&CK Coverage remains owned by Detection and is not duplicated here. Investigation Handoff remains owned by the Investigation Workspace; Export Center points analysts to that existing workflow instead of recreating its schema or export implementation.

## Report Center

Report Center discovers only the bounded set of known analysis HTML report filenames under the configured output directory. Analysts can inspect and open an existing artifact using the established report opener. Discovery does not scan arbitrary paths, create a registry, parse report content, or modify an artifact.

## Investigation Report

Investigation Report reads one durable Investigation record and its repository revision. It presents metadata, active and historical Findings, evidence-reference counts and classifications, hypotheses, decisions, annotations, Response Actions and transition counts, and observed ATT&CK mappings. It is a human-readable screen, not an export bundle and not a replacement for Investigation Handoff.

FULL mode indicates that the current process has source analysis context. OFFLINE mode preserves the same durable analyst report and explicitly marks machine context unavailable. Protected evidence values are never rendered.

## Executive Summary

Executive Summary composes the existing Operational Summary, Threat Activity Overview, and ATT&CK Activity projections. Counts and the top attention item therefore retain the same deterministic Operations Queue prioritization semantics. It adds no independent calculation or source of truth. Recent activity is bounded and analyst-authored; ATT&CK rows are bounded projections from observed activity.

## Safety and limitations

Every report screen is read-only. Viewing or navigating Reporting does not save an Investigation, alter a Response Action, rerun detection, execute remediation, or write repository state. Screens use the shared terminal rendering and clearing conventions and include a warning that telemetry and analyst-authored content may be sensitive and should be reviewed before external sharing.
System may report the bounded count and availability of known analysis report files as storage health. It does not open, parse, register, export, or take ownership of those reports; Report Center remains the authoritative Reporting discovery workflow.