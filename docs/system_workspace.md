# System workspace

See the [v3.6 product walkthrough](walkthrough.md) for the current end-to-end interface tour.

SOC-Forge v3.6 System provides local platform inspection. It does not continuously monitor services or modify configuration.

## Ownership and navigation

System answers how the local SOC-Forge process is configured and operating through Platform Status, Configuration, Rule / Asset Health, Repository & Storage, Environment, and About SOC-Forge. It does not duplicate Detection Coverage, security-data Analysis, durable Investigation state, Operations prioritization, or Reporting exports.

All screens are read-only. Inspection does not create probe files, save configuration, change environment variables, start or stop services, install packages, load snapshots, alter Investigation revisions, or modify rules, artifacts, or output data.

## Platform Status

Platform Status is an immutable current-process projection. Startup and System consume the same authoritative status model instead of fixed presentation labels. Checks use the installed Python runtime, built-in rule loader, Investigation repository capability, snapshot/output capability, importable analyst services, report renderer, and required packaged web assets.

Controlled component states are `ready`, `degraded`, `unavailable`, and `unknown`:

- `ready`: the checked capability is locally usable.
- `degraded`: core operation remains possible, but a checked capability is partial.
- `unavailable`: an authoritative check shows that the capability cannot operate.
- `unknown`: SOC-Forge cannot make a reliable determination.

Runtime, Detection Rules, Investigation Repository, Analysis Services, and Analyst Services are required. Reporting Assets and Web Assets are optional for core terminal operation. A required unavailable component makes the overall state unavailable; a required degraded component or unavailable/degraded optional component makes it degraded; an unknown required component makes it unknown; otherwise all checked components produce ready. There is no numeric health score.

This is a bounded local inspection, not live monitoring. System performs no port probes, process polling, uptime tracking, network checks, background loops, or service control.

## Configuration

Configuration uses the existing `load_config` function and immutable configuration model. The screen identifies the configured source, whether that file was loaded, and a bounded allowlist of current effective output, brute-force, and correlation values. When the file is absent, loader defaults are labeled explicitly. Secrets are not dumped; no editor, reveal, save, reset, or reload operation exists.

## Rule / Asset Health

Rule / Asset Health uses the built-in rule path and existing rule loader. It reports discovered YAML files, loaded rules, bounded parse failures, required web static assets, and the HTML report renderer. It answers whether packaged resources can be loaded and used. It does not calculate rule effectiveness or ATT&CK Detection Coverage, and does not list tactic or technique coverage.

## Repository & Storage

Repository & Storage inspects only bounded known paths: the configured Investigation repository, output directory, completed-analysis snapshot directory, and known analysis report filenames. It reports path existence, OS permission-based readability/writability capability, Investigation count when repository records can be read, snapshot-location existence, and known report count.

A writability result is permission/capability inspection only. System never creates a test file or initializes a missing directory to prove writability, and it does not recursively scan output trees or Handoff content.

## Environment and About

Environment uses Python `sys`, `platform`, `pathlib`, and `os` facilities so it works on macOS, Linux, WSL, and Windows without shell commands or assumptions about home paths, shells, or virtual-environment directory names. It reports the SOC-Forge and Python versions, platform, architecture, executable, working directory, virtual-environment detection, terminal interactivity, and current color capability.

About summarizes detection and correlation, Detection Engineering, Investigations and analyst reasoning, Findings, Response Actions, Operations Queue, Security Analysis, Reporting/Handoff, and terminal/local-web interfaces. SOC-Forge records analyst-controlled response work. It does not execute remediation or claim production monitoring automation.

## Deferred capabilities

Configuration editing, environment management, package installation, self-update, rule editing, repository repair, backup/restore, service controls, live health polling, performance dashboards, web/API System parity, remote diagnostics, telemetry health, and AI diagnostics remain outside this workspace.
