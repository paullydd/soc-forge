# SOC-Forge

SOC-Forge is a lightweight **Security Operations Center (SOC) detection engine** written in Python.  
It processes security events, applies detection rules, correlates related alerts into investigation cases, and generates an interactive HTML report that helps analysts understand potential attack activity.

The goal of this project is to demonstrate how a **modern detection pipeline** works in real SOC environments.

---

# Features

SOC-Forge currently includes:

## Event Processing
- Ingests structured security events
- Normalizes event data for analysis

## Detection Engine
- YAML-based detection rules
- MITRE ATT&CK tactic mapping
- Modular rule engine

## Correlation
- Groups related alerts into investigation **cases**
- Detects multi-step attack behavior

## Case Analysis
- Timeline reconstruction
- Indicator extraction (IPs, hosts, users)
- Risk scoring per case
- Analyst-style investigation summary

## Attack Chain Visualization
- Reconstructs attacker activity stages
- Maps events to MITRE ATT&CK tactics
- Displays attack progression inside the report

## Reporting

SOC-Forge generates a detailed **HTML investigation report** including:

- Severity statistics
- MITRE coverage
- Correlation summary
- Investigation cases
- Indicators of compromise (IOCs)
- Attack timeline
- Attack chain reconstruction

## Testing & CI

- Automated tests with **pytest**
- GitHub Actions CI pipeline
- Multi-version testing (Python 3.10, 3.11, 3.12)

---

# Project Architecture

SOC-Forge follows a simplified SOC detection pipeline:

Below is the same README formatted exactly for a README.md file so you can copy-paste it directly into your repo.

# SOC-Forge

SOC-Forge is a lightweight **Security Operations Center (SOC) detection engine** written in Python.  
It processes security events, applies detection rules, correlates related alerts into investigation cases, and generates an interactive HTML report that helps analysts understand potential attack activity.

The goal of this project is to demonstrate how a **modern detection pipeline** works in real SOC environments.

---

# Features

SOC-Forge currently includes:

## Event Processing
- Ingests structured security events
- Normalizes event data for analysis

## Detection Engine
- YAML-based detection rules
- MITRE ATT&CK tactic mapping
- Modular rule engine

## Correlation
- Groups related alerts into investigation **cases**
- Detects multi-step attack behavior

## Case Analysis
- Timeline reconstruction
- Indicator extraction (IPs, hosts, users)
- Risk scoring per case
- Analyst-style investigation summary

## Attack Chain Visualization
- Reconstructs attacker activity stages
- Maps events to MITRE ATT&CK tactics
- Displays attack progression inside the report

## Reporting

SOC-Forge generates a detailed **HTML investigation report** including:

- Severity statistics
- MITRE coverage
- Correlation summary
- Investigation cases
- Indicators of compromise (IOCs)
- Attack timeline
- Attack chain reconstruction

## Testing & CI

- Automated tests with **pytest**
- GitHub Actions CI pipeline
- Multi-version testing (Python 3.10, 3.11, 3.12)

---

# Project Architecture

SOC-Forge follows a simplified SOC detection pipeline:


Security Events
↓
Event Normalization
↓
Detection Rules (YAML)
↓
Alert Generation
↓
Correlation Engine
↓
Case Grouping
↓
Risk Scoring
↓
IOC Extraction
↓
Attack Chain Reconstruction
↓
HTML Investigation Report
---

# Example Attack Chain

SOC-Forge can reconstruct multi-stage attack behavior.

Example investigation:
Credential Access → Lateral Movement → Persistence


Detected events may include:


Account Lockout
RDP Logon
Scheduled Task Created

These events are grouped into a single investigation case with a timeline and evidence.

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/soc-forge.git
cd soc-forge

Install the project:

pip install -e .

Usage

Run SOC-Forge against a sample event file:

soc-forge --input sample_events.jsonl

Output files will be generated in the out/ directory:

out/
 ├── alerts.json
 ├── normalized_events.jsonl
 └── report.html

Open the HTML report in a browser to view the investigation results.

Running Tests

SOC-Forge includes a full test suite.

Run all tests with:

pytest -q

Tests cover:

Detection rules

Correlation logic

Risk scoring

MITRE mapping

Case enrichment

Attack chain reconstruction

Example Repository Structure
soc-forge
│
├── soc_forge
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── ingest
│   ├── rules
│   ├── correlate
│   ├── scoring
│   └── report
│
├── tests
├── sample_events.jsonl
├── config.yml
├── pyproject.toml
└── README.md
MITRE ATT&CK Alignment

SOC-Forge detection rules can map alerts to MITRE ATT&CK tactics, enabling investigation views such as:

Initial Access

Credential Access

Lateral Movement

Persistence

Privilege Escalation

The engine reconstructs attack progression across these tactics.

Project Goals

This project was built to explore and demonstrate:

SOC detection engineering

SIEM-style correlation pipelines

MITRE ATT&CK mapping

Incident investigation workflows

Python-based security tooling
```

## Phase 11 – Detection Depth

Phase 11 expands SOC-Forge detection coverage with additional Windows security detections and multi-stage correlations.

### New detections

- SOCF-007 – New user account created
- SOCF-008 – Privileged group membership change
- SOCF-009 – Windows Security log cleared

### New correlations

- SOCF-CORR-004 – New account followed by privileged group assignment
- SOCF-CORR-005 – New privileged account followed by audit log clearing

### Example attack chain

Create Account → Privilege Escalation → Defense Evasion

SOC-Forge automatically detects this pattern and produces a high-confidence case investigation report.

## 🔎 Threat Hunting (Phase 12)

SOC-Forge now includes a threat hunting engine to identify suspicious behavior even when no detection rules fire.

### Hunt Capabilities
- Suspicious command execution (e.g., PowerShell encoded)
- Rare source IP detection per user
- Multi-host lateral movement detection
- Failed login burst detection

### Output
- CLI hunt summary
- JSON export (`out/hunts.json`)
- Integrated HTML report section with:
  - Findings
  - Entities
  - Evidence
  - MITRE mapping


## v1.0.0

SOC-Forge v1.0.0 is the first major release of a mini SOC detection, investigation, and threat hunting platform.

### Core capabilities
- Event ingestion from JSONL and Windows Security CSV
- YAML-based detection rules
- Alert correlation
- Case building and evidence expansion
- MITRE ATT&CK mapping
- IOC extraction and recommended actions
- Threat hunting analytics
- Risk overview scoring
- HTML investigation reporting

## Attack Simulation

SOC-Forge can generate simulated authentication attack data for end-to-end validation.

### Brute force
```bash
soc-forge --simulate brute_force --sim-output out/simulated_events.jsonl
soc-forge --input out/simulated_events.jsonl
