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