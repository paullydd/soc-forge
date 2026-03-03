# SOC-Forge

Mini SOC detection engine (Phase 1).

## Run (dev)
python3 soc_forge/cli.py --input sample_events.jsonl

## Install editable + run as CLI
pip install -e .
soc-forge --input sample_events.jsonl

# SOC-Forge

SOC-Forge is a lightweight detection and correlation engine for Windows Security logs.

It simulates core SOC detection logic including:
- Signature-based detections
- Heuristic scoring
- Multi-stage attack correlation
- MITRE ATT&CK mapping
- Case-based HTML reporting

---

## 🚀 Current Version

**v0.3.0 – Phase 3: Detection Depth Complete**

### Detection Coverage
- SOCF-001: Brute Force (4625)
- SOCF-002: Account Lockout (4740)
- SOCF-003: Privileged Group Change (4728/4732)
- SOCF-004: New Service Installed (7045)
- SOCF-005: Scheduled Task Created (4698)
- SOCF-006: Suspicious RDP Logon (4624 LogonType 10)

### Correlation Engine
- SOCF-CORR-001: Brute Force → Lockout
- SOCF-CORR-002: RDP → Scheduled Task
- SOCF-CORR-003: RDP → Privileged Group Change

### Features
- Config-driven detection logic (YAML)
- Heuristic scoring with severity escalation
- Windows Security CSV ingestion
- JSONL ingestion
- Deterministic correlation IDs
- HTML case-based reporting
- Pytest test suite
- GitHub Actions CI

---

## 📦 Example Usage

```bash
soc-forge --input sample_events.jsonl --format jsonl