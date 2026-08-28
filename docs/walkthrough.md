# SOC-Forge v3.6 Product Walkthrough

This concise tour follows the current local web application. Start `soc-forge-web --port 8765`, open `http://127.0.0.1:8765`, and use the grouped sidebar in this order:

```text
Workspace   Command Center
Operations  Operations / Investigations / Cases
Engineering Detection
Analysis    Security Analysis
Information Reporting / System
```

> Findings are analyst-authored conclusions. Response Actions record analyst-controlled work; SOC-Forge does not execute remediation. Detection Coverage is configured ruleset representation, not observed activity or complete security visibility. Shared observations do not establish attacker or campaign identity, and chronology does not establish causality.

**Modes:** FULL combines current machine analysis with durable analyst state. OFFLINE presents durable analyst state only and is not failure. UNKNOWN means a safe read-only check could not determine a fact; unavailable machine values are not represented as zero.

## 1. Command Center

Begin with current analyst workload, Top Attention, recent attributed activity, and supporting generated security context. The Command Center composes existing sources and owns no priority or risk model. Demo/Lab controls remain collapsed below operational content.

## 2. Detection

Use **Overview** for current alert and rule context, **Alerts** for machine detections, **Rules** for deterministic catalog and explainability, **ATT&CK** for the explicit separation between configured Detection Coverage and observed mappings, and **Health** for the existing scorecard components. Detection is read-only; there are no browser rule-editing controls.

## 3. Operations

Review the server-ordered queue, filter by work type or priority, and select an item to see its authoritative reason and priority basis. Operations does not acknowledge, assign, snooze, execute, or persist queue work. Continue in the owning Investigation Finding or Response Action workflow.

## 4. Investigations and Cases

Cases provide generated triage briefs. Investigations provide durable, revisioned analyst work through **Summary**, **Findings**, **Evidence**, **Timeline**, **Response**, and **Handoff** tabs. Machine evidence and durable analyst reasoning remain attributed separately. Handoff is the structured validated transfer; it is not a Reporting presentation.

## 5. Security Analysis

Use **Overview**, **Entities**, **ATT&CK**, **Relationships**, **Timeline**, and **Hunts** for immutable cross-state exploration. Available host, user, IP address, and process values support exact selection without fuzzy identity resolution. Relationships are deterministic overlap, timelines are chronology, and Hunt projections are review-only.

## 6. Reporting

Use **Overview**, **Reports**, **Investigation Report**, **Executive**, and **Exports** to review existing supported output. Investigation Reports present durable state; Investigation Handoff remains owned by Investigations. Reporting does not generate AI conclusions, schedule delivery, or create a second artifact model.

## 7. System

Use **Status**, **Configuration**, **Health**, **Storage**, **Environment**, and **About** for bounded read-only local inspection. UNKNOWN remains distinct from failure. System does not edit configuration, control services, repair repositories, install packages, or monitor live infrastructure.

## Visual Documentation Status

The versioned v3.5 screenshots remain a historical record and are indexed under [screenshots](screenshots/README.md). Reliable browser capture is not available in the current WSL release-preparation environment, so this v3.6 walkthrough intentionally contains no unverified current screenshots. The screenshot index records the required manual v3.6 capture set.

## Deeper References

- [Web UI](web_ui.md)
- [Web design](web_design.md)
- [Detection Engineering](detection_engineering.md)
- [Operations Queue](operations_queue.md)
- [Investigation domain](investigation_domain.md)
- [Security Analysis](security_analysis.md)
- [Reporting](reporting.md)
- [System Workspace](system_workspace.md)
- [Investigation Handoff](investigation_handoff.md)
