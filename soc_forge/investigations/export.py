from typing import Any, Dict


def build_case_brief(case: Dict[str, Any]) -> str:
    quality = case.get("case_quality") or case.get("header", {}).get("details", {}).get("case_quality", {}) or {}
    executive_summary = quality.get("executive_summary") or case.get("executive_summary") or case.get("summary") or "No executive summary available."
    key_findings = quality.get("key_findings") or []
    key_evidence = quality.get("key_evidence") or []
    containment = quality.get("containment_guidance") or case.get("containment_guidance") or []
    gaps = quality.get("quality_gaps") or []

    lines = [
        f"Case ID: {case.get('case_id', case.get('id', 'Unknown'))}",
        f"Title: {case.get('title', case.get('name', 'Untitled Case'))}",
        f"Risk Score: {case.get('risk_score', case.get('risk', 'N/A'))}",
        f"Quality Score: {quality.get('quality_score', 'N/A')}",
        "",
        "Executive Summary:",
        str(executive_summary),
    ]

    lines.extend(["", "Key Findings:"])
    lines.extend([f"- {item}" for item in key_findings] or ["No key findings generated."])

    lines.extend(["", "Key Evidence:"])
    if key_evidence:
        for item in key_evidence:
            lines.append(
                f"- {item.get('timestamp', '')} | {item.get('rule_id', '')} | "
                f"{item.get('title', '')} | {item.get('why_it_matters', '')}"
            )
    else:
        lines.append("No key evidence generated.")

    lines.extend(["", "Containment Guidance:"])
    lines.extend([f"- {item}" for item in containment] or ["No containment guidance generated."])

    if gaps:
        lines.extend(["", "Quality Gaps:"])
        lines.extend(f"- {gap}" for gap in gaps)

    return "\n".join(lines)


def build_closure_report(case: Dict[str, Any]) -> str:
    status = case.get("status", "New")
    disposition = case.get("disposition", "Not set")
    closure_summary = case.get("closure_summary", "") or "No closure summary recorded."
    containment_action = case.get("containment_action", "") or "No containment action recorded."

    history_lines = []
    for event in case.get("status_history", []):
        if not isinstance(event, dict):
            continue
        line = f"- {event.get('changed_at', 'unknown time')} | {event.get('changed_by', 'analyst')} | {event.get('status', 'Unknown')}"
        if event.get("reason"):
            line += f" | {event['reason']}"
        history_lines.append(line)

    return "\n".join(
        [
            f"Case ID: {case.get('case_id', case.get('id', 'Unknown'))}",
            f"Title: {case.get('title', case.get('name', 'Untitled Case'))}",
            f"Status: {status}",
            f"Disposition: {disposition}",
            f"Owner: {case.get('owner', 'Unassigned')}",
            f"Updated: {case.get('updated_at', 'Unknown')}",
            "",
            "Closure Summary:",
            closure_summary,
            "",
            "Containment Action:",
            containment_action,
            "",
            "Status History:",
            "\n".join(history_lines) if history_lines else "No status history recorded.",
        ]
    )
