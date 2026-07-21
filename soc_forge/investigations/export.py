import json
import os
from typing import Any, Dict

from soc_forge.ui.panels import header, success, warning
from soc_forge.cases.lifecycle import ensure_case_lifecycle


def export_investigation_bundle(case: Dict[str, Any]) -> None:
    ensure_case_lifecycle(case)
    case_id = case.get("case_id", case.get("id", "unknown"))
    safe_case_id = str(case_id).replace(" ", "_")

    output_dir = f"out/investigation_bundle_case_{safe_case_id}"
    os.makedirs(output_dir, exist_ok=True)

    write_text(output_dir, "case_summary.txt", build_case_summary(case))
    write_text(output_dir, "case_brief.txt", build_case_brief(case))
    write_text(output_dir, "closure_report.txt", build_closure_report(case))
    write_json(output_dir, "timeline.json", case.get("timeline", []))
    write_json(output_dir, "indicators.json", case.get("indicators", case.get("iocs", {})))
    write_text(output_dir, "notes.txt", build_notes(case))
    write_json(output_dir, "lifecycle.json", build_lifecycle(case))
    write_json(output_dir, "evidence.json", case.get("evidence", []))
    write_text(output_dir, "attack_graph.txt", build_attack_graph(case))
    write_text(output_dir, "story.txt", case.get("story", case.get("analyst_summary", "")))

    header("INVESTIGATION BUNDLE EXPORTED")
    success(f"Bundle created at: {output_dir}")

    input("\nPress Enter to return...")


def build_case_summary(case: Dict[str, Any]) -> str:
    return "\n".join(
        [
            f"Case ID: {case.get('case_id', case.get('id', 'Unknown'))}",
            f"Title: {case.get('title', case.get('name', 'Untitled Case'))}",
            f"Status: {case.get('status', 'New')}",
            f"Owner: {case.get('owner', 'Unassigned')}",
            f"Risk Score: {case.get('risk_score', case.get('risk', 'N/A'))}",
            f"Created: {case.get('created_at', case.get('created', 'Unknown'))}",
            f"Updated: {case.get('updated_at', 'Unknown')}",
            "",
            "MITRE:",
            str(case.get("mitre", case.get("mitre_attack", case.get("techniques", [])))),
        ]
    )


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


def build_notes(case: Dict[str, Any]) -> str:
    notes = case.get("notes", [])

    if not notes:
        return "No analyst notes available."

    lines = []
    for note in notes:
        if isinstance(note, dict):
            timestamp = note.get("created_at") or "unknown time"
            author = note.get("author") or "analyst"
            text = note.get("text", "")
            lines.append(f"- {timestamp} | {author}: {text}")
        else:
            lines.append(f"- {note}")

    return "\n".join(lines)


def build_lifecycle(case: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": case.get("status", "New"),
        "owner": case.get("owner", "Unassigned"),
        "created_at": case.get("created_at"),
        "updated_at": case.get("updated_at"),
        "status_history": case.get("status_history", []),
        "notes": case.get("notes", []),
    }


def build_attack_graph(case: Dict[str, Any]) -> str:
    graph = case.get("attack_graph", case.get("graph", ""))

    if isinstance(graph, list):
        return "\n".join(str(line) for line in graph)

    return str(graph) if graph else "No attack graph available."


def write_text(output_dir: str, filename: str, content: str) -> None:
    path = os.path.join(output_dir, filename)

    with open(path, "w", encoding="utf-8") as file:
        file.write(content)


def write_json(output_dir: str, filename: str, content: Any) -> None:
    path = os.path.join(output_dir, filename)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(content, file, indent=4)