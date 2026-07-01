import json
import os
from typing import Any, Dict

from soc_forge.ui.panels import header, success, warning


def export_investigation_bundle(case: Dict[str, Any]) -> None:
    case_id = case.get("case_id", case.get("id", "unknown"))
    safe_case_id = str(case_id).replace(" ", "_")

    output_dir = f"out/investigation_bundle_case_{safe_case_id}"
    os.makedirs(output_dir, exist_ok=True)

    write_text(output_dir, "case_summary.txt", build_case_summary(case))
    write_json(output_dir, "timeline.json", case.get("timeline", []))
    write_json(output_dir, "indicators.json", case.get("indicators", case.get("iocs", {})))
    write_text(output_dir, "notes.txt", build_notes(case))
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
            f"Risk Score: {case.get('risk_score', case.get('risk', 'N/A'))}",
            f"Created: {case.get('created_at', case.get('created', 'Unknown'))}",
            "",
            "MITRE:",
            str(case.get("mitre", case.get("mitre_attack", case.get("techniques", [])))),
        ]
    )


def build_notes(case: Dict[str, Any]) -> str:
    notes = case.get("notes", [])

    if not notes:
        return "No analyst notes available."

    return "\n".join(f"- {note}" for note in notes)


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