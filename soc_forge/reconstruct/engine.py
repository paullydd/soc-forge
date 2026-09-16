from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .heuristics import score_link
from .models import (
    AttackReconstruction,
    ReconstructionEdge,
    ReconstructionEvidence,
    ReconstructionStep,
)


RULE_TO_RECON = {
    "SOCF-001": ("Credential Access", "Credential Access", "T1110", "Brute force login attempts"),
    "SOCF-002": ("Credential Access", "Credential Access", None, "Account lockout observed"),
    "SOCF-003": ("Privilege Escalation", "Privilege Escalation", "T1098", "Privileged group membership change"),
    "SOCF-004": ("Persistence", "Service Execution", "T1543", "Suspicious service installation"),
    "SOCF-005": ("Persistence", "Persistence", "T1053.005", "Suspicious scheduled task created"),
    "SOCF-006": ("Initial Access", "Initial Access", "T1021.001", "Successful RDP logon"),
    "SOCF-016": ("Lateral Movement", "Service Execution", "T1021.002", "PsExec-style service execution"),
    "SOCF-020": ("Collection", "Collection", "T1560", "Suspicious archive staging of sensitive files"),
    "SOCF-021": ("Defense Evasion", "Defense Evasion", "T1562.001", "Windows security control tampering"),
    "SOCF-022": ("Impact", "Impact", "T1490", "System recovery or shadow copy deletion"),
    "SOCF-023": ("Initial Access", "Initial Access", "T1133", "RDP logon from an external-looking source address"),
    "SOCF-024": ("Discovery", "Discovery", "T1087", "Account or group discovery command execution"),
    "SOCF-027": ("Initial Access", "Initial Access", "T1133", "SSH logon from an external-looking source address"),
    "SOCF-028": ("Privilege Escalation", "Privilege Escalation", "T1053.003", "Tar checkpoint-action wildcard injection (Linux)"),
    "SOCF-029": ("Reconnaissance", "Reconnaissance", "T1595.003", "Web content-discovery burst"),
    "SOCF-030": ("Credential Access", "Credential Access", "T1552.001", "Sensitive file or path exposed via web server"),
}


def _candidate_from_item(item: Dict[str, Any], idx: int) -> Dict[str, Any] | None:
    rule_id = item.get("rule_id")
    if rule_id not in RULE_TO_RECON:
        return None

    tactic, stage, technique, default_title = RULE_TO_RECON[rule_id]
    details = item.get("details", {}) or {}

    return {
        "id": f"cand-{idx}",
        "rule_id": rule_id,
        "title": item.get("title") or default_title,
        "tactic": tactic,
        "stage": stage,
        "technique": technique,
        "ts": item.get("timestamp") or item.get("ts"),
        # Real pipeline alerts (soc_forge/rules/engine.py) nest the source
        # address under details["ip"], not details["src_ip"] - fall back to
        # both so IP-based edge scoring (score_link's heaviest signal) works
        # on real data, not just flat-shaped test fixtures that happen to use
        # the "src_ip" spelling.
        "src_ip": item.get("src_ip") or details.get("src_ip") or details.get("ip"),
        "username": item.get("username") or details.get("username"),
        "host": item.get("host") or details.get("host"),
        "score": float(item.get("score", 0) or 0),
        "confidence": min(0.55 + (float(item.get("score", 0) or 0) / 200.0), 0.98),
        "raw": item,
    }


def build_candidates(case_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for idx, item in enumerate(case_items, start=1):
        cand = _candidate_from_item(item, idx)
        if cand:
            out.append(cand)
    out.sort(key=lambda x: x.get("ts") or "")
    return out


def build_edges(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    for i, a in enumerate(candidates):
        for j in range(i + 1, len(candidates)):
            b = candidates[j]
            score, reasons = score_link(a, b)
            if score >= 0.55:
                edges.append({
                    "from": a["id"],
                    "to": b["id"],
                    "weight": score,
                    "reasons": reasons,
                })
    return edges


def extract_path(candidates: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not candidates:
        return [], []

    # candidates is already sorted by timestamp, and build_edges only ever
    # creates edges from an earlier index to a later one - so array order is
    # already a topological order and this is a DP longest-weighted-path
    # search over a DAG, not a greedy walk. best_score[j] is the best total
    # edge weight of any path ending at candidate j, allowing j to be a fresh
    # start of its own (baseline 0.0) so the search isn't locked into
    # starting at candidates[0] the way the old greedy walk was.
    id_to_index = {c["id"]: i for i, c in enumerate(candidates)}
    incoming: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges:
        incoming.setdefault(e["to"], []).append(e)

    best_score = [0.0] * len(candidates)
    best_prev: List[int | None] = [None] * len(candidates)
    best_edge: List[Dict[str, Any] | None] = [None] * len(candidates)

    for j, c in enumerate(candidates):
        for e in incoming.get(c["id"], []):
            i = id_to_index[e["from"]]
            candidate_score = best_score[i] + e["weight"]
            if candidate_score > best_score[j]:
                best_score[j] = candidate_score
                best_prev[j] = i
                best_edge[j] = e

    # Pick the best-scoring endpoint; ties prefer the earlier candidate so
    # the narrative still favors "start at the earliest coherent activity"
    # when multiple paths score equally.
    end = min(range(len(candidates)), key=lambda j: (-best_score[j], j))

    order: List[int] = []
    idx: int | None = end
    while idx is not None:
        order.append(idx)
        idx = best_prev[idx]
    order.reverse()

    path = [candidates[i] for i in order]
    rels = [best_edge[i] for i in order[1:]]

    if len(path) == 1 and len(candidates) > 1:
        path = candidates[:]
        rels = []

    return path, rels


def maybe_insert_inferred_steps(path: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not path:
        return []

    final_path: List[Dict[str, Any]] = [path[0]]

    for prev, curr in zip(path, path[1:]):
        if prev.get("rule_id") == "SOCF-001" and curr.get("rule_id") == "SOCF-006":
            final_path.append({
                "id": f"inferred-{prev['id']}-{curr['id']}",
                "rule_id": None,
                "title": "Likely access obtained using compromised credentials",
                "tactic": "Initial Access",
                "stage": "Initial Access",
                "technique": "T1078",
                "ts": curr.get("ts"),
                "src_ip": curr.get("src_ip"),
                "username": curr.get("username"),
                "host": curr.get("host"),
                "score": 0,
                "confidence": 0.68,
                "inferred": True,
                "notes": [
                    "Inferred from repeated failed logons followed by successful remote logon."
                ],
                "raw": {},
            })
        final_path.append(curr)

    return final_path


def summarize_path(path: List[Dict[str, Any]]) -> str:
    if not path:
        return "No meaningful attack path could be reconstructed."

    stages = [p.get("stage") for p in path if p.get("stage")]
    unique_stages = []
    for s in stages:
        if s not in unique_stages:
            unique_stages.append(s)

    if len(unique_stages) >= 3:
        return f"Likely progression observed across {' → '.join(unique_stages[:4])}."
    if len(unique_stages) == 2:
        return f"Likely activity progressed from {unique_stages[0]} to {unique_stages[1]}."
    return f"Likely malicious activity centered on {unique_stages[0]}." if unique_stages else "A probable attack sequence was reconstructed."


def reconstruct_case(case_header: Dict[str, Any], case_items: List[Dict[str, Any]]) -> AttackReconstruction:
    case_id = case_header.get("case_id", "CASE-UNKNOWN")

    candidates = build_candidates(case_items)
    edges = build_edges(candidates)
    path, rels = extract_path(candidates, edges)
    included_ids = {p["id"] for p in path}
    orphaned = [c for c in candidates if c["id"] not in included_ids]
    path = maybe_insert_inferred_steps(path)

    attack_steps: List[ReconstructionStep] = []
    relationships: List[ReconstructionEdge] = []

    for i, p in enumerate(path, start=1):
        raw = p.get("raw", {}) or {}
        evidence = [
            ReconstructionEvidence(
                kind="alert" if not p.get("inferred") else "inferred",
                ref=raw.get("alert_id", p.get("id", f"step-{i}")),
                timestamp=p.get("ts"),
                rule_id=p.get("rule_id"),
                summary=p.get("title"),
            )
        ]

        attack_steps.append(
            ReconstructionStep(
                step_no=i,
                stage=p.get("stage") or "Unknown",
                title=p.get("title") or "Unknown activity",
                technique=p.get("technique"),
                tactic=p.get("tactic"),
                timestamp=p.get("ts"),
                confidence=float(p.get("confidence", 0.5)),
                entities={
                    "src_ip": p.get("src_ip"),
                    "username": p.get("username"),
                    "host": p.get("host"),
                },
                evidence=evidence,
                notes=p.get("notes", []),
                inferred=bool(p.get("inferred", False)),
            )
        )

    for idx, rel in enumerate(rels, start=1):
        relationships.append(
            ReconstructionEdge(
                from_step=idx,
                to_step=idx + 1,
                reason=", ".join(rel.get("reasons", [])),
                weight=float(rel.get("weight", 0.0)),
            )
        )

    confidences = [s.confidence for s in attack_steps] or [0.0]
    overall_conf = round(sum(confidences) / len(confidences), 2)

    key_entities = {
        "src_ips": sorted({s.entities.get("src_ip") for s in attack_steps if s.entities.get("src_ip")}),
        "users": sorted({s.entities.get("username") for s in attack_steps if s.entities.get("username")}),
        "hosts": sorted({s.entities.get("host") for s in attack_steps if s.entities.get("host")}),
    }

    gaps = []
    if any(s.stage == "Persistence" for s in attack_steps) and not any(s.stage == "Execution" for s in attack_steps):
        gaps.append("Execution activity was not directly observed before persistence-related behavior.")
    if orphaned:
        orphan_desc = "; ".join(
            f"{c.get('rule_id')} at {c.get('ts')}" for c in sorted(orphaned, key=lambda c: c.get("ts") or "")
        )
        gaps.append(
            f"{len(orphaned)} additional alert(s) in this case were not connected to the primary "
            f"narrative and are not reflected in the attack path above: {orphan_desc}."
        )

    assumptions = []
    if any(s.inferred for s in attack_steps):
        assumptions.append("At least one step was inferred from surrounding evidence rather than directly observed.")

    return AttackReconstruction(
        case_id=case_id,
        summary=summarize_path(path),
        confidence=overall_conf,
        attack_path=attack_steps,
        relationships=relationships,
        key_entities=key_entities,
        gaps=gaps,
        assumptions=assumptions,
    )
