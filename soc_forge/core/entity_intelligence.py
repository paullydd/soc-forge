from typing import Any, Dict, List

from soc_forge.investigations.replay import describe_timeline_event


def get_entity_relationships(graph, entity_id):
    edges = graph.get("edges", [])
    relationships = []

    for edge in edges:
        if edge.get("source") == entity_id:
            relationships.append(
                {
                    "direction": "outbound",
                    "related_entity": edge.get("target"),
                    "relationship": edge.get("relationship"),
                    "evidence": edge.get("evidence"),
                }
            )

        elif edge.get("target") == entity_id:
            relationships.append(
                {
                    "direction": "inbound",
                    "related_entity": edge.get("source"),
                    "relationship": edge.get("relationship"),
                    "evidence": edge.get("evidence"),
                }
            )

    return relationships


def _event_mentions_entity(item: Dict[str, Any], entity_id: str) -> bool:
    needle = str(entity_id).lower()
    if not needle:
        return False

    searchable_parts = [describe_timeline_event(item)]
    for key in ("timestamp", "rule_id", "severity"):
        if item.get(key):
            searchable_parts.append(str(item[key]))

    return needle in " ".join(searchable_parts).lower()


def _alert_mentions_entity(alert: Dict[str, Any], entity_id: str) -> bool:
    needle = str(entity_id).lower()
    if not needle:
        return False
    return needle in str(alert).lower()


def get_entity_timeline(case, entity_id):
    timeline = case.get("timeline", []) if isinstance(case, dict) else []
    matches = [item for item in timeline if isinstance(item, dict) and _event_mentions_entity(item, entity_id)]
    return matches or timeline[:5]


def get_entity_alerts(case, entity_id=None):
    if not isinstance(case, dict):
        return []

    alerts = case.get("alerts", []) or case.get("items", []) or []
    if not entity_id:
        return alerts

    matched = [alert for alert in alerts if isinstance(alert, dict) and _alert_mentions_entity(alert, entity_id)]
    return matched or alerts[:5]


def calculate_entity_risk(node):
    risk = node.get("risk", 0)

    if risk >= 75:
        return "HIGH"

    if risk >= 40:
        return "MEDIUM"

    return "LOW"


def build_entity_profile(graph, case, entity_id):
    nodes = graph.get("nodes", {})
    node = nodes.get(entity_id)

    if not node:
        return None

    relationships = get_entity_relationships(graph, entity_id)

    return {
        "id": entity_id,
        "type": node.get("type", "unknown"),
        "risk_score": node.get("risk", 0),
        "risk_level": calculate_entity_risk(node),
        "events": node.get("events", 0),
        "techniques": node.get("techniques", []),
        "alerts": get_entity_alerts(case, entity_id),
        "relationships": relationships,
        "timeline": get_entity_timeline(case, entity_id),
        "case_title": case.get("title", "Unknown Case") if isinstance(case, dict) else "Unknown Case",
    }
