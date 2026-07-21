from collections import defaultdict
import re
from typing import Any, Dict, Iterable, List


def _safe(value):
    if value is None or value == "":
        return "unknown"
    return str(value)


def _is_known(value):
    return value is not None and str(value).strip().lower() not in {"", "unknown", "none", "n/a"}


def _extract_ips_from_text(text):
    if not text:
        return []
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple) or isinstance(value, set):
        return list(value)
    return [value]


def _values_from(indicators: Dict[str, Any], *keys: str) -> List[Any]:
    values: List[Any] = []
    for key in keys:
        for value in _as_list(indicators.get(key)):
            if value not in values:
                values.append(value)
    return values


def _alert_label(alert: Any) -> str:
    if isinstance(alert, dict):
        rule_id = alert.get("rule_id", "")
        title = alert.get("title", "Alert")
        timestamp = alert.get("timestamp", "")
        return " ".join(str(part) for part in [rule_id, title, timestamp] if part)
    return str(alert)


def _mitre_labels(case: Dict[str, Any], alerts: Iterable[Any]) -> List[str]:
    labels: List[str] = []

    for item in _as_list(case.get("mitre")):
        labels.append(str(item))

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        for item in _as_list(alert.get("mitre")):
            if isinstance(item, dict):
                tactic = item.get("tactic")
                technique = item.get("technique") or item.get("technique_id") or item.get("id")
                label = " - ".join(str(part) for part in [tactic, technique] if part)
                if label:
                    labels.append(label)
            elif item:
                labels.append(str(item))

    seen = set()
    out = []
    for label in labels:
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _add_node(nodes, entity_id, entity_type):
    entity_id = _safe(entity_id)

    if entity_id not in nodes:
        nodes[entity_id] = {
            "id": entity_id,
            "type": entity_type,
            "events": 0,
            "risk": 0,
            "techniques": set(),
        }

    nodes[entity_id]["events"] += 1
    return entity_id


def _relationship_metadata(relationship):
    labels = {
        "targeted": (90, "critical"),
        "authenticated_to": (85, "high"),
        "scheduled_task_observed": (80, "high"),
        "service_observed": (70, "medium"),
        "member_of_or_modified": (85, "high"),
        "group_change_observed": (75, "medium"),
    }
    confidence, severity = labels.get(relationship, (60, "medium"))
    return confidence, severity


def _add_edge(edges, source, target, relationship, evidence=None):
    if not source or not target:
        return

    confidence, severity = _relationship_metadata(relationship)
    edge = {
        "source": _safe(source),
        "target": _safe(target),
        "relationship": relationship,
        "evidence": evidence,
        "confidence": confidence,
        "severity": severity,
    }

    if edge not in edges:
        edges.append(edge)


def _primary_path(*groups):
    path = []
    for group in groups:
        if group:
            candidate = _safe(group[0])
            if candidate not in path:
                path.append(candidate)
    return path


def build_investigation_graph(case):
    """
    Build an analyst-focused investigation graph from a SOC-Forge case.

    Supports both the older console indicator shape:
      {"IP Addresses": [...], "Users": [...], "Hosts": [...]}
    and the generated report shape:
      {"ips": [...], "users": [...], "hosts": [...]}
    """
    if not isinstance(case, dict):
        return {"nodes": {}, "edges": [], "timeline_count": 0, "alert_count": 0}

    nodes = {}
    edges = []

    indicators = case.get("indicators") or case.get("iocs") or {}
    if not isinstance(indicators, dict):
        indicators = {}

    alerts = case.get("alerts") or case.get("items") or []
    timeline = case.get("timeline") or []
    mitre = _mitre_labels(case, alerts)

    ips = _values_from(indicators, "IP Addresses", "ips", "ip", "src_ips", "src_ip")
    users = _values_from(indicators, "Users", "users", "user", "accounts", "account")
    hosts = _values_from(indicators, "Hosts", "hosts", "host", "computers", "computer")
    services = _values_from(indicators, "Services", "services", "service")
    tasks = _values_from(indicators, "Scheduled Tasks", "scheduled_tasks", "tasks", "task")
    groups = _values_from(indicators, "Groups", "groups", "group", "group_names")

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        details = alert.get("details", {}) or {}
        event = alert.get("event", {}) or {}
        for value in [alert.get("ip"), details.get("ip"), details.get("src_ip"), event.get("ip"), event.get("src_ip")]:
            if _is_known(value) and value not in ips:
                ips.append(value)
        for value in [
            alert.get("username"),
            alert.get("actor"),
            alert.get("target_user"),
            details.get("username"),
            details.get("actor"),
            details.get("target_user"),
            event.get("username"),
            event.get("actor"),
            event.get("target_user"),
        ]:
            if _is_known(value) and value not in users:
                users.append(value)
        for value in [alert.get("host"), details.get("host"), event.get("host"), event.get("computer")]:
            if _is_known(value) and value not in hosts:
                hosts.append(value)
        for value in _extract_ips_from_text(details.get("message") or event.get("message")):
            if value not in ips:
                ips.append(value)
        for value in [details.get("task_name"), event.get("task_name")]:
            if _is_known(value) and value not in tasks:
                tasks.append(value)
        for value in [details.get("group_name"), event.get("group_name")]:
            if _is_known(value) and value not in groups:
                groups.append(value)

    ips = [ip for ip in ips if _is_known(ip)]
    users = [user for user in users if _is_known(user)]
    hosts = [host for host in hosts if _is_known(host)]
    services = [service for service in services if _is_known(service)]
    tasks = [task for task in tasks if _is_known(task)]
    groups = [group for group in groups if _is_known(group)]

    for ip in ips:
        _add_node(nodes, ip, "ip")
    for user in users:
        _add_node(nodes, user, "user")
    for host in hosts:
        _add_node(nodes, host, "host")
    for service in services:
        _add_node(nodes, service, "service")
    for task in tasks:
        _add_node(nodes, task, "scheduled_task")
    for group in groups:
        _add_node(nodes, group, "group")

    evidence = ", ".join(_alert_label(alert) for alert in alerts) if alerts else "Case indicators"

    for ip in ips:
        for user in users:
            _add_edge(edges, ip, user, "targeted", evidence)

    for user in users:
        for host in hosts:
            _add_edge(edges, user, host, "authenticated_to", evidence)

    for host in hosts:
        for service in services:
            _add_edge(edges, host, service, "service_observed", evidence)

    for host in hosts:
        for task in tasks:
            _add_edge(edges, host, task, "scheduled_task_observed", evidence)

    for user in users:
        for group in groups:
            _add_edge(edges, user, group, "member_of_or_modified", evidence)

    for host in hosts:
        for group in groups:
            _add_edge(edges, host, group, "group_change_observed", evidence)

    for node in nodes.values():
        node["techniques"] = sorted(mitre)
        node["risk"] = min(
            100,
            len(alerts) * 15 + len(node["techniques"]) * 10 + node["events"] * 5,
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "primary_path": _primary_path(ips, users, hosts, tasks or services, groups),
        "timeline_count": len(timeline),
        "alert_count": len(alerts),
    }


def get_entity_neighbors(graph, entity_id):
    entity_id = _safe(entity_id)

    related = []

    for edge in graph.get("edges", []):
        if edge["source"] == entity_id:
            related.append(edge["target"])
        elif edge["target"] == entity_id:
            related.append(edge["source"])

    return sorted(set(related))


def summarize_graph(graph):
    nodes = graph.get("nodes", {})
    edges = graph.get("edges", [])

    by_type = defaultdict(int)

    for node in nodes.values():
        by_type[node["type"]] += 1

    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "entity_types": dict(by_type),
    }
