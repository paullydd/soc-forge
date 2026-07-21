from typing import Any, Dict, List


def count_indicators(case: Dict[str, Any]) -> int:
    indicators = case.get("indicators", case.get("iocs", {}))

    if isinstance(indicators, dict):
        total = 0
        for values in indicators.values():
            if isinstance(values, list):
                total += len(values)
            elif values:
                total += 1
        return total

    if isinstance(indicators, list):
        return len(indicators)

    return 0


def build_analyst_summary(case: Dict[str, Any]) -> str:
    risk = int(case.get("risk_score", case.get("risk", 0)))
    title = case.get("title", case.get("name", "Untitled Case"))
    alert_count = len(case.get("alerts", []))
    entity_count = count_indicators(case)
    timeline_count = len(case.get("timeline", []))

    if risk >= 300:
        severity = "critical"
    elif risk >= 200:
        severity = "high"
    elif risk >= 100:
        severity = "medium"
    else:
        severity = "low"

    return (
        f"SOC-Forge Analyst assesses '{title}' as a {severity}-severity investigation. "
        f"The case contains {alert_count} alert(s), {entity_count} related entit(ies), "
        f"and {timeline_count} timeline event(s)."
    )


def build_analyst_findings(case: Dict[str, Any]) -> List[str]:
    findings = []

    status = case.get("status", "New")
    alerts = case.get("alerts", [])
    notes = case.get("notes", [])
    timeline = case.get("timeline", [])
    entity_count = count_indicators(case)

    if len(alerts) >= 3:
        findings.append("Multiple related alerts suggest correlated activity rather than an isolated event.")

    if entity_count >= 5:
        findings.append("Multiple related entities were identified across the investigation.")

    if timeline:
        findings.append("A timeline is available and should be reviewed to understand event sequence.")

    if not notes:
        findings.append("No analyst notes are currently recorded for this case.")

    if status in ["New", "Open"]:
        findings.append("The case has not yet moved into an active investigation status.")

    return findings


def build_analyst_recommendations(case: Dict[str, Any]) -> List[Dict[str, str]]:
    recommendations = []

    if case.get("timeline"):
        recommendations.append(
            {
                "action": "Review the investigation replay or timeline.",
                "reason": "Timeline events are available and can show how the activity unfolded.",
            }
        )

    if count_indicators(case) > 0:
        recommendations.append(
            {
                "action": "Open Entity Explorer.",
                "reason": "Related users, hosts, IPs, services, or tasks were identified.",
            }
        )

    if not case.get("notes"):
        recommendations.append(
            {
                "action": "Add analyst notes.",
                "reason": "No investigation notes have been recorded yet.",
            }
        )

    recommendations.append(
        {
            "action": "Export the investigation bundle.",
            "reason": "The bundle preserves timeline, indicators, notes, graph, and narrative evidence.",
        }
    )

    return recommendations


def calculate_confidence(case: Dict[str, Any]) -> int:
    score = 0

    if case.get("alerts"):
        score += 25

    if case.get("timeline"):
        score += 25

    if count_indicators(case) > 0:
        score += 25

    if case.get("story") or case.get("analyst_summary"):
        score += 15

    if case.get("notes"):
        score += 10

    return min(score, 100)

def calculate_investigation_score(case: Dict[str, Any]) -> int:
    score = 0

    if case.get("alerts"):
        score += 15

    if case.get("timeline"):
        score += 20

    if count_indicators(case) > 0:
        score += 20

    if case.get("story") or case.get("analyst_summary"):
        score += 15

    if case.get("attack_graph") or case.get("graph"):
        score += 10

    if case.get("notes"):
        score += 10

    if case.get("status") in ["Contained", "Closed"]:
        score += 10

    return min(score, 100)