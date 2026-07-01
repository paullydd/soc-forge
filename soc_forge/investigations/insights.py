from typing import Dict, List

from soc_forge.ui.panels import section
from soc_forge.ui.colors import Colors


def build_insights(case: Dict) -> List[str]:
    insights = []

    status = case.get("status", "New")
    notes = case.get("notes", [])
    alerts = case.get("alerts", [])
    timeline = case.get("timeline", [])

    entities = (
        case.get("entities")
        or case.get("iocs")
        or case.get("indicators")
        or []
    )

    if status == "Open":
        insights.append("⚠ Investigation has not been started.")

    if not notes:
        insights.append("⚠ No analyst notes have been added.")

    if len(alerts) >= 3:
        insights.append("✓ Multiple related alerts detected.")

    if timeline:
        insights.append("✓ Timeline available.")

    if len(entities) >= 5:
        insights.append("✓ Multiple related entities discovered.")

    return insights


def show_insights(case: Dict) -> None:
    section("INVESTIGATION INSIGHTS")

    insights = build_insights(case)

    if not insights:
        print(f"{Colors.GREEN}✓ No outstanding investigation issues.{Colors.RESET}")
        return

    for insight in insights:
        print(insight)

def build_recommendations(case: Dict) -> List[str]:
    recommendations = []

    if case.get("timeline"):
        recommendations.append("Review the attack timeline.")

    recommendations.append("Inspect related entities.")

    if not case.get("notes"):
        recommendations.append("Add analyst notes.")

    recommendations.append("Export the investigation.")

    return recommendations


def show_recommendations(case: Dict) -> None:
    section("RECOMMENDED ACTIONS")

    for index, action in enumerate(build_recommendations(case), start=1):
        print(f"{index}. {action}")