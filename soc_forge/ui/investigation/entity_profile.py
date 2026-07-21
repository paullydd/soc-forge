from soc_forge.ui.panels import section, status_card, warning, divider
from soc_forge.core.entity_analyst import analyze_entity
from soc_forge.investigations.replay import describe_timeline_event


def _alert_summary(alert):
    if isinstance(alert, dict):
        rule_id = alert.get("rule_id", "N/A")
        title = alert.get("title", "Unknown alert")
        timestamp = alert.get("timestamp", "")
        return " | ".join(str(part) for part in [timestamp, rule_id, title] if part)
    return str(alert)


def entity_profile_panel(profile):
    if not profile:
        warning("Entity profile not found.")
        return []

    section("Entity Profile")

    status_card(
        profile["id"],
        [
            ("Type", profile.get("type", "unknown")),
            ("Risk", profile.get("risk_level", "LOW")),
            ("Risk Score", profile.get("risk_score", 0)),
            ("Events", profile.get("events", 0)),
            ("Observed In", profile.get("case_title", "Unknown Case")),
        ],
    )

    analysis = analyze_entity(profile)

    divider()

    section("SOC-Forge Analyst")

    print(f"Confidence: {analysis['confidence']}%")

    divider()

    section("Reasoning")

    if analysis["reasoning"]:
        for item in analysis["reasoning"]:
            print(f"- {item}")
    else:
        print("No high-confidence reasoning signals yet.")

    divider()

    section("Recommended Next Steps")

    for i, item in enumerate(analysis["recommendations"], start=1):
        print(f"{i}. {item}")

    alerts = profile.get("alerts", [])
    if alerts:
        section("Evidence")
        for alert in alerts:
            print(f"- {_alert_summary(alert)}")

    techniques = profile.get("techniques", [])
    if techniques:
        section("Observed Techniques")
        for technique in techniques:
            print(f"- {technique}")

    relationships = profile.get("relationships", [])
    related_entities = []

    divider()
    section("Connected Entities")

    if not relationships:
        warning("No connected entities found.")
    else:
        for index, relationship in enumerate(relationships, start=1):
            related = relationship.get("related_entity")
            related_entities.append(related)

            direction = relationship.get("direction")
            relation = relationship.get("relationship")

            print(f"{index}. {related}")
            print(f"   Relationship: {relation}")
            print(f"   Direction: {direction}")

            evidence = relationship.get("evidence")
            if evidence:
                print(f"   Evidence: {evidence}")

            print()

    timeline = profile.get("timeline", [])
    if timeline:
        divider()
        section("Timeline")
        for item in timeline:
            if isinstance(item, dict):
                print(f"{item.get('timestamp', 'Unknown')} | {describe_timeline_event(item)}")
            else:
                print(item)

    return related_entities
