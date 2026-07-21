"""
SOC-Forge Entity Analyst

Provides analyst reasoning for individual entities.
"""


def analyze_entity(profile):
    reasoning = []
    recommendations = []

    confidence = 50

    risk = profile.get("risk_score", 0)
    entity_type = profile.get("type", "unknown")

    alerts = profile.get("alerts", [])
    relationships = profile.get("relationships", [])
    techniques = profile.get("techniques", [])

    if risk >= 75:
        reasoning.append("Entity has a high calculated risk score.")
        confidence += 15

    if len(alerts) >= 3:
        reasoning.append("Entity is associated with multiple security alerts.")
        confidence += 10

    if len(relationships) >= 2:
        reasoning.append("Entity has multiple relationships within the investigation.")
        confidence += 10

    if techniques:
        reasoning.append("MITRE ATT&CK techniques were observed.")
        confidence += 10

    #
    # Recommendations
    #

    if entity_type == "user":
        recommendations.extend([
            "Review successful logons.",
            "Check privilege escalation.",
            "Verify account status."
        ])

    elif entity_type == "ip":
        recommendations.extend([
            "Review firewall logs.",
            "Search historical activity.",
            "Identify additional targeted hosts."
        ])

    elif entity_type == "host":
        recommendations.extend([
            "Review persistence mechanisms.",
            "Inspect scheduled tasks.",
            "Review running services."
        ])

    elif entity_type == "service":
        recommendations.extend([
            "Verify service legitimacy.",
            "Review service creation events."
        ])

    else:
        recommendations.append(
            "Continue investigating related entities."
        )

    confidence = min(confidence, 99)

    return {
        "confidence": confidence,
        "reasoning": reasoning,
        "recommendations": recommendations,
    }