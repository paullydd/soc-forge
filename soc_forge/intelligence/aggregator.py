from typing import Dict, List

from .scoring import score_alert, score_hunt


def build_risk_summary(
    alerts: List[Dict],
    hunts: List[Dict],
    correlations: Dict | None = None,
) -> Dict:

    alert_scores = [score_alert(a) for a in alerts]
    hunt_scores = [score_hunt(h) for h in hunts]

    corr_bonus = 0
    if correlations and correlations.get("total", 0) > 0:
        corr_bonus = min(20, correlations["total"] * 5)

    total_score = sum(alert_scores) + sum(hunt_scores) + corr_bonus

    # normalize (simple version)
    max_possible = (len(alert_scores) * 75) + (len(hunt_scores) * 80) + 20
    if max_possible == 0:
        overall = 0
    else:
        overall = int((total_score / max_possible) * 100)

    return {
        "overall_score": overall,
        "level": risk_level(overall),
        "alerts": len(alerts),
        "hunts": len(hunts),
        "correlations": correlations.get("total", 0) if correlations else 0,
    }


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
