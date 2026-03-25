from typing import Dict


HUNT_SCORE_MAP: Dict[str, int] = {
    "HUNT-001": 80,  # suspicious command
    "HUNT-002": 60,  # rare IP
    "HUNT-003": 75,  # lateral movement
    "HUNT-004": 50,  # failed login burst
}


SEVERITY_MAP = {
    "critical": 90,
    "high": 75,
    "medium": 50,
    "low": 25,
}


def score_hunt(finding: Dict) -> int:
    base = HUNT_SCORE_MAP.get(finding.get("hunt_id"), 50)
    return base


def score_alert(alert: Dict) -> int:
    return SEVERITY_MAP.get(alert.get("severity", "low"), 25)
