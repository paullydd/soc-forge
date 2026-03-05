from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass
class Alert:
    rule_id: str
    severity: str
    title: str
    timestamp: str
    details: dict
    mitre: list
    score: int = 0
    status: str = "new"
    correlation_id: Optional[str] = None
