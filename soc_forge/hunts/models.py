from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class HuntFinding:
    hunt_id: str
    title: str
    severity: str
    category: str
    summary: str
    confidence: str
    entities: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    mitre: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "summary": self.summary,
            "confidence": self.confidence,
            "entities": self.entities,
            "evidence": self.evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "mitre": self.mitre,
        }