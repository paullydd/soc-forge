from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ReconstructionEvidence:
    kind: str  # alert, event, hunt, correlation, inferred
    ref: str
    timestamp: Optional[str] = None
    rule_id: Optional[str] = None
    event_id: Optional[int] = None
    summary: Optional[str] = None


@dataclass
class ReconstructionStep:
    step_no: int
    stage: str
    title: str
    technique: Optional[str]
    tactic: Optional[str]
    timestamp: Optional[str]
    confidence: float
    entities: Dict[str, Any] = field(default_factory=dict)
    evidence: List[ReconstructionEvidence] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    inferred: bool = False


@dataclass
class ReconstructionEdge:
    from_step: int
    to_step: int
    reason: str
    weight: float


@dataclass
class AttackReconstruction:
    case_id: str
    summary: str
    confidence: float
    attack_path: List[ReconstructionStep] = field(default_factory=list)
    relationships: List[ReconstructionEdge] = field(default_factory=list)
    key_entities: Dict[str, List[str]] = field(default_factory=dict)
    gaps: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
