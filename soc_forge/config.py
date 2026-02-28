from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


@dataclass(frozen=True)
class BruteforceConfig:
    threshold: int = 8
    window_minutes: int = 10
    severity: str = "high"
    score: int = 60


@dataclass(frozen=True)
class SimpleRuleConfig:
    severity: str
    score: int


@dataclass(frozen=True)
class CorrelationConfig:
    window_minutes: int = 15
    bruteforce_lockout_enabled: bool = True
    bruteforce_lockout_severity: str = "critical"
    bruteforce_lockout_score: int = 120


@dataclass(frozen=True)
class OutputConfig:
    alerts_json: str = "out/alerts.json"
    report_html: str = "out/report.html"


@dataclass(frozen=True)
class SocForgeConfig:
    output: OutputConfig = OutputConfig()
    bruteforce: BruteforceConfig = BruteforceConfig()
    account_lockout: SimpleRuleConfig = SimpleRuleConfig(severity="medium", score=40)
    new_admin: SimpleRuleConfig = SimpleRuleConfig(severity="high", score=90)
    correlation: CorrelationConfig = CorrelationConfig()


def _get(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def load_config(path: Optional[str]) -> SocForgeConfig:
    """
    Loads YAML config from `path`. If path is None or file missing, returns defaults.
    """
    if not path:
        return SocForgeConfig()

    p = Path(path)
    if not p.exists():
        # fall back to defaults (keeps UX smooth)
        return SocForgeConfig()

    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    # Output
    out = OutputConfig(
        alerts_json=str(_get(raw, "output.alerts_json", "out/alerts.json")),
        report_html=str(_get(raw, "output.report_html", "out/report.html")),
    )

    # Detections
    bf = BruteforceConfig(
        threshold=int(_get(raw, "detections.brute_force.threshold", 8)),
        window_minutes=int(_get(raw, "detections.brute_force.window_minutes", 10)),
        severity=str(_get(raw, "detections.brute_force.severity", "high")),
        score=int(_get(raw, "detections.brute_force.score", 60)),
    )

    lock = SimpleRuleConfig(
        severity=str(_get(raw, "detections.account_lockout.severity", "medium")),
        score=int(_get(raw, "detections.account_lockout.score", 40)),
    )

    admin = SimpleRuleConfig(
        severity=str(_get(raw, "detections.new_admin.severity", "high")),
        score=int(_get(raw, "detections.new_admin.score", 90)),
    )

    corr = CorrelationConfig(
        window_minutes=int(_get(raw, "correlation.window_minutes", 15)),
        bruteforce_lockout_enabled=bool(_get(raw, "correlation.rules.bruteforce_lockout.enabled", True)),
        bruteforce_lockout_severity=str(_get(raw, "correlation.rules.bruteforce_lockout.severity", "critical")),
        bruteforce_lockout_score=int(_get(raw, "correlation.rules.bruteforce_lockout.score", 120)),
    )

    return SocForgeConfig(
        output=out,
        bruteforce=bf,
        account_lockout=lock,
        new_admin=admin,
        correlation=corr,
    )
