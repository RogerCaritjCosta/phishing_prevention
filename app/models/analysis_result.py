from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORES = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 10,
    Severity.CRITICAL: 20,
}


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alarm:
    analyzer: str
    alarm_type: str
    severity: Severity
    title: str
    description: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "analyzer": self.analyzer,
            "alarm_type": self.alarm_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "details": self.details,
        }

    def score(self) -> int:
        return SEVERITY_SCORES[self.severity]


_SEVERITY_TO_RISK = {
    Severity.INFO: RiskLevel.LOW,
    Severity.LOW: RiskLevel.LOW,
    Severity.MEDIUM: RiskLevel.MEDIUM,
    Severity.HIGH: RiskLevel.HIGH,
    Severity.CRITICAL: RiskLevel.CRITICAL,
}

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


def compute_risk_level(alarms: list[Alarm]) -> RiskLevel:
    if not alarms:
        return RiskLevel.LOW

    total = sum(a.score() for a in alarms)
    max_severity = max((a.severity for a in alarms), key=lambda s: SEVERITY_SCORES[s])

    # Score-based risk
    if total >= 30:
        score_risk = RiskLevel.CRITICAL
    elif total >= 15:
        score_risk = RiskLevel.HIGH
    elif total >= 5:
        score_risk = RiskLevel.MEDIUM
    else:
        score_risk = RiskLevel.LOW

    # Cap: risk level cannot exceed the max individual alarm severity
    severity_cap = _SEVERITY_TO_RISK[max_severity]
    if _RISK_ORDER.index(score_risk) > _RISK_ORDER.index(severity_cap):
        return severity_cap

    return score_risk


RISK_LEVEL_LABELS = {
    "en": {RiskLevel.LOW: "Low", RiskLevel.MEDIUM: "Medium", RiskLevel.HIGH: "High", RiskLevel.CRITICAL: "Critical"},
    "es": {RiskLevel.LOW: "Bajo", RiskLevel.MEDIUM: "Medio", RiskLevel.HIGH: "Alto", RiskLevel.CRITICAL: "Crítico"},
    "ca": {RiskLevel.LOW: "Baix", RiskLevel.MEDIUM: "Mitjà", RiskLevel.HIGH: "Alt", RiskLevel.CRITICAL: "Crític"},
}
