from app.analyzers.base import BaseAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.content_analyzer import ContentAnalyzer
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.external_api import ExternalAPIAnalyzer
from app.models.analysis_result import (
    Alarm, compute_risk_level, RISK_LEVEL_LABELS, RiskLevel
)

_ANALYZERS: list[BaseAnalyzer] = [
    URLAnalyzer(),
    ContentAnalyzer(),
    HeaderAnalyzer(),
    ExternalAPIAnalyzer(),
]


def run_analysis(parsed_data: dict, language: str = "en") -> dict:
    all_alarms: list[Alarm] = []
    analyzers_run: list[str] = []

    for analyzer in _ANALYZERS:
        try:
            alarms = analyzer.analyze(parsed_data, language)
            all_alarms.extend(alarms)
            analyzers_run.append(analyzer.name)
        except Exception:
            pass

    risk_level = compute_risk_level(all_alarms)
    labels = RISK_LEVEL_LABELS.get(language, RISK_LEVEL_LABELS["en"])

    return {
        "success": True,
        "risk_level": risk_level.value,
        "risk_level_label": labels[risk_level],
        "alarms": [a.to_dict() for a in all_alarms],
        "metadata": {
            "analyzers_run": analyzers_run,
        },
    }
