from abc import ABC, abstractmethod
from app.models.analysis_result import Alarm


class BaseAnalyzer(ABC):
    """Base class for all analyzers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this analyzer."""

    @abstractmethod
    def analyze(self, parsed_data: dict, language: str = "en") -> list[Alarm]:
        """Run analysis and return a list of alarms."""
