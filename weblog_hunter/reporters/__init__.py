"""
Reporter base classes and utilities
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from weblog_hunter.models import AnalysisResult


class BaseReporter(ABC):
    """Abstract base class for report generators"""
    
    @abstractmethod
    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate a report from analysis results
        
        Args:
            result: Analysis results
            output_path: Path to write report to
        """
        pass
    
    def ensure_directory(self, filepath: str) -> None:
        """Ensure the directory for a file exists"""
        directory = Path(filepath).parent
        if directory and str(directory) != ".":
            directory.mkdir(parents=True, exist_ok=True)
