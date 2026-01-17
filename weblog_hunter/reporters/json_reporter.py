"""
JSON report generator
"""

import json

from weblog_hunter.models import AnalysisResult
from weblog_hunter.reporters import BaseReporter


class JSONReporter(BaseReporter):
    """Generates JSON reports"""
    
    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate a JSON report
        
        Args:
            result: Analysis results
            output_path: Path to write JSON file
        """
        self.ensure_directory(output_path)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
