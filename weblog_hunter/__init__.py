"""
weblog-hunter: Automated web log reconnaissance and threat hunting tool
"""

__version__ = "2.0.0"
__author__ = "Ziya Shalbuzov"

from weblog_hunter.models import LogEntry, IPAnalysis, AnalysisResult

__all__ = ["LogEntry", "IPAnalysis", "AnalysisResult", "__version__", "__author__"]
