"""
Data models for weblog-hunter with type hints
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Counter as CounterType


@dataclass
class LogEntry:
    """Represents a single parsed log entry"""
    
    ip: str
    timestamp: Optional[datetime]
    method: str
    url: str
    path: str
    query: str
    status: int
    bytes: int
    user_agent: str
    referer: Optional[str] = None
    tool: Optional[str] = None
    abnormal: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "ip": self.ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "query": self.query,
            "status": self.status,
            "bytes": self.bytes,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "tool": self.tool,
            "abnormal": self.abnormal,
        }


@dataclass
class IPAnalysis:
    """Analysis results for a single IP address"""
    
    ip: str
    request_count: int
    score: float
    status_codes: Dict[int, int]
    abnormal_count: int
    login_attempts: int
    identity_queries: int
    max_requests_per_minute: int
    top_paths: List[tuple]
    abnormal_examples: List[LogEntry]
    tools_used: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "ip": self.ip,
            "request_count": self.request_count,
            "score": self.score,
            "status_codes": self.status_codes,
            "abnormal_count": self.abnormal_count,
            "login_attempts": self.login_attempts,
            "identity_queries": self.identity_queries,
            "max_requests_per_minute": self.max_requests_per_minute,
            "top_paths": self.top_paths,
            "abnormal_examples": [e.to_dict() for e in self.abnormal_examples],
            "tools_used": self.tools_used,
        }


@dataclass
class EndpointVulnerability:
    """Represents a potentially vulnerable endpoint"""
    
    endpoint: str
    score: float
    sqli_hits: int
    sqli_500: int
    unique_payloads: int
    examples: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "endpoint": self.endpoint,
            "score": self.score,
            "sqli_hits": self.sqli_hits,
            "sqli_500": self.sqli_500,
            "unique_payloads": self.unique_payloads,
            "examples": self.examples,
        }


@dataclass
class AnalysisResult:
    """Complete analysis results"""
    
    files_read: int
    parsed_events: int
    parse_failures: int
    top_suspicious_ips: List[IPAnalysis]
    tools_first_seen: List[tuple]
    vulnerable_endpoints: List[EndpointVulnerability]
    inferred_scrape_section: Optional[str]
    all_events: List[LogEntry] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "summary": {
                "files_read": self.files_read,
                "parsed_events": self.parsed_events,
                "parse_failures": self.parse_failures,
                "top_suspicious_ips": [ip.ip for ip in self.top_suspicious_ips],
                "tools_by_first_seen": [
                    (name, ts.isoformat()) for name, ts in self.tools_first_seen
                ],
                "top_sqli_endpoints": [ep.endpoint for ep in self.vulnerable_endpoints[:10]],
                "inferred_scrape_section": self.inferred_scrape_section,
            },
            "top_ips_detail": [ip.to_dict() for ip in self.top_suspicious_ips],
            "vulnerable_endpoints": [ep.to_dict() for ep in self.vulnerable_endpoints],
            "events": [e.to_dict() for e in self.all_events[:20000]],  # cap for size
        }
