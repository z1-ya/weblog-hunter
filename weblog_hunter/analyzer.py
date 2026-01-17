"""
Analysis and scoring logic for weblog-hunter
"""

from collections import Counter, defaultdict
from typing import List, Dict, Optional

from weblog_hunter.models import LogEntry, IPAnalysis, EndpointVulnerability, AnalysisResult
from weblog_hunter.signatures import (
    IDENTITY_HINTS,
    LOGIN_HINTS,
    EMAIL_HINTS,
)


class ThreatAnalyzer:
    """Analyzes log entries for threats and suspicious behavior"""
    
    def __init__(self, min_requests: int = 50):
        """
        Initialize analyzer
        
        Args:
            min_requests: Minimum requests for an IP to be scored
        """
        self.min_requests = min_requests
    
    def analyze(self, entries: List[LogEntry], top_n: int = 10) -> AnalysisResult:
        """
        Perform complete analysis on log entries
        
        Args:
            entries: List of parsed log entries
            top_n: Number of top suspicious IPs to return
            
        Returns:
            AnalysisResult with all analysis data
        """
        # Group by IP
        by_ip = defaultdict(list)
        for entry in entries:
            by_ip[entry.ip].append(entry)
        
        # Score IPs
        ip_analyses = self._score_ips(by_ip)
        
        # Get top suspicious IPs
        top_ips = ip_analyses[:top_n]
        
        # Find tools by first appearance
        tools_first_seen = self._find_tools_first_seen(entries)
        
        # Rank vulnerable endpoints
        vulnerable_endpoints = self._rank_vulnerable_endpoints(entries)
        
        # Infer email scraping section
        scrape_section = self._infer_scrape_section(by_ip, [ip.ip for ip in top_ips])
        
        return AnalysisResult(
            files_read=0,  # Set by caller
            parsed_events=len(entries),
            parse_failures=0,  # Set by caller
            top_suspicious_ips=top_ips,
            tools_first_seen=tools_first_seen,
            vulnerable_endpoints=vulnerable_endpoints,
            inferred_scrape_section=scrape_section,
            all_events=entries,
        )
    
    def _score_ips(self, by_ip: Dict[str, List[LogEntry]]) -> List[IPAnalysis]:
        """Score all IPs and return sorted list"""
        scored_ips = []
        
        for ip, events in by_ip.items():
            if len(events) < self.min_requests:
                continue
            
            analysis = self._analyze_ip(ip, events)
            scored_ips.append(analysis)
        
        # Sort by score descending
        scored_ips.sort(key=lambda x: x.score, reverse=True)
        return scored_ips
    
    def _analyze_ip(self, ip: str, events: List[LogEntry]) -> IPAnalysis:
        """Analyze a single IP's behavior"""
        n = len(events)
        
        # Count status codes
        status_codes = dict(Counter(e.status for e in events))
        s4xx = sum(v for k, v in status_codes.items() if 400 <= k <= 499)
        s5xx = sum(v for k, v in status_codes.items() if 500 <= k <= 599)
        
        # Count abnormal requests
        abnormal_count = sum(1 for e in events if e.abnormal)
        
        # Count login attempts
        login_attempts = sum(1 for e in events if LOGIN_HINTS.search(e.path))
        
        # Count identity queries
        identity_queries = sum(1 for e in events if IDENTITY_HINTS.search(e.path))
        
        # Calculate max requests per minute (burst detection)
        per_minute = Counter()
        for e in events:
            if e.timestamp:
                key = e.timestamp.strftime("%Y-%m-%d %H:%M")
                per_minute[key] += 1
        max_rpm = max(per_minute.values()) if per_minute else 0
        
        # Calculate score
        score = (
            0.002 * n +           # Volume
            0.02 * s5xx +         # Server errors
            0.01 * s4xx +         # Client errors
            0.05 * abnormal_count +  # Attack signatures
            0.03 * login_attempts +  # Login probing
            0.02 * identity_queries +  # Identity queries
            0.01 * max_rpm        # Burst activity
        )
        
        # Get top paths
        path_counter = Counter(e.path for e in events)
        top_paths = path_counter.most_common(10)
        
        # Get abnormal examples
        abnormal_examples = [e for e in events if e.abnormal][:8]
        
        # Get tools used
        tools = list(set(e.tool for e in events if e.tool))
        
        return IPAnalysis(
            ip=ip,
            request_count=n,
            score=score,
            status_codes=status_codes,
            abnormal_count=abnormal_count,
            login_attempts=login_attempts,
            identity_queries=identity_queries,
            max_requests_per_minute=max_rpm,
            top_paths=top_paths,
            abnormal_examples=abnormal_examples,
            tools_used=tools,
        )
    
    def _find_tools_first_seen(self, entries: List[LogEntry]) -> List[tuple]:
        """Find when each tool was first seen in logs"""
        tool_first_seen = {}
        
        for entry in entries:
            if not entry.tool or not entry.timestamp:
                continue
            
            tool = entry.tool
            if tool not in tool_first_seen or entry.timestamp < tool_first_seen[tool]:
                tool_first_seen[tool] = entry.timestamp
        
        # Sort by timestamp
        return sorted(tool_first_seen.items(), key=lambda x: x[1])
    
    def _rank_vulnerable_endpoints(self, entries: List[LogEntry]) -> List[EndpointVulnerability]:
        """Rank endpoints by vulnerability (SQLi focus)"""
        endpoint_stats = {}
        
        for entry in entries:
            if "SQLi" not in entry.abnormal:
                continue
            
            path = entry.path
            if path not in endpoint_stats:
                endpoint_stats[path] = {
                    "sqli_hits": 0,
                    "sqli_500": 0,
                    "payloads": set(),
                    "examples": [],
                }
            
            stats = endpoint_stats[path]
            stats["sqli_hits"] += 1
            
            if 500 <= entry.status <= 599:
                stats["sqli_500"] += 1
            
            # Track unique payloads
            stats["payloads"].add(entry.url[:200])
            
            # Keep examples
            if len(stats["examples"]) < 5:
                stats["examples"].append(entry.url)
        
        # Convert to EndpointVulnerability objects and score
        vulnerabilities = []
        for endpoint, stats in endpoint_stats.items():
            score = (
                3 * stats["sqli_hits"] +
                2 * stats["sqli_500"] +
                len(stats["payloads"])
            )
            
            vulnerabilities.append(EndpointVulnerability(
                endpoint=endpoint,
                score=score,
                sqli_hits=stats["sqli_hits"],
                sqli_500=stats["sqli_500"],
                unique_payloads=len(stats["payloads"]),
                examples=stats["examples"],
            ))
        
        # Sort by score descending
        vulnerabilities.sort(key=lambda x: x.score, reverse=True)
        return vulnerabilities
    
    def _infer_scrape_section(self, by_ip: Dict[str, List[LogEntry]], top_ips: List[str]) -> Optional[str]:
        """Infer which section is being used for email/data scraping"""
        scrape_candidates = defaultdict(lambda: {
            "hits": 0,
            "ok": 0,
            "bytes": [],
            "paths": Counter()
        })
        
        for ip in top_ips:
            if ip not in by_ip:
                continue
            
            events = by_ip[ip]
            for entry in events:
                if IDENTITY_HINTS.search(entry.path):
                    sc = scrape_candidates[ip]
                    sc["hits"] += 1
                    sc["paths"][entry.path] += 1
                    
                    if 200 <= entry.status <= 299:
                        sc["ok"] += 1
                    
                    sc["bytes"].append(entry.bytes)
        
        # Find best candidate section
        inferred_section = None
        best_metric = None
        
        for ip, sc in scrape_candidates.items():
            if sc["hits"] == 0:
                continue
            
            # Get most-hit path for this IP
            path, count = sc["paths"].most_common(1)[0]
            
            # Calculate metric (hits, successful requests, avg bytes)
            avg_bytes = sum(sc["bytes"]) / max(1, len(sc["bytes"]))
            metric = (sc["hits"], sc["ok"], avg_bytes)
            
            if best_metric is None or metric > best_metric:
                best_metric = metric
                inferred_section = path
        
        return inferred_section
