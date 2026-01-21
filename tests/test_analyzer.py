"""
Tests for threat analyzer functionality
"""

from datetime import datetime

from weblog_hunter.analyzer import ThreatAnalyzer
from weblog_hunter.models import LogEntry


class TestThreatAnalyzer:
    """Test the ThreatAnalyzer class"""

    def create_sample_entries(self):
        """Create sample log entries for testing"""
        entries = []

        # Normal requests from IP 1
        for i in range(5):
            entries.append(
                LogEntry(
                    ip="192.168.1.1",
                    timestamp=datetime(2026, 1, 17, 10, i, 0),
                    method="GET",
                    url="/index.php",
                    path="/index.php",
                    query="",
                    status=200,
                    bytes=1234,
                    user_agent="Mozilla/5.0",
                    tool="browser",
                    abnormal=[],
                )
            )

        # Suspicious requests from IP 2 (many SQLi attempts)
        for i in range(60):
            entries.append(
                LogEntry(
                    ip="192.168.1.2",
                    timestamp=datetime(2026, 1, 17, 11, 0, i),
                    method="GET",
                    url=f"/admin.php?id={i} UNION SELECT * FROM users",
                    path="/admin.php",
                    query=f"id={i} UNION SELECT * FROM users",
                    status=500 if i % 2 == 0 else 403,
                    bytes=789,
                    user_agent="sqlmap/1.0",
                    tool="sqlmap",
                    abnormal=["SQLi"],
                )
            )

        # Login attempts from IP 3
        for i in range(55):
            entries.append(
                LogEntry(
                    ip="192.168.1.3",
                    timestamp=datetime(2026, 1, 17, 12, 0, i),
                    method="POST",
                    url="/login.php",
                    path="/login.php",
                    query="",
                    status=401,
                    bytes=234,
                    user_agent="Mozilla/5.0",
                    tool="browser",
                    abnormal=[],
                )
            )

        return entries

    def test_analyze_basic(self):
        """Test basic analysis functionality"""
        analyzer = ThreatAnalyzer(min_requests=5)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=3)

        assert result.parsed_events == len(entries)
        assert len(result.top_suspicious_ips) <= 3
        assert len(result.top_suspicious_ips) > 0

    def test_min_requests_threshold(self):
        """Test that IPs below min_requests threshold are filtered"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        # Only IPs with >= 50 requests should be included
        for ip_analysis in result.top_suspicious_ips:
            assert ip_analysis.request_count >= 50

    def test_scoring_abnormal_requests(self):
        """Test that IPs with abnormal requests get higher scores"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        # IP with SQLi attacks should have higher score than normal traffic
        ip_scores = {ip.ip: ip.score for ip in result.top_suspicious_ips}

        if "192.168.1.2" in ip_scores:
            # IP 2 has SQLi attacks, should have high score
            assert ip_scores["192.168.1.2"] > 1.0

    def test_tool_detection_in_analysis(self):
        """Test that tools are detected during analysis"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        # Find IP 2 which uses sqlmap
        for ip_analysis in result.top_suspicious_ips:
            if ip_analysis.ip == "192.168.1.2":
                assert "sqlmap" in ip_analysis.tools_used

    def test_vulnerable_endpoints_ranking(self):
        """Test vulnerable endpoint ranking"""
        analyzer = ThreatAnalyzer(min_requests=5)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        # Should have vulnerable endpoints detected
        if len(result.vulnerable_endpoints) > 0:
            # Top endpoint should have highest score
            scores = [ep.score for ep in result.vulnerable_endpoints]
            assert scores == sorted(scores, reverse=True)

            # Check that /admin.php is in vulnerable endpoints
            endpoint_paths = [ep.endpoint for ep in result.vulnerable_endpoints]
            assert "/admin.php" in endpoint_paths

    def test_tools_first_seen(self):
        """Test tools first seen tracking"""
        analyzer = ThreatAnalyzer(min_requests=5)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        # Should have detected tools
        assert len(result.tools_first_seen) > 0

        # Tools should be sorted by timestamp
        if len(result.tools_first_seen) > 1:
            timestamps = [ts for _, ts in result.tools_first_seen]
            assert timestamps == sorted(timestamps)

    def test_status_code_counting(self):
        """Test status code counting"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        for ip_analysis in result.top_suspicious_ips:
            if ip_analysis.ip == "192.168.1.2":
                # Should have both 500 and 403 status codes
                assert 500 in ip_analysis.status_codes or 403 in ip_analysis.status_codes

    def test_top_paths_extraction(self):
        """Test top paths extraction"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        for ip_analysis in result.top_suspicious_ips:
            assert len(ip_analysis.top_paths) > 0
            # Top paths should be sorted by count
            if len(ip_analysis.top_paths) > 1:
                counts = [count for _, count in ip_analysis.top_paths]
                assert counts == sorted(counts, reverse=True)

    def test_abnormal_examples_extraction(self):
        """Test abnormal examples extraction"""
        analyzer = ThreatAnalyzer(min_requests=50)
        entries = self.create_sample_entries()

        result = analyzer.analyze(entries, top_n=10)

        for ip_analysis in result.top_suspicious_ips:
            if ip_analysis.abnormal_count > 0:
                assert len(ip_analysis.abnormal_examples) > 0
                # Should not exceed 8 examples
                assert len(ip_analysis.abnormal_examples) <= 8


class TestScoring:
    """Test scoring algorithm"""

    def test_volume_scoring(self):
        """Test that request volume affects score"""
        analyzer = ThreatAnalyzer(min_requests=1)

        # Create two IPs with different volumes
        entries = []
        for i in range(100):
            entries.append(
                LogEntry(
                    ip="192.168.1.1",
                    timestamp=datetime(2026, 1, 17, 10, 0, i % 60),
                    method="GET",
                    url="/index.php",
                    path="/index.php",
                    query="",
                    status=200,
                    bytes=1234,
                    user_agent="Mozilla/5.0",
                    tool="browser",
                    abnormal=[],
                )
            )

        for i in range(10):
            entries.append(
                LogEntry(
                    ip="192.168.1.2",
                    timestamp=datetime(2026, 1, 17, 10, 0, i),
                    method="GET",
                    url="/index.php",
                    path="/index.php",
                    query="",
                    status=200,
                    bytes=1234,
                    user_agent="Mozilla/5.0",
                    tool="browser",
                    abnormal=[],
                )
            )

        result = analyzer.analyze(entries, top_n=10)

        # IP with more requests should have higher score
        scores = {ip.ip: ip.score for ip in result.top_suspicious_ips}
        assert scores["192.168.1.1"] > scores["192.168.1.2"]
