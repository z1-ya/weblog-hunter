"""
Tests for log parser functionality
"""

from pathlib import Path

from weblog_hunter.models import LogEntry
from weblog_hunter.parser import LogParser


class TestLogParser:
    """Test the LogParser class"""

    def test_parse_timestamp_with_timezone(self):
        """Test parsing timestamp with timezone"""
        parser = LogParser()
        ts = parser.parse_timestamp("17/Jan/2026:10:00:00 +0000")
        assert ts is not None
        assert ts.year == 2026
        assert ts.month == 1
        assert ts.day == 17
        assert ts.hour == 10

    def test_parse_timestamp_without_timezone(self):
        """Test parsing timestamp without timezone"""
        parser = LogParser()
        ts = parser.parse_timestamp("17/Jan/2026:10:00:00")
        assert ts is not None
        assert ts.year == 2026

    def test_parse_valid_apache_log_line(self):
        """Test parsing a valid Apache combined log line"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = parser.parse_line(line)

        assert entry is not None
        assert entry.ip == "192.168.1.1"
        assert entry.method == "GET"
        assert entry.url == "/index.php"
        assert entry.path == "/index.php"
        assert entry.status == 200
        assert entry.bytes == 1234
        assert "Mozilla/5.0" in entry.user_agent

    def test_parse_sqli_detection(self):
        """Test that SQLi attacks are detected during parsing"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET /admin.php?id=1%20OR%201=1 HTTP/1.1" 500 789 "-" "sqlmap/1.0"'
        entry = parser.parse_line(line)

        assert entry is not None
        assert "SQLi" in entry.abnormal
        assert entry.tool == "sqlmap"

    def test_parse_traversal_detection(self):
        """Test that path traversal is detected"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "curl/7.68.0"'
        entry = parser.parse_line(line)

        assert entry is not None
        assert "Traversal/LFI" in entry.abnormal
        assert entry.tool == "curl"

    def test_parse_xss_detection(self):
        """Test that XSS is detected"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 789 "-" "Mozilla/5.0"'
        entry = parser.parse_line(line)

        assert entry is not None
        assert "XSS" in entry.abnormal

    def test_parse_malformed_line(self):
        """Test that malformed lines return None"""
        parser = LogParser()
        line = "This is not a valid log line"
        entry = parser.parse_line(line)

        assert entry is None

    def test_parse_file(self):
        """Test parsing a complete log file"""
        parser = LogParser()
        fixtures_dir = Path(__file__).parent / "fixtures" / "sample_logs"
        log_file = fixtures_dir / "sample_apache.log"

        if log_file.exists():
            entries, failures = parser.parse_file(str(log_file))
            assert len(entries) > 0
            assert isinstance(entries[0], LogEntry)

    def test_parse_query_parameters(self):
        """Test that query parameters are extracted"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET /search.php?q=test&page=1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = parser.parse_line(line)

        assert entry is not None
        assert entry.path == "/search.php"
        assert entry.query == "q=test&page=1"


class TestToolDetection:
    """Test tool detection from user agents"""

    def test_detect_sqlmap(self):
        """Test sqlmap detection"""
        parser = LogParser()
        line = (
            '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "sqlmap/1.0"'
        )
        entry = parser.parse_line(line)
        assert entry.tool == "sqlmap"

    def test_detect_nikto(self):
        """Test nikto detection"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "nikto/2.1.6"'
        entry = parser.parse_line(line)
        assert entry.tool == "nikto"

    def test_detect_browser(self):
        """Test browser detection"""
        parser = LogParser()
        line = '192.168.1.1 - - [17/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/96.0"'
        entry = parser.parse_line(line)
        assert entry.tool == "browser"
