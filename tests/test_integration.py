"""
Integration tests for weblog-hunter
"""

import os
import tempfile
from pathlib import Path

import pytest

from weblog_hunter.analyzer import ThreatAnalyzer
from weblog_hunter.parser import LogParser
from weblog_hunter.reporters.html import HTMLReporter
from weblog_hunter.reporters.json_reporter import JSONReporter
from weblog_hunter.reporters.markdown import MarkdownReporter


class TestEndToEnd:
    """End-to-end integration tests"""

    def get_sample_log_path(self):
        """Get path to sample log file"""
        fixtures_dir = Path(__file__).parent / "fixtures" / "sample_logs"
        return fixtures_dir / "sample_apache.log"

    def test_full_pipeline(self):
        """Test complete analysis pipeline"""
        log_file = self.get_sample_log_path()

        if not log_file.exists():
            pytest.skip("Sample log file not found")

        # Parse logs
        parser = LogParser()
        entries, failures, files_read = parser.parse_logs(str(log_file))

        assert len(entries) > 0
        assert files_read == 1

        # Analyze
        analyzer = ThreatAnalyzer(min_requests=1)
        result = analyzer.analyze(entries, top_n=10)
        result.files_read = files_read
        result.parse_failures = failures

        assert result.parsed_events == len(entries)
        assert len(result.top_suspicious_ips) > 0

    def test_markdown_report_generation(self):
        """Test markdown report generation"""
        log_file = self.get_sample_log_path()

        if not log_file.exists():
            pytest.skip("Sample log file not found")

        # Parse and analyze
        parser = LogParser()
        entries, failures, files_read = parser.parse_logs(str(log_file))

        analyzer = ThreatAnalyzer(min_requests=1)
        result = analyzer.analyze(entries, top_n=10)
        result.files_read = files_read
        result.parse_failures = failures

        # Generate report
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.md")
            reporter = MarkdownReporter()
            reporter.generate(result, output_path)

            # Check report was created
            assert os.path.exists(output_path)

            # Check report content
            with open(output_path) as f:
                content = f.read()
                assert "Web Log Recon Report" in content
                assert "Top suspicious IPs" in content

    def test_json_report_generation(self):
        """Test JSON report generation"""
        log_file = self.get_sample_log_path()

        if not log_file.exists():
            pytest.skip("Sample log file not found")

        # Parse and analyze
        parser = LogParser()
        entries, failures, files_read = parser.parse_logs(str(log_file))

        analyzer = ThreatAnalyzer(min_requests=1)
        result = analyzer.analyze(entries, top_n=10)
        result.files_read = files_read
        result.parse_failures = failures

        # Generate report
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.json")
            reporter = JSONReporter()
            reporter.generate(result, output_path)

            # Check report was created
            assert os.path.exists(output_path)

            # Check report is valid JSON
            import json

            with open(output_path) as f:
                data = json.load(f)
                assert "summary" in data
                assert "files_read" in data["summary"]

    def test_html_report_generation(self):
        """Test HTML report generation"""
        log_file = self.get_sample_log_path()

        if not log_file.exists():
            pytest.skip("Sample log file not found")

        # Parse and analyze
        parser = LogParser()
        entries, failures, files_read = parser.parse_logs(str(log_file))

        analyzer = ThreatAnalyzer(min_requests=1)
        result = analyzer.analyze(entries, top_n=10)
        result.files_read = files_read
        result.parse_failures = failures

        # Generate report
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            reporter = HTMLReporter()
            reporter.generate(result, output_path)

            # Check report was created
            assert os.path.exists(output_path)

            # Check report content
            with open(output_path) as f:
                content = f.read()
                assert "<!DOCTYPE html>" in content
                assert "Web Log Recon Report" in content

    def test_compressed_log_parsing(self):
        """Test parsing gzip compressed logs"""
        import gzip

        log_file = self.get_sample_log_path()
        if not log_file.exists():
            pytest.skip("Sample log file not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create compressed version
            gz_path = os.path.join(tmpdir, "sample.log.gz")
            with open(log_file, "rb") as f_in:
                with gzip.open(gz_path, "wb") as f_out:
                    f_out.write(f_in.read())

            # Parse compressed log
            parser = LogParser()
            entries, failures, files_read = parser.parse_logs(gz_path)

            assert len(entries) > 0
            assert files_read == 1

    def test_directory_parsing(self):
        """Test parsing logs from a directory"""
        log_file = self.get_sample_log_path()
        if not log_file.exists():
            pytest.skip("Sample log file not found")

        # Parse the fixtures directory
        fixtures_dir = Path(__file__).parent / "fixtures" / "sample_logs"

        parser = LogParser()
        entries, failures, files_read = parser.parse_logs(str(fixtures_dir))

        assert len(entries) > 0
        assert files_read >= 1


class TestCLICompatibility:
    """Test CLI backwards compatibility"""

    def test_old_wrapper_still_works(self):
        """Test that old weblog_hunter.py wrapper still works"""
        # This is more of a documentation test
        # The old script should import from the new package
        import sys
        from pathlib import Path

        # Add repo root to path
        repo_root = Path(__file__).parent.parent
        sys.path.insert(0, str(repo_root))

        # Should be able to import from old location
        try:
            from weblog_hunter.__main__ import main

            assert main is not None
        except ImportError:
            pytest.fail("Could not import main from new package structure")
