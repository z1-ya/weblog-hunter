"""
Log parsing functionality for weblog-hunter
Supports Apache, Nginx, and other common log formats
"""

import gzip
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, List
from urllib.parse import urlsplit, unquote

from weblog_hunter.models import LogEntry
from weblog_hunter.signatures import SignatureDetector


# Apache/Nginx combined log format regex
# Example: IP - - [10/Apr/2021:12:01:55 +0000] "GET /path?q=1 HTTP/1.1" 200 1234 "-" "UA"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/(?P<httpver>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


class LogParser:
    """Parser for web server access logs"""
    
    def __init__(self):
        self.detector = SignatureDetector()
    
    def parse_timestamp(self, ts_string: str) -> Optional[datetime]:
        """
        Parse Apache/Nginx timestamp
        
        Args:
            ts_string: Timestamp string (e.g., "10/Apr/2021:12:01:55 +0000")
            
        Returns:
            Parsed datetime object or None if parsing fails
        """
        # Try with timezone first, then without
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
            try:
                return datetime.strptime(ts_string, fmt)
            except ValueError:
                continue
        return None
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line
        
        Args:
            line: Raw log line
            
        Returns:
            LogEntry object or None if parsing fails
        """
        match = COMBINED_LOG_REGEX.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp = self.parse_timestamp(groups["ts"])
        
        # Parse URL components
        url = groups["url"]
        parsed_url = urlsplit(url)
        path = parsed_url.path or url
        query = parsed_url.query or ""
        
        # Parse bytes
        bytes_str = groups["bytes"]
        bytes_val = 0
        if bytes_str not in ("-", ""):
            try:
                bytes_val = int(bytes_str)
            except ValueError:
                bytes_val = 0
        
        # Detect attacks and tools
        user_agent = groups.get("ua") or ""
        abnormal = self.detector.detect_attacks(url)
        tool = self.detector.detect_tool(user_agent)
        
        return LogEntry(
            ip=groups["ip"],
            timestamp=timestamp,
            method=groups["method"],
            url=url,
            path=path,
            query=query,
            status=int(groups["status"]),
            bytes=bytes_val,
            user_agent=user_agent,
            referer=groups.get("ref"),
            tool=tool,
            abnormal=abnormal,
        )
    
    def open_file(self, filepath: str):
        """
        Open a file, handling .gz compression
        
        Args:
            filepath: Path to log file
            
        Returns:
            File handle
        """
        if filepath.endswith(".gz"):
            return gzip.open(filepath, "rt", errors="replace")
        return open(filepath, "rt", errors="replace")
    
    def parse_file(self, filepath: str) -> tuple[List[LogEntry], int]:
        """
        Parse a log file
        
        Args:
            filepath: Path to log file
            
        Returns:
            Tuple of (list of LogEntry objects, number of parse failures)
        """
        entries = []
        failures = 0
        
        with self.open_file(filepath) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                    
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
                else:
                    failures += 1
        
        return entries, failures
    
    def iter_log_files(self, input_path: str) -> Iterator[str]:
        """
        Iterate over log files in a directory or yield single file
        
        Args:
            input_path: Path to log file or directory
            
        Yields:
            Path to each log file
        """
        path = Path(input_path)
        
        if path.is_dir():
            # Walk directory and find log files
            for root, _, files in os.walk(path):
                for filename in files:
                    if any(filename.endswith(ext) for ext in [".log", ".log.gz", ".txt", ".gz"]):
                        yield os.path.join(root, filename)
        else:
            yield input_path
    
    def parse_logs(self, input_path: str, show_progress: bool = False) -> tuple[List[LogEntry], int, int]:
        """
        Parse all logs from input path
        
        Args:
            input_path: Path to log file or directory
            show_progress: Whether to show progress bar (requires tqdm)
            
        Returns:
            Tuple of (list of all LogEntry objects, total parse failures, files read)
        """
        all_entries = []
        total_failures = 0
        files_read = 0
        
        files = list(self.iter_log_files(input_path))
        
        if show_progress:
            try:
                from tqdm import tqdm
                files = tqdm(files, desc="Parsing log files", unit="file")
            except ImportError:
                pass
        
        for filepath in files:
            entries, failures = self.parse_file(filepath)
            all_entries.extend(entries)
            total_failures += failures
            files_read += 1
        
        return all_entries, total_failures, files_read
