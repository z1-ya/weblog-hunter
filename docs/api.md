# API Documentation

Use weblog-hunter as a Python library in your own projects.

## Basic Usage

```python
from weblog_hunter.parser import LogParser
from weblog_hunter.analyzer import ThreatAnalyzer
from weblog_hunter.reporters.markdown import MarkdownReporter

# Parse logs
parser = LogParser()
entries, failures, files_read = parser.parse_logs("/var/log/apache2/access.log")

# Analyze threats
analyzer = ThreatAnalyzer(min_requests=50)
result = analyzer.analyze(entries, top_n=10)
result.files_read = files_read
result.parse_failures = failures

# Generate report
reporter = MarkdownReporter()
reporter.generate(result, "report.md")
```

## Classes

### LogParser

Parse web server access logs.

```python
from weblog_hunter.parser import LogParser

parser = LogParser()

# Parse a single file
entries, failures = parser.parse_file("/var/log/apache2/access.log")

# Parse directory
entries, failures, files_read = parser.parse_logs("/var/log/apache2/", show_progress=True)
```

### ThreatAnalyzer

Analyze log entries for threats.

```python
from weblog_hunter.analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer(min_requests=50)
result = analyzer.analyze(entries, top_n=10)

# Access results
for ip_analysis in result.top_suspicious_ips:
    print(f"{ip_analysis.ip}: {ip_analysis.score}")
```

### SignatureDetector

Detect attack patterns.

```python
from weblog_hunter.signatures import SignatureDetector

detector = SignatureDetector()

# Detect attacks in URL
attacks = detector.detect_attacks("/admin.php?id=1 UNION SELECT * FROM users")
# Returns: ["SQLi"]

# Detect tool from user agent
tool = detector.detect_tool("sqlmap/1.0")
# Returns: "sqlmap"
```

## Data Models

### LogEntry

```python
from weblog_hunter.models import LogEntry
from datetime import datetime

entry = LogEntry(
    ip="192.168.1.1",
    timestamp=datetime.now(),
    method="GET",
    url="/index.php",
    path="/index.php",
    query="",
    status=200,
    bytes=1234,
    user_agent="Mozilla/5.0",
    tool="browser",
    abnormal=[]
)
```

### AnalysisResult

```python
# Access analysis results
result.parsed_events          # Total events parsed
result.top_suspicious_ips     # List of IPAnalysis objects
result.vulnerable_endpoints   # List of EndpointVulnerability objects
result.tools_first_seen       # List of (tool, timestamp) tuples

# Convert to dictionary for JSON
data = result.to_dict()
```

## Reporters

### MarkdownReporter

```python
from weblog_hunter.reporters.markdown import MarkdownReporter

reporter = MarkdownReporter()
reporter.generate(result, "report.md")
```

### JSONReporter

```python
from weblog_hunter.reporters.json_reporter import JSONReporter

reporter = JSONReporter()
reporter.generate(result, "report.json")
```

### HTMLReporter

```python
from weblog_hunter.reporters.html import HTMLReporter

reporter = HTMLReporter()
reporter.generate(result, "report.html")
```

## Advanced Usage

### Custom Signature Detection

```python
import re
from weblog_hunter.signatures import SignatureDetector

# Extend signature detector
class CustomDetector(SignatureDetector):
    def detect_custom_attack(self, url):
        if re.search(r'my-pattern', url):
            return True
        return False
```

### Custom Scoring

```python
from weblog_hunter.analyzer import ThreatAnalyzer

class CustomAnalyzer(ThreatAnalyzer):
    def _analyze_ip(self, ip, events):
        analysis = super()._analyze_ip(ip, events)
        # Add custom scoring logic
        analysis.score += my_custom_score(events)
        return analysis
```

### Progress Tracking

```python
from tqdm import tqdm

# Parse with progress bar
entries, failures, files_read = parser.parse_logs(
    "/var/log/apache2/",
    show_progress=True
)
```

## Type Hints

All modules include comprehensive type hints for better IDE support:

```python
from weblog_hunter.parser import LogParser
from weblog_hunter.models import LogEntry
from typing import List, Tuple

def process_logs(log_path: str) -> Tuple[List[LogEntry], int]:
    parser = LogParser()
    entries, failures = parser.parse_file(log_path)
    return entries, failures
```

## Examples

See the `examples/` directory for complete working examples.
