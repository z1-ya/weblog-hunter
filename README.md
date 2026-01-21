# weblog-hunter 🎯

[![CI](https://github.com/shalbuzov/weblog-hunter/workflows/CI/badge.svg)](https://github.com/shalbuzov/weblog-hunter/actions)
[![codecov](https://codecov.io/gh/shalbuzov/weblog-hunter/branch/main/graph/badge.svg)](https://codecov.io/gh/shalbuzov/weblog-hunter)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Professional automated web log reconnaissance and threat hunting tool. Detects attacker behavior, exploited endpoints, SQL injection, scraping activity, and attacker tooling from Apache/Nginx access logs with zero manual analysis.

## ✨ Features

- 🔍 **Automatic Threat Detection**: SQLi, XSS, LFI, SSRF, RCE, XXE, NoSQL injection, and more
- 🤖 **Attack Tool Fingerprinting**: Identifies sqlmap, nikto, curl, gobuster, and 10+ other tools
- 📊 **Multi-Format Reports**: Generate Markdown, JSON, and interactive HTML reports
- 🎯 **Vulnerability Endpoint Ranking**: Automatically identifies your most vulnerable endpoints
- 📈 **Behavioral Analysis**: Detects brute force, credential stuffing, and scraping patterns
- ⚡ **High Performance**: Process millions of log lines with progress tracking
- 🐳 **Docker Support**: Easy containerized deployment
- 🧪 **Well-Tested**: 55+ tests with comprehensive coverage
- 📦 **Modular Architecture**: Clean, maintainable code with type hints
- 🔄 **Backwards Compatible**: Drop-in replacement for the original script

## 🚀 Quick Start

### Installation

```bash
# Install from source
git clone https://github.com/shalbuzov/weblog-hunter.git
cd weblog-hunter
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Analyze a single log file
weblog-hunter --input /var/log/apache2/access.log --out report.md

# Analyze directory of logs with HTML report
weblog-hunter --input /var/log/apache2/ --format html --out report.html

# Generate all report formats
weblog-hunter --input logs/ --format all --top 20 --min-req 100

# Use as Python module
python -m weblog_hunter --input access.log --out report.md
```

### Example Output

```bash
[*] Parsing logs from: examples/sample_apache.log
[+] Parsed 14 events from 1 file(s)
[*] Analyzing threats...
[*] Generating reports...
[+] Wrote MD report: report.md
[*] Top suspicious IP: 192.168.1.101 (score: 3.45)
```

## 📖 Usage Examples

### Analyze Apache Logs

```bash
weblog-hunter --input /var/log/apache2/access.log --out apache_report.md
```

### Analyze Nginx Logs

```bash
weblog-hunter --input /var/log/nginx/access.log --format html --out nginx_report.html
```

### Process Compressed Logs

```bash
# Works with .gz files automatically
weblog-hunter --input /var/log/apache2/access.log.gz --out report.md
```

### Custom Thresholds

```bash
# Lower minimum request threshold and show top 20 IPs
weblog-hunter --input logs/ --top 20 --min-req 10 --out report.md
```

### Quiet Mode for Automation

```bash
# No progress bars, suitable for cron jobs
weblog-hunter --input logs/ --out report.md --quiet
```

### Verbose Output

```bash
# Show detailed parsing information
weblog-hunter --input logs/ --out report.md --verbose
```

## 🔍 Detection Capabilities

### Attack Types Detected

- **SQL Injection (SQLi)**: UNION, OR 1=1, SLEEP, BENCHMARK, information_schema
- **Cross-Site Scripting (XSS)**: `<script>`, onerror, onload, javascript:
- **Path Traversal/LFI**: ../, %2e%2e, /etc/passwd, win.ini
- **Server-Side Request Forgery (SSRF)**: Internal IPs, localhost, cloud metadata
- **Command Injection**: cat, wget, curl, shell operators
- **Remote Code Execution (RCE)**: eval, exec, system, shell_exec
- **XML External Entity (XXE)**: DOCTYPE, ENTITY declarations
- **LDAP Injection**: Filter manipulation patterns
- **NoSQL Injection**: $ne, $gt, $where operators

### Tools Identified

- **Scanners**: sqlmap, nikto, acunetix, nmap, masscan, wpscan
- **Brute Forcers**: gobuster, dirbuster, hydra
- **HTTP Clients**: curl, wget, python-requests, go-http-client
- **Frameworks**: Burp Suite, ZAP, Metasploit, Nuclei
- **Bots**: Googlebot, Bingbot, and other crawlers

### Behavioral Patterns

- **Brute Force Attacks**: Multiple failed authentication attempts
- **Credential Stuffing**: Testing multiple accounts with similar patterns
- **Data Scraping**: Systematic enumeration of identity endpoints
- **Rate-Based Anomalies**: Burst activity detection
- **Session Hijacking**: Rapid IP changes for same session

## 📊 Report Formats

### Markdown Report

Clean, readable format perfect for documentation and sharing:

```markdown
# Web Log Recon Report

- Files read: **3**
- Parsed events: **15,234**
- Parse failures: **127**

## Top suspicious IPs (auto-scored)

| Rank | IP | Score | Requests |
|---:|---|---:|---:|
| 1 | 192.168.1.101 | 12.45 | 1,234 |
```

### JSON Report

Machine-readable format for integration with other tools:

```json
{
  "summary": {
    "files_read": 3,
    "parsed_events": 15234,
    "top_suspicious_ips": ["192.168.1.101", "10.0.0.5"]
  },
  "top_ips_detail": [...]
}
```

### HTML Report

Interactive, styled report with sortable tables and visual hierarchy:

- Responsive design
- Color-coded threat levels
- Organized sections
- Attack type badges
- Copy-friendly code blocks

## 🏗️ Architecture

```
weblog-hunter/
├── weblog_hunter/
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # CLI entry point
│   ├── parser.py             # Log parsing with format detection
│   ├── analyzer.py           # Threat analysis and scoring
│   ├── signatures.py         # Attack pattern definitions
│   ├── models.py             # Data models with type hints
│   ├── config.py             # Configuration management
│   └── reporters/            # Report generators
│       ├── markdown.py       # Markdown output
│       ├── json_reporter.py  # JSON output
│       └── html.py           # HTML output
├── tests/                    # Comprehensive test suite
├── examples/                 # Sample logs and reports
└── docs/                     # Documentation
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=weblog_hunter tests/

# Run specific test file
pytest tests/test_parser.py -v

# Run specific test
pytest tests/test_parser.py::TestLogParser::test_parse_sqli_detection -v
```

Current test coverage: **55 passing tests** covering:
- Log parsing (12 tests)
- Signature detection (26 tests)
- Threat analysis (10 tests)
- Integration workflows (7 tests)

## ⚙️ Configuration

### Command Line Options

```
--input PATH              Input log file or directory
--out PATH                Markdown report output path
--json PATH               JSON report output path
--html PATH               HTML report output path
--format FORMAT           Output format: md, json, html, all
--top N                   Top N suspicious IPs (default: 10)
--min-req N              Minimum requests for scoring (default: 50)
--config FILE            Configuration file (YAML)
--verbose, -v            Verbose output
--quiet, -q              Quiet mode (no progress bars)
--version                Show version
```

### Configuration File (YAML)

Create a `weblog-hunter.yml` file:

```yaml
analysis:
  min_requests: 50
  top_ips: 10

output:
  formats: [md, html, json]
  directory: ./reports/

performance:
  threads: 4
  max_memory_mb: 1024
```

Use with:

```bash
weblog-hunter --input logs/ --config weblog-hunter.yml
```

## 🐳 Docker Usage

```bash
# Build image
docker build -t weblog-hunter .

# Run analysis
docker run -v $(pwd)/logs:/logs -v $(pwd)/reports:/reports \
  weblog-hunter --input /logs --output /reports/report.md
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/contributing.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/shalbuzov/weblog-hunter.git
cd weblog-hunter

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black weblog_hunter/

# Lint code
ruff check weblog_hunter/

# Type check
mypy weblog_hunter/
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original concept and implementation by Ziya Shalbuzov
- Built with Python, regex, and determination
- Inspired by real-world threat hunting needs

## 📚 Documentation

- [Usage Guide](docs/usage.md) - Comprehensive usage examples
- [API Documentation](docs/api.md) - Use as a Python library
- [Contributing Guide](docs/contributing.md) - How to contribute

## 🔗 Links

- **GitHub**: https://github.com/shalbuzov/weblog-hunter
- **Issues**: https://github.com/shalbuzov/weblog-hunter/issues

## 📈 Performance

- Parses **100,000+ lines/second** on modern hardware
- Memory efficient with streaming support
- Progress bars for long-running operations
- Supports compressed (.gz) logs natively

## 🛡️ Security

This tool is designed for defensive security purposes:
- Analyze your own web server logs
- Identify security incidents
- Discover vulnerable endpoints
- Track attacker behavior

**Do not use this tool for unauthorized security testing.**

---

Made with ❤️ for the security community
