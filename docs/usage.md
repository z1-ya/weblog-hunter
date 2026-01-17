# Usage Guide

Comprehensive guide for using weblog-hunter effectively.

## Quick Start

```bash
# Analyze a single log file
weblog-hunter --input /var/log/apache2/access.log --out report.md

# Analyze directory with HTML report  
weblog-hunter --input /var/log/apache2/ --format html --out report.html

# Generate all formats
weblog-hunter --input logs/ --format all
```

## Command Line Options

- `--input PATH`: Input log file or directory (required)
- `--out PATH`: Markdown report output (default: report.md)
- `--json PATH`: JSON report output
- `--html PATH`: HTML report output
- `--format FORMAT`: Output format (md, json, html, all)
- `--top N`: Top N suspicious IPs (default: 10)
- `--min-req N`: Minimum requests for scoring (default: 50)
- `--config FILE`: YAML configuration file
- `--verbose, -v`: Verbose output
- `--quiet, -q`: Quiet mode
- `--version`: Show version

## Real-World Examples

### Incident Response
```bash
weblog-hunter --input /var/log/apache2/access.log.1 --top 20 --min-req 10 --format html
```

### Weekly Security Review
```bash
weblog-hunter --input /var/log/nginx/ --format all --top 50 --quiet
```

### Compliance Reporting
```bash
weblog-hunter --input logs/$(date +%Y-%m)-*.log --format html --out compliance-report.html
```

See full documentation at https://github.com/z1-ya/weblog-hunter
