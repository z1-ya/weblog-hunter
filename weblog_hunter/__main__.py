"""
CLI entry point for weblog-hunter
"""

import argparse
import sys
from pathlib import Path

from weblog_hunter import __version__
from weblog_hunter.parser import LogParser
from weblog_hunter.analyzer import ThreatAnalyzer
from weblog_hunter.reporters.markdown import MarkdownReporter
from weblog_hunter.reporters.json_reporter import JSONReporter
from weblog_hunter.reporters.html import HTMLReporter
from weblog_hunter.config import Config


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Automatic reconnaissance on web access logs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --input access.log --out report.md
  %(prog)s --input /var/log/apache2/ --format html --out report.html
  %(prog)s --input logs/ --format all --top 20 --min-req 100
        """
    )
    
    # Input/Output
    parser.add_argument("--input", required=True, help="Path to access.log or folder of logs (.log/.gz supported)")
    parser.add_argument("--out", default="report.md", help="Output report path (default: report.md)")
    parser.add_argument("--json", dest="json_out", default=None, help="Optional JSON report output path")
    parser.add_argument("--html", dest="html_out", default=None, help="Optional HTML report output path")
    parser.add_argument("--format", dest="output_format", choices=["md", "json", "html", "all"], default=None,
                        help="Output format (overrides individual output options)")
    
    # Analysis options
    parser.add_argument("--top", type=int, default=10, help="Top N suspicious IPs to detail (default: 10)")
    parser.add_argument("--min-req", type=int, default=50, help="Minimum requests before scoring an IP (default: 50)")
    
    # Config file
    parser.add_argument("--config", dest="config_file", default=None, help="Configuration file (YAML)")
    
    # Display options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (no progress bars)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config_file:
        try:
            config = Config.from_file(args.config_file)
        except Exception as e:
            print(f"Error loading config file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        config = Config()
    
    # Merge CLI arguments
    config.merge_cli_args(args)
    
    # Parse logs
    if not config.quiet:
        print(f"[*] Parsing logs from: {args.input}")
    
    log_parser = LogParser()
    entries, failures, files_read = log_parser.parse_logs(
        args.input, 
        show_progress=config.show_progress and not config.quiet
    )
    
    if not config.quiet:
        print(f"[+] Parsed {len(entries)} events from {files_read} file(s)")
        if failures > 0:
            print(f"[!] {failures} lines failed to parse")
    
    # Analyze
    if not config.quiet:
        print(f"[*] Analyzing threats...")
    
    analyzer = ThreatAnalyzer(min_requests=config.min_requests)
    result = analyzer.analyze(entries, top_n=config.top_ips)
    result.files_read = files_read
    result.parse_failures = failures
    
    # Determine output formats
    output_formats = []
    if args.output_format == "all":
        output_formats = ["md", "json", "html"]
    elif args.output_format:
        output_formats = [args.output_format]
    else:
        # Use individual output options
        if args.out:
            output_formats.append("md")
        if args.json_out:
            output_formats.append("json")
        if args.html_out:
            output_formats.append("html")
    
    # Generate reports
    if not config.quiet:
        print(f"[*] Generating reports...")
    
    reporters = {
        "md": (MarkdownReporter(), args.out if "md" in output_formats else "report.md"),
        "json": (JSONReporter(), args.json_out if args.json_out else "report.json"),
        "html": (HTMLReporter(), args.html_out if args.html_out else "report.html"),
    }
    
    for format_name in output_formats:
        if format_name in reporters:
            reporter, output_path = reporters[format_name]
            
            # Adjust output path for "all" format
            if args.output_format == "all":
                base = Path(args.out).stem if args.out else "report"
                ext = {"md": ".md", "json": ".json", "html": ".html"}[format_name]
                output_path = base + ext
            
            reporter.generate(result, output_path)
            
            if not config.quiet:
                print(f"[+] Wrote {format_name.upper()} report: {output_path}")
    
    # Summary
    if not config.quiet and result.top_suspicious_ips:
        print(f"\n[*] Top suspicious IP: {result.top_suspicious_ips[0].ip} "
              f"(score: {result.top_suspicious_ips[0].score:.2f})")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
