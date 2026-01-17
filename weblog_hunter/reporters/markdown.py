"""
Markdown report generator
"""

from weblog_hunter.models import AnalysisResult
from weblog_hunter.reporters import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generates markdown reports"""
    
    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate a markdown report
        
        Args:
            result: Analysis results
            output_path: Path to write markdown file
        """
        lines = []
        
        # Header
        lines.append("# Web Log Recon Report\n")
        lines.append(f"- Files read: **{result.files_read}**")
        lines.append(f"- Parsed events: **{result.parsed_events}**")
        lines.append(f"- Parse failures (non-matching lines): **{result.parse_failures}**\n")
        
        # Top suspicious IPs
        lines.append("## Top suspicious IPs (auto-scored)\n")
        if not result.top_suspicious_ips:
            lines.append("No IPs found matching the minimum request threshold.\n")
        else:
            lines.append("| Rank | IP | Score | Requests |\n|---:|---|---:|---:|")
            for i, ip_analysis in enumerate(result.top_suspicious_ips, 1):
                lines.append(
                    f"| {i} | {ip_analysis.ip} | {ip_analysis.score:.2f} | "
                    f"{ip_analysis.request_count} |"
                )
            lines.append("")
        
        # Attacker tools
        lines.append("## Attacker tools (by first appearance in logs)\n")
        if result.tools_first_seen:
            for name, ts in result.tools_first_seen:
                lines.append(f"- **{name}** — first seen: {ts.isoformat()}")
        else:
            lines.append("- No tool fingerprints found in User-Agent fields.")
        lines.append("")
        
        # Vulnerable endpoints
        lines.append("## Likely vulnerable SQLi endpoints (ranked)\n")
        if result.vulnerable_endpoints:
            lines.append(
                "| Rank | Endpoint | Score | SQLi hits | SQLi+500 | Unique payloads |\n"
                "|---:|---|---:|---:|---:|---:|"
            )
            for i, ep in enumerate(result.vulnerable_endpoints[:10], 1):
                lines.append(
                    f"| {i} | `{ep.endpoint}` | {ep.score:.0f} | {ep.sqli_hits} | "
                    f"{ep.sqli_500} | {ep.unique_payloads} |"
                )
            lines.append("")
            
            # Show examples for top endpoint
            if result.vulnerable_endpoints:
                top_ep = result.vulnerable_endpoints[0]
                lines.append(f"### Example SQLi requests targeting `{top_ep.endpoint}`")
                for url in top_ep.examples:
                    lines.append(f"- `{url}`")
                lines.append("")
        else:
            lines.append("- No SQLi signatures found.\n")
        
        # Email scraping section
        lines.append("## Inferred section used for email scraping\n")
        if result.inferred_scrape_section:
            lines.append(
                f"- Most likely section: **`{result.inferred_scrape_section}`** "
                "(identity/user-related endpoint repeatedly hit by top suspicious IPs)\n"
            )
        else:
            lines.append(
                "- Could not infer a scraping section (no strong identity endpoint hits "
                "among top suspicious IPs).\n"
            )
        
        # Per-IP details
        lines.append("## Per-IP movement (top suspicious IPs)\n")
        for ip_analysis in result.top_suspicious_ips:
            lines.append(f"### {ip_analysis.ip}")
            lines.append(f"- Requests: **{ip_analysis.request_count}**")
            
            # Status codes
            status_str = ", ".join(
                f"{k}:{v}" for k, v in sorted(ip_analysis.status_codes.items())
            )
            lines.append(f"- Status codes: {status_str}")
            
            # Top endpoints
            lines.append("- Top endpoints:")
            for path, count in ip_analysis.top_paths:
                lines.append(f"  - `{path}` — {count}")
            
            # Abnormal examples
            if ip_analysis.abnormal_examples:
                lines.append("- Abnormal query examples:")
                for entry in ip_analysis.abnormal_examples:
                    attack_types = ",".join(entry.abnormal)
                    lines.append(
                        f"  - **{attack_types}** `{entry.url}` (status {entry.status})"
                    )
            
            lines.append("")
        
        # Write report
        report_text = "\n".join(lines)
        self.ensure_directory(output_path)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
