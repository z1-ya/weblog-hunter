"""
HTML report generator with interactive features
"""

from jinja2 import Template

from weblog_hunter.models import AnalysisResult
from weblog_hunter.reporters import BaseReporter

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Log Recon Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3498db;
        }

        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #ecf0f1;
        }

        h3 {
            color: #7f8c8d;
            margin-top: 20px;
            margin-bottom: 10px;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .summary-item {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }

        .summary-item .label {
            font-size: 0.9em;
            color: #7f8c8d;
            margin-bottom: 5px;
        }

        .summary-item .value {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }

        th {
            background: #34495e;
            color: white;
            font-weight: 600;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .high-score {
            color: #e74c3c;
            font-weight: bold;
        }

        .medium-score {
            color: #f39c12;
            font-weight: bold;
        }

        .low-score {
            color: #27ae60;
        }

        .tool-badge {
            display: inline-block;
            padding: 3px 8px;
            margin: 2px;
            background: #3498db;
            color: white;
            border-radius: 3px;
            font-size: 0.85em;
        }

        .attack-badge {
            display: inline-block;
            padding: 3px 8px;
            margin: 2px;
            background: #e74c3c;
            color: white;
            border-radius: 3px;
            font-size: 0.85em;
        }

        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }

        .ip-detail {
            background: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }

        .endpoint-list {
            list-style: none;
            padding-left: 0;
        }

        .endpoint-list li {
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 3px;
        }

        .abnormal-example {
            margin: 5px 0;
            padding: 8px;
            background: #fff5f5;
            border-left: 3px solid #e74c3c;
            border-radius: 3px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Web Log Recon Report</h1>

        <div class="summary">
            <div class="summary-item">
                <div class="label">Files Processed</div>
                <div class="value">{{ result.files_read }}</div>
            </div>
            <div class="summary-item">
                <div class="label">Events Parsed</div>
                <div class="value">{{ result.parsed_events }}</div>
            </div>
            <div class="summary-item">
                <div class="label">Parse Failures</div>
                <div class="value">{{ result.parse_failures }}</div>
            </div>
        </div>

        <h2>🚨 Top Suspicious IPs</h2>
        {% if result.top_suspicious_ips %}
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>IP Address</th>
                    <th>Score</th>
                    <th>Requests</th>
                    <th>Tools</th>
                </tr>
            </thead>
            <tbody>
                {% for ip in result.top_suspicious_ips %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td><strong>{{ ip.ip }}</strong></td>
                    <td class="{% if ip.score > 10 %}high-score{% elif ip.score > 5 %}medium-score{% else %}low-score{% endif %}">
                        {{ "%.2f"|format(ip.score) }}
                    </td>
                    <td>{{ ip.request_count }}</td>
                    <td>
                        {% for tool in ip.tools_used %}
                        <span class="tool-badge">{{ tool }}</span>
                        {% endfor %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No IPs found matching the minimum request threshold.</p>
        {% endif %}

        <h2>🛠️ Attacker Tools (First Appearance)</h2>
        {% if result.tools_first_seen %}
        <ul>
            {% for name, ts in result.tools_first_seen %}
            <li><strong>{{ name }}</strong> — first seen: {{ ts.isoformat() }}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p>No tool fingerprints found in User-Agent fields.</p>
        {% endif %}

        <h2>💉 Likely Vulnerable SQLi Endpoints</h2>
        {% if result.vulnerable_endpoints %}
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Endpoint</th>
                    <th>Score</th>
                    <th>SQLi Hits</th>
                    <th>SQLi+500</th>
                    <th>Unique Payloads</th>
                </tr>
            </thead>
            <tbody>
                {% for ep in result.vulnerable_endpoints[:10] %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td><code>{{ ep.endpoint }}</code></td>
                    <td>{{ ep.score }}</td>
                    <td>{{ ep.sqli_hits }}</td>
                    <td>{{ ep.sqli_500 }}</td>
                    <td>{{ ep.unique_payloads }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if result.vulnerable_endpoints %}
        <h3>Example SQLi Requests (Top Endpoint)</h3>
        <ul class="endpoint-list">
            {% for url in result.vulnerable_endpoints[0].examples %}
            <li><code>{{ url }}</code></li>
            {% endfor %}
        </ul>
        {% endif %}
        {% else %}
        <p>No SQLi signatures found.</p>
        {% endif %}

        <h2>📧 Inferred Email Scraping Section</h2>
        {% if result.inferred_scrape_section %}
        <p>Most likely section: <strong><code>{{ result.inferred_scrape_section }}</code></strong></p>
        <p><em>This identity/user-related endpoint was repeatedly hit by top suspicious IPs.</em></p>
        {% else %}
        <p>Could not infer a scraping section (no strong identity endpoint hits among top suspicious IPs).</p>
        {% endif %}

        <h2>📊 Per-IP Movement Details</h2>
        {% for ip in result.top_suspicious_ips %}
        <div class="ip-detail">
            <h3>{{ ip.ip }}</h3>
            <p><strong>Requests:</strong> {{ ip.request_count }}</p>
            <p><strong>Status codes:</strong>
                {% for status, count in ip.status_codes.items() %}
                    {{ status }}:{{ count }}{% if not loop.last %}, {% endif %}
                {% endfor %}
            </p>

            <p><strong>Top Endpoints:</strong></p>
            <ul class="endpoint-list">
                {% for path, count in ip.top_paths %}
                <li><code>{{ path }}</code> — {{ count }} requests</li>
                {% endfor %}
            </ul>

            {% if ip.abnormal_examples %}
            <p><strong>Abnormal Query Examples:</strong></p>
            {% for entry in ip.abnormal_examples %}
            <div class="abnormal-example">
                {% for attack in entry.abnormal %}
                <span class="attack-badge">{{ attack }}</span>
                {% endfor %}
                <br>
                <code>{{ entry.url }}</code> (status {{ entry.status }})
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """Generates HTML reports with interactive features"""

    def generate(self, result: AnalysisResult, output_path: str) -> None:
        """
        Generate an HTML report

        Args:
            result: Analysis results
            output_path: Path to write HTML file
        """
        template = Template(HTML_TEMPLATE)
        html_content = template.render(result=result)

        self.ensure_directory(output_path)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
