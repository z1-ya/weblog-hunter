#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import urlsplit, unquote

# --- Parsing: supports many Apache/Nginx "common/combined-like" variants ---
# Example combined:
# IP - - [10/Apr/2021:12:01:55 +0000] "GET /path?q=1 HTTP/1.1" 200 1234 "-" "UA"
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/(?P<httpver>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Timestamp parse (Apache style: 10/Apr/2021:12:01:55 +0000)
def parse_ts(ts: str):
    # Some logs omit timezone; handle both
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None

def open_any(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "rt", errors="replace")

def iter_log_files(input_path):
    if os.path.isdir(input_path):
        for root, _, files in os.walk(input_path):
            for fn in files:
                if fn.endswith(".log") or fn.endswith(".log.gz") or fn.endswith(".txt") or fn.endswith(".gz"):
                    yield os.path.join(root, fn)
    else:
        yield input_path

# --- Signatures ---
SQLI_RE = re.compile(r"(?i)(\bunion\b|\bselect\b|\binformation_schema\b|\bsleep\s*\(|\bbenchmark\s*\(|--|/\*|\*/|%27|'|\bor\s+1=1\b)")
TRAV_RE = re.compile(r"(?i)(\.\./|%2e%2e%2f|%2e%2e\\|/etc/passwd|win\.ini)")
XSS_RE  = re.compile(r"(?i)(<script|%3cscript|onerror=|onload=|alert\s*\()")
SSRF_RE = re.compile(r"(?i)(https?://|%3a%2f%2f|169\.254\.169\.254|localhost|127\.0\.0\.1)")
CMDI_RE = re.compile(r"(?i)(\bcat\b|\bwget\b|\bcurl\b|;|\|\||&&|\b/bin/sh\b|\bpowershell\b)")
SCANNER_UA = [
    ("sqlmap", re.compile(r"(?i)\bsqlmap\b")),
    ("curl", re.compile(r"(?i)\bcurl/\d")),
    ("python-requests", re.compile(r"(?i)\bpython-requests\b")),
    ("go-http-client", re.compile(r"(?i)\bgo-http-client\b")),
    ("nikto", re.compile(r"(?i)\bnikto\b")),
    ("acunetix", re.compile(r"(?i)\bacunetix\b")),
    ("nmap", re.compile(r"(?i)\bnmap\b")),
    ("masscan", re.compile(r"(?i)\bmasscan\b")),
    ("wget", re.compile(r"(?i)\bwget/\d")),
    ("gobuster", re.compile(r"(?i)\bgobuster\b")),
    ("dirbuster", re.compile(r"(?i)\bdirbuster\b")),
]

IDENTITY_HINTS = re.compile(r"(?i)(whoami|profile|account|user|users|customer|customers|admin)")
LOGIN_HINTS    = re.compile(r"(?i)(login|signin|auth|token|session)")
EMAIL_HINTS    = re.compile(r"(?i)(email|mail)")

def classify_abnormal(url: str):
    # url includes path + query possibly
    decoded = unquote(url)
    hits = []
    if SQLI_RE.search(decoded): hits.append("SQLi")
    if TRAV_RE.search(decoded): hits.append("Traversal/LFI")
    if XSS_RE.search(decoded):  hits.append("XSS")
    if SSRF_RE.search(decoded): hits.append("SSRF")
    if CMDI_RE.search(decoded): hits.append("CMDi/Shell")
    return hits

def tool_from_ua(ua: str):
    if not ua:
        return None
    for name, rx in SCANNER_UA:
        if rx.search(ua):
            return name
    # treat normal browsers as "browser"
    if "Mozilla/" in ua or "Chrome/" in ua or "Safari/" in ua or "Firefox/" in ua:
        return "browser"
    return None

def main():
    ap = argparse.ArgumentParser(description="Automatic reconnaissance on web access logs.")
    ap.add_argument("--input", required=True, help="Path to access.log or folder of logs (.log/.gz supported)")
    ap.add_argument("--out", default="report.md", help="Markdown report output path")
    ap.add_argument("--json", dest="json_out", default=None, help="Optional JSON report output path")
    ap.add_argument("--top", type=int, default=10, help="Top N suspicious IPs to detail")
    ap.add_argument("--min-req", type=int, default=50, help="Minimum requests before scoring an IP")
    args = ap.parse_args()

    events = []
    parse_fail = 0
    files_read = 0

    for fp in iter_log_files(args.input):
        files_read += 1
        with open_any(fp) as f:
            for line in f:
                line = line.rstrip("\n")
                m = LOG_RE.match(line)
                if not m:
                    parse_fail += 1
                    continue
                gd = m.groupdict()
                ts = parse_ts(gd["ts"])
                method = gd["method"]
                url = gd["url"]
                status = int(gd["status"])
                b = gd["bytes"]
                size = 0 if b in ("-", "") else int(b) if b.isdigit() else 0
                ua = gd.get("ua") or ""
                ip = gd["ip"]

                # split path/query
                u = urlsplit(url)
                path = u.path or url  # fallback
                query = u.query or ""

                abnormal = classify_abnormal(url)
                tool = tool_from_ua(ua)

                events.append({
                    "ts": ts.isoformat() if ts else None,
                    "ts_obj": ts,
                    "ip": ip,
                    "method": method,
                    "url": url,
                    "path": path,
                    "query": query,
                    "status": status,
                    "bytes": size,
                    "ua": ua,
                    "tool": tool,
                    "abnormal": abnormal,
                })

    # --- Aggregate ---
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    # scoring IPs: volume + errors + abnormal payloads + auth probing
    ip_scores = []
    for ip, evs in by_ip.items():
        n = len(evs)
        if n < args.min_req:
            continue

        statuses = Counter(e["status"] for e in evs)
        s4 = sum(v for k, v in statuses.items() if 400 <= k <= 499)
        s5 = sum(v for k, v in statuses.items() if 500 <= k <= 599)

        abnormal_hits = sum(1 for e in evs if e["abnormal"])
        login_hits = sum(1 for e in evs if LOGIN_HINTS.search(e["path"]))
        identity_hits = sum(1 for e in evs if IDENTITY_HINTS.search(e["path"]))

        # crude burst metric: requests in same minute
        per_min = Counter()
        for e in evs:
            if e["ts_obj"]:
                key = e["ts_obj"].strftime("%Y-%m-%d %H:%M")
                per_min[key] += 1
        max_rpm = max(per_min.values()) if per_min else 0

        score = (
            0.002 * n +
            0.02 * s5 +
            0.01 * s4 +
            0.05 * abnormal_hits +
            0.03 * login_hits +
            0.02 * identity_hits +
            0.01 * max_rpm
        )
        ip_scores.append((score, ip))

    ip_scores.sort(reverse=True)
    top_ips = [ip for _, ip in ip_scores[:args.top]]

    # tools by first-seen (global + per top ip)
    tool_first_seen = {}
    for e in events:
        if not e["tool"] or not e["ts_obj"]:
            continue
        t = e["tool"]
        if t not in tool_first_seen or e["ts_obj"] < tool_first_seen[t]:
            tool_first_seen[t] = e["ts_obj"]
    tools_ordered = sorted(tool_first_seen.items(), key=lambda x: x[1])

    # vulnerable endpoints ranking (SQLi)
    # score per endpoint = sqli_hits*3 + (sqli_and_500)*2 + unique_payloads
    endpoint_stats = {}
    for e in events:
        if "SQLi" not in e["abnormal"]:
            continue
        key = e["path"]
        st = endpoint_stats.setdefault(key, {"sqli_hits": 0, "sqli_500": 0, "payloads": set(), "examples": []})
        st["sqli_hits"] += 1
        if 500 <= e["status"] <= 599:
            st["sqli_500"] += 1
        # payload-ish: keep part of url for uniqueness
        st["payloads"].add(e["url"][:200])
        if len(st["examples"]) < 5:
            st["examples"].append(e["url"])

    endpoint_rank = []
    for ep, st in endpoint_stats.items():
        score = 3*st["sqli_hits"] + 2*st["sqli_500"] + len(st["payloads"])
        endpoint_rank.append((score, ep, st))
    endpoint_rank.sort(reverse=True)

    # email scraping inference: identity endpoints hammered + post-login + success + large bytes
    scrape_candidates = defaultdict(lambda: {"hits": 0, "ok": 0, "bytes": [], "paths": Counter()})
    for ip in top_ips:
        evs = by_ip[ip]
        for e in evs:
            if IDENTITY_HINTS.search(e["path"]):
                sc = scrape_candidates[ip]
                sc["hits"] += 1
                sc["paths"][e["path"]] += 1
                if 200 <= e["status"] <= 299:
                    sc["ok"] += 1
                sc["bytes"].append(e["bytes"])
    # pick best “email scrape section” from top IPs: most identity hits
    inferred_section = None
    best = None
    for ip, sc in scrape_candidates.items():
        if sc["hits"] == 0:
            continue
        # choose most-hit identity path for that ip
        path, cnt = sc["paths"].most_common(1)[0]
        metric = (sc["hits"], sc["ok"], sum(sc["bytes"]) / max(1, len(sc["bytes"])))
        if best is None or metric > best:
            best = metric
            inferred_section = path

    # --- Build report ---
    lines = []
    lines.append("# Web Log Recon Report\n")
    lines.append(f"- Files read: **{files_read}**")
    lines.append(f"- Parsed events: **{len(events)}**")
    lines.append(f"- Parse failures (non-matching lines): **{parse_fail}**\n")

    lines.append("## Top suspicious IPs (auto-scored)\n")
    if not ip_scores:
        lines.append(f"No IP exceeded --min-req {args.min_req}. Try lowering it.\n")
    else:
        lines.append("| Rank | IP | Score | Requests |\n|---:|---|---:|---:|")
        for i, (score, ip) in enumerate(ip_scores[:args.top], 1):
            lines.append(f"| {i} | {ip} | {score:.2f} | {len(by_ip[ip])} |")
        lines.append("")

    lines.append("## Attacker tools (by first appearance in logs)\n")
    if tools_ordered:
        for name, ts in tools_ordered:
            lines.append(f"- **{name}** — first seen: {ts.isoformat()}")
    else:
        lines.append("- No tool fingerprints found in User-Agent fields.")
    lines.append("")

    lines.append("## Likely vulnerable SQLi endpoints (ranked)\n")
    if endpoint_rank:
        lines.append("| Rank | Endpoint | Score | SQLi hits | SQLi+500 | Unique payloads |\n|---:|---|---:|---:|---:|---:|")
        for i, (score, ep, st) in enumerate(endpoint_rank[:10], 1):
            lines.append(f"| {i} | `{ep}` | {score} | {st['sqli_hits']} | {st['sqli_500']} | {len(st['payloads'])} |")
        lines.append("")
        # show examples for top endpoint
        top_ep = endpoint_rank[0][1]
        ex = endpoint_rank[0][2]["examples"]
        lines.append(f"### Example SQLi requests targeting `{top_ep}`")
        for u in ex:
            lines.append(f"- `{u}`")
        lines.append("")
    else:
        lines.append("- No SQLi signatures found.\n")

    lines.append("## Inferred section used for email scraping\n")
    if inferred_section:
        lines.append(f"- Most likely section: **`{inferred_section}`** (identity/user-related endpoint repeatedly hit by top suspicious IPs)\n")
    else:
        lines.append("- Could not infer a scraping section (no strong identity endpoint hits among top suspicious IPs).\n")

    lines.append("## Per-IP movement (top suspicious IPs)\n")
    for ip in top_ips:
        evs = by_ip[ip]
        lines.append(f"### {ip}")
        lines.append(f"- Requests: **{len(evs)}**")
        st = Counter(e["status"] for e in evs)
        lines.append(f"- Status codes: " + ", ".join(f"{k}:{v}" for k, v in sorted(st.items())))
        # top paths
        top_paths = Counter(e["path"] for e in evs).most_common(10)
        lines.append("- Top endpoints:")
        for p, c in top_paths:
            lines.append(f"  - `{p}` — {c}")
        # abnormal examples
        ab = [e for e in evs if e["abnormal"]]
        if ab:
            lines.append("- Abnormal query examples:")
            for e in ab[:8]:
                lines.append(f"  - **{','.join(e['abnormal'])}** `{e['url']}` (status {e['status']})")
        lines.append("")

    report_md = "\n".join(lines)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report_md)

    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        # remove ts_obj before json
        out_events = []
        for e in events:
            e2 = dict(e)
            e2.pop("ts_obj", None)
            out_events.append(e2)
        out = {
            "summary": {
                "files_read": files_read,
                "parsed_events": len(events),
                "parse_failures": parse_fail,
                "top_suspicious_ips": top_ips,
                "tools_by_first_seen": [(k, v.isoformat()) for k, v in tools_ordered],
                "top_sqli_endpoints": [ep for _, ep, _ in endpoint_rank[:10]],
                "inferred_scrape_section": inferred_section,
            },
            "events": out_events[:20000],  # cap to keep file reasonable
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)

    print(f"[+] Wrote markdown report: {args.out}")
    if args.json_out:
        print(f"[+] Wrote json report: {args.json_out}")

if __name__ == "__main__":
    main()
