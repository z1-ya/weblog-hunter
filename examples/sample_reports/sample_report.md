# Web Log Recon Report

- Files read: **1**
- Parsed events: **14**
- Parse failures (non-matching lines): **6**

## Top suspicious IPs (auto-scored)

| Rank | IP | Score | Requests |
|---:|---|---:|---:|
| 1 | 10.0.0.1 | 0.19 | 4 |
| 2 | 192.168.1.102 | 0.15 | 2 |
| 3 | 192.168.1.104 | 0.12 | 2 |
| 4 | 192.168.1.103 | 0.06 | 1 |
| 5 | 192.168.1.100 | 0.05 | 2 |
| 6 | 203.0.113.50 | 0.04 | 3 |

## Attacker tools (by first appearance in logs)

- **browser** — first seen: 2026-01-17T10:00:00+00:00
- **curl** — first seen: 2026-01-17T10:00:25+00:00
- **python-requests** — first seen: 2026-01-17T10:00:45+00:00

## Likely vulnerable SQLi endpoints (ranked)

- No SQLi signatures found.

## Inferred section used for email scraping

- Most likely section: **`/api/users`** (identity/user-related endpoint repeatedly hit by top suspicious IPs)

## Per-IP movement (top suspicious IPs)

### 10.0.0.1
- Requests: **4**
- Status codes: 200:1, 401:3
- Top endpoints:
  - `/login` — 3
  - `/api/users` — 1

### 192.168.1.102
- Requests: **2**
- Status codes: 404:1, 500:1
- Top endpoints:
  - `/../../etc/passwd` — 1
  - `/index.php` — 1
- Abnormal query examples:
  - **Traversal/LFI** `/../../etc/passwd` (status 404)
  - **Traversal/LFI** `/index.php?file=../../../etc/passwd` (status 500)

### 192.168.1.104
- Requests: **2**
- Status codes: 200:2
- Top endpoints:
  - `/proxy.php` — 1
  - `/fetch.php` — 1
- Abnormal query examples:
  - **SSRF** `/proxy.php?url=http://169.254.169.254/latest/meta-data/` (status 200)
  - **SSRF** `/fetch.php?url=http://localhost:8080/admin` (status 200)

### 192.168.1.103
- Requests: **1**
- Status codes: 200:1
- Top endpoints:
  - `/search.php` — 1
- Abnormal query examples:
  - **XSS** `/search.php?q=<script>alert(1)</script>` (status 200)

### 192.168.1.100
- Requests: **2**
- Status codes: 200:2
- Top endpoints:
  - `/index.php` — 1
  - `/login.php` — 1

### 203.0.113.50
- Requests: **3**
- Status codes: 200:3
- Top endpoints:
  - `/` — 1
  - `/about.html` — 1
  - `/contact.html` — 1
