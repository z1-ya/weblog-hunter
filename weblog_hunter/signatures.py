"""
Attack signatures and detection patterns for weblog-hunter
"""

import re
from typing import List, Optional

# SQL Injection patterns
SQLI_PATTERNS = re.compile(
    r"(?i)(\bunion\b|\bselect\b|\binformation_schema\b|\bsleep\s*\(|\bbenchmark\s*\("
    r"|--|/\*|\*/|%27|'|\bor\s+1=1\b|\band\s+1=1\b)"
)

# Path traversal / LFI patterns
TRAVERSAL_PATTERNS = re.compile(
    r"(?i)(\.\./|%2e%2e%2f|%2e%2e\\|/etc/passwd|win\.ini|\.\.\\|%5c%2e%2e)"
)

# Cross-Site Scripting (XSS) patterns
XSS_PATTERNS = re.compile(
    r"(?i)(<script|%3cscript|onerror=|onload=|alert\s*\(|javascript:|<iframe|"
    r"<img\s+src|eval\s*\(|<svg|onmouseover=)"
)

# Server-Side Request Forgery (SSRF) patterns
SSRF_PATTERNS = re.compile(
    r"(?i)(https?://|%3a%2f%2f|169\.254\.169\.254|localhost|127\.0\.0\.1|"
    r"0\.0\.0\.0|::1|\[::1\]|metadata\.google\.internal)"
)

# Command Injection patterns
CMDI_PATTERNS = re.compile(
    r"(?i)(\bcat\b|\bwget\b|\bcurl\b|;|\|\||&&|\b/bin/sh\b|\bpowershell\b|"
    r"\bexec\b|\bsystem\b|\$\(|\`|<\(|>\()"
)

# Remote Code Execution (RCE) patterns
RCE_PATTERNS = re.compile(
    r"(?i)(eval\(|exec\(|system\(|passthru\(|shell_exec\(|phpinfo\(|"
    r"assert\(|preg_replace\s*\(.*\/e[\"']?\s*,|create_function\()"
)

# XML External Entity (XXE) patterns
XXE_PATTERNS = re.compile(
    r"(?i)(<!ENTITY\s+\w+\s+SYSTEM|<!DOCTYPE.*ENTITY|SYSTEM\s+[\"']file:|SYSTEM\s+[\"']http)"
)

# LDAP Injection patterns
LDAP_PATTERNS = re.compile(r"(?i)(\*\)|\(\||&\(|\|\()")

# NoSQL Injection patterns
NOSQL_PATTERNS = re.compile(r"(?i)(\$ne|\$gt|\$lt|\$where|\$regex|\[\$)")

# Scanner/Tool User-Agent patterns
SCANNER_PATTERNS = [
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
    ("burpsuite", re.compile(r"(?i)\bburp\b")),
    ("zaproxy", re.compile(r"(?i)\bzap\b")),
    ("wpscan", re.compile(r"(?i)\bwpscan\b")),
    ("metasploit", re.compile(r"(?i)\bmetasploit\b")),
    ("nuclei", re.compile(r"(?i)\bnuclei\b")),
    ("sqlninja", re.compile(r"(?i)\bsqlninja\b")),
    ("havij", re.compile(r"(?i)\bhavij\b")),
    ("httperf", re.compile(r"(?i)\bhttperf\b")),
    ("jmeter", re.compile(r"(?i)\bjmeter\b")),
]

# Endpoint hints for specific attack types
IDENTITY_HINTS = re.compile(
    r"(?i)(whoami|profile|account|user|users|customer|customers|admin|member)"
)

LOGIN_HINTS = re.compile(r"(?i)(login|signin|auth|token|session|oauth|sso|authenticate)")

EMAIL_HINTS = re.compile(r"(?i)(email|mail|contact)")

API_HINTS = re.compile(r"(?i)(/api/|/rest/|/graphql|/v\d+/|\.json|\.xml)")

# Brute force patterns - multiple failed login attempts
BRUTE_FORCE_STATUS_CODES = {401, 403}

# Credential stuffing - detecting patterns in usernames
CREDENTIAL_STUFFING_PARAMS = re.compile(r"(?i)(username|user|email|login|account)=([^&\s]+)")

# Bot detection patterns
BOT_USER_AGENTS = re.compile(
    r"(?i)(bot|crawler|spider|scraper|slurp|googlebot|bingbot|"
    r"yandexbot|baiduspider|facebookexternalhit|twitterbot)"
)

# DDoS patterns - indicators in requests
DDOS_INDICATORS = re.compile(r"(?i)(slowloris|rudy|ddos|flood)")

# Data exfiltration - sensitive endpoints
SENSITIVE_ENDPOINTS = re.compile(
    r"(?i)(/export|/download|/backup|/dump|/database|/admin/users|" r"/api/users|\.sql|\.db|\.bak)"
)

# Session hijacking indicators
SESSION_PARAMS = re.compile(r"(?i)(session|sessionid|sid|jsessionid|phpsessid)")


class SignatureDetector:
    """Detects various attack signatures in URLs and user agents"""

    @staticmethod
    def detect_attacks(url: str) -> List[str]:
        """
        Detect attack signatures in a URL

        Args:
            url: The URL to analyze (can be URL-encoded)

        Returns:
            List of detected attack types
        """
        from urllib.parse import unquote

        decoded = unquote(url)
        detected = []

        if SQLI_PATTERNS.search(decoded):
            detected.append("SQLi")
        if TRAVERSAL_PATTERNS.search(decoded):
            detected.append("Traversal/LFI")
        if XSS_PATTERNS.search(decoded):
            detected.append("XSS")
        if SSRF_PATTERNS.search(decoded):
            detected.append("SSRF")
        if CMDI_PATTERNS.search(decoded):
            detected.append("CMDi/Shell")
        if RCE_PATTERNS.search(decoded):
            detected.append("RCE")
        if XXE_PATTERNS.search(decoded):
            detected.append("XXE")
        if LDAP_PATTERNS.search(decoded):
            detected.append("LDAP Injection")
        if NOSQL_PATTERNS.search(decoded):
            detected.append("NoSQL Injection")

        return detected

    @staticmethod
    def detect_tool(user_agent: str) -> Optional[str]:
        """
        Detect scanning/attack tools from User-Agent

        Args:
            user_agent: The User-Agent string

        Returns:
            Tool name if detected, None otherwise
        """
        if not user_agent:
            return None

        for name, pattern in SCANNER_PATTERNS:
            if pattern.search(user_agent):
                return name

        # Classify as browser if it looks like one
        if any(browser in user_agent for browser in ["Mozilla/", "Chrome/", "Safari/", "Firefox/"]):
            return "browser"

        # Check for bots
        if BOT_USER_AGENTS.search(user_agent):
            return "bot"

        return None

    @staticmethod
    def is_bot_user_agent(user_agent: str) -> bool:
        """Check if user agent appears to be a bot"""
        return bool(BOT_USER_AGENTS.search(user_agent))

    @staticmethod
    def is_sensitive_endpoint(path: str) -> bool:
        """Check if endpoint deals with sensitive data"""
        return bool(SENSITIVE_ENDPOINTS.search(path))

    @staticmethod
    def has_session_parameter(url: str) -> bool:
        """Check if URL contains session parameters"""
        return bool(SESSION_PARAMS.search(url))

    @staticmethod
    def is_api_endpoint(path: str) -> bool:
        """Check if endpoint is an API endpoint"""
        return bool(API_HINTS.search(path))
