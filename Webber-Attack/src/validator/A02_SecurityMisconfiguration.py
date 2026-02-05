"""
A02:2025 - Security Misconfiguration Validator
==============================================
OWASP Top 10 2025 - A02 (was A05 in 2021)

Security Misconfiguration rose from #5 to #2 in 2025.
Every tested application showed some form of misconfiguration.
Over 719,000 CWEs mapped including CWE-16 (Configuration) and CWE-611 (XXE).

Validates:
- Default credentials / accounts
- Directory listing enabled
- Verbose error messages / Stack traces exposed
- Debug mode enabled
- Exposed sensitive files (.git, .env, .htaccess, backups, configs)
- Unnecessary HTTP methods enabled
- Missing security headers (INFORMATIONAL - doesn't count as exploit)
- CORS misconfiguration (moved to A01 for access control, but config aspect here)
- Cloud storage misconfiguration (S3, Azure Blob, GCS)
- Admin interfaces exposed
- Sample/test applications not removed
- Improper error handling revealing system info
"""

import re
import urllib.parse
from typing import Optional, Dict, List

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)


class A02_MisconfigValidator(BaseValidator):
    """
    Validates Security Misconfiguration vulnerabilities (OWASP 2025 A02).
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "DIRECTORY" in vuln_subtype or "LISTING" in vuln_subtype:
            return await self._validate_directory_listing(vuln)
        
        elif "HEADER" in vuln_subtype:
            # Headers are INFORMATIONAL - valid findings but don't count as exploits
            return await self._validate_missing_headers(vuln)
        
        elif "ERROR" in vuln_subtype or "VERBOSE" in vuln_subtype or "STACK" in vuln_subtype:
            return await self._validate_verbose_errors(vuln)
        
        elif "DEFAULT" in vuln_subtype or ("CREDENTIAL" in vuln_subtype and "EXPOSED" not in vuln_subtype):
            return await self._validate_default_credentials(vuln)
        
        elif "DEBUG" in vuln_subtype:
            return await self._validate_debug_mode(vuln)
        
        elif any(x in vuln_subtype for x in ["GIT", "ENV", "HTACCESS", "CONFIG", "EXPOSED", "SENSITIVE"]):
            return await self._validate_exposed_files(vuln)
        
        elif "BACKUP" in vuln_subtype:
            return await self._validate_backup_files(vuln)
        
        elif "METHOD" in vuln_subtype or "HTTP" in vuln_subtype:
            return await self._validate_http_methods(vuln)
        
        elif "CLOUD" in vuln_subtype or "S3" in vuln_subtype or "BUCKET" in vuln_subtype:
            return await self._validate_cloud_misconfig(vuln)
        
        elif "ADMIN" in vuln_subtype or "PANEL" in vuln_subtype:
            return await self._validate_admin_exposure(vuln)
        
        elif "SAMPLE" in vuln_subtype or "TEST" in vuln_subtype or "EXAMPLE" in vuln_subtype:
            return await self._validate_sample_files(vuln)
        
        else:
            return await self._validate_generic_misconfig(vuln)
    
    # =========================================================================
    # DIRECTORY LISTING
    # =========================================================================
    
    async def _validate_directory_listing(self, vuln: VulnReport) -> ValidationReport:
        """Check for directory listing enabled - allows attackers to enumerate files"""
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            dir_listing_indicators = [
                (r"Index of /", "Apache/nginx index"),
                (r"Directory listing for", "Python SimpleHTTPServer"),
                (r"<title>Index of", "Apache index"),
                (r"Parent Directory</a>", "Parent directory link"),
                (r'\[DIR\]', "Directory marker"),
                (r"<h1>Index of", "H1 index header"),
                (r"Directory Listing", "Generic directory listing"),
                (r"<pre>.*<a href=", "Pre-formatted directory"),
                (r"<a href=\"\?C=N;O=D\">", "Apache sorting links"),
                (r"to parent directory", "IIS parent directory"),
                (r"<br>\s*<br>\s*<a href=", "Directory links pattern"),
                (r"<title>listing directory", "Node.js/serve-static directory"),  # ← For Juice Shop!
                (r"listing directory /", "Generic listing directory"),
                (r'<ul li.*path', "Styled directory listing"),  # Juice Shop uses <ul><li> structure
                (r'"path".*"stats"', "JSON-style directory listing")
            ]
            
            for pattern, description in dir_listing_indicators:
                if re.search(pattern, body, re.I | re.S):
                    # Extract some file names as evidence
                    files = re.findall(r'<a href="([^"]+)"', body)
                    files = [f for f in files if not f.startswith('?') and f != '../'][:5]
                    
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Directory listing enabled ({description}). Files visible: {', '.join(files[:3])}",
                        validation_method="Directory Listing",
                        details={"indicator": description, "sample_files": files}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No directory listing detected",
                validation_method="Directory Listing"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Directory Listing"
            )
    
    # =========================================================================
    # MISSING SECURITY HEADERS (INFORMATIONAL)
    # =========================================================================
    
    async def _validate_missing_headers(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for missing security headers.
        
        IMPORTANT: Returns INFORMATIONAL - these are valid findings but should NOT
        count as "solved challenges" in Juice Shop or real exploits.
        Missing headers are configuration weaknesses, not direct vulnerabilities.
        """
        try:
            _, _, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            security_headers = {
                "x-frame-options": ("Clickjacking protection", "HIGH"),
                "x-content-type-options": ("MIME sniffing protection", "MEDIUM"),
                "content-security-policy": ("XSS/injection protection", "HIGH"),
                "strict-transport-security": ("HTTPS enforcement (HSTS)", "HIGH"),
                "x-xss-protection": ("Legacy XSS filter", "LOW"),
                "referrer-policy": ("Referrer leakage control", "MEDIUM"),
                "permissions-policy": ("Browser feature control", "LOW"),
                "cross-origin-opener-policy": ("Cross-origin isolation", "MEDIUM"),
                "cross-origin-resource-policy": ("Resource sharing control", "MEDIUM"),
            }
            
            missing = []
            missing_high = []
            
            for header, (description, severity) in security_headers.items():
                if header not in headers_lower:
                    missing.append(f"{header}")
                    if severity == "HIGH":
                        missing_high.append(header)
            
            if missing:
                # Consolidate ALL missing headers into ONE informational finding
                return ValidationReport(
                    result=ValidationResult.INFORMATIONAL,
                    confidence=1.0,
                    evidence=f"Missing {len(missing)} security headers: {', '.join(missing[:5])}{'...' if len(missing) > 5 else ''}",
                    validation_method="Missing Security Headers",
                    details={
                        "missing_headers": missing,
                        "high_priority": missing_high,
                        "total_missing": len(missing)
                    },
                    is_informational=True  # Does NOT count as solved challenge
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="All security headers present",
                validation_method="Missing Security Headers"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Missing Security Headers"
            )
    
    # =========================================================================
    # VERBOSE ERRORS / STACK TRACES
    # =========================================================================
    
    async def _validate_verbose_errors(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for verbose error messages / stack traces.
        Reveals internal paths, technology stack, and potential vulnerabilities.
        """
        try:
            # ─────────────────────────────────────────────────────────────
            # FIRST: Check if the endpoint ALREADY returns verbose errors
            # Agent may have hit an endpoint that naturally returns 500
            # ─────────────────────────────────────────────────────────────
            if vuln.endpoint:
                endpoint = vuln.endpoint
                if not endpoint.startswith("http"):
                    endpoint = f"{self.target_url}/{endpoint.lstrip('/')}"
                
                # Re-request the exact endpoint
                status, body, _ = await self._request(vuln.method or "GET", endpoint, headers=vuln.headers)
                
                # If error status, check for verbose patterns
                if status >= 400:
                    verbose_patterns = [
                        (r"Traceback \(most recent call last\)", "Python traceback"),
                        (r"at .+\.js:\d+", "JavaScript stack trace"),
                        (r"at .+\.java:\d+", "Java stack trace"),
                        (r"at .+\.php:\d+", "PHP stack trace"),
                        (r"SQLSTATE\[", "SQL error"),
                        (r"<b>Fatal error</b>:", "PHP fatal error"),
                        (r"/var/www/", "Path disclosure"),
                        (r"/home/\w+/", "Linux path"),
                        (r"C:\\", "Windows path"),
                        (r"Django Version:", "Django debug"),
                        (r"Laravel.*Exception", "Laravel exception"),
                        (r"TypeError:", "Type error"),
                        (r"ReferenceError:", "Reference error"),
                        (r"NullPointerException", "Java NPE"),
                    ]
                    
                    for pattern, description in verbose_patterns:
                        match = re.search(pattern, body, re.I)
                        if match:
                            start = max(0, match.start() - 50)
                            end = min(len(body), match.end() + 100)
                            snippet = body[start:end].replace('\n', ' ')[:150]
                            
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=1.0,
                                evidence=f"Verbose error exposed ({description}): {snippet}...",
                                validation_method="Verbose Errors",
                                details={"error_type": description, "status": status}
                            )
            
            # Payloads to trigger errors
            error_triggers = [
                ("'", "SQL quote"),
                ("{{", "Template syntax"),
                ("<", "XML/HTML"),
                ("/../../../../etc/passwd", "Path traversal"),
                ("%00", "Null byte"),
                ("[]", "Array notation"),
                ("-1", "Negative ID"),
                ("99999999", "Large number"),
                ("undefined", "Undefined value"),
                ("null", "Null value"),
            ]
            
            verbose_patterns = [
                # Stack traces
                (r"Traceback \(most recent call last\)", "Python traceback"),
                (r"at .+\.java:\d+", "Java stack trace"),
                (r"at .+\.cs:\d+", "C# stack trace"),
                (r"at .+\.php:\d+", "PHP stack trace"),
                (r"at .+\.js:\d+", "JavaScript stack trace"),
                (r"at .+\.rb:\d+", "Ruby stack trace"),
                (r"at .+\.go:\d+", "Go stack trace"),
                
                # Framework errors
                (r"Django Version:", "Django debug"),
                (r"Flask Debug", "Flask debug"),
                (r"Laravel.*Exception", "Laravel exception"),
                (r"Symfony\\Component", "Symfony exception"),
                (r"Rails\.root", "Rails debug info"),
                (r"Express\s+\d+\.\d+", "Express.js error"),
                (r"ASP\.NET.*Error", "ASP.NET error"),
                (r"Spring Framework", "Spring error"),
                
                # Database errors
                (r"SQL syntax.*MySQL", "MySQL syntax error"),
                (r"PostgreSQL.*ERROR", "PostgreSQL error"),
                (r"ORA-\d{5}", "Oracle error"),
                (r"SQLSTATE\[", "PDO SQL error"),
                (r"Microsoft.*SQL.*Server", "MSSQL error"),
                (r"sqlite3\.OperationalError", "SQLite error"),
                (r"MongoDB.*Error", "MongoDB error"),
                
                # Path disclosure
                (r"/var/www/", "Linux web path"),
                (r"/home/\w+/", "Linux home path"),
                (r"/usr/local/", "Linux local path"),
                (r"C:\\inetpub\\", "Windows IIS path"),
                (r"C:\\Users\\", "Windows user path"),
                (r"D:\\www\\", "Windows web path"),
                
                # PHP specific
                (r"<b>Fatal error</b>:", "PHP fatal error"),
                (r"<b>Warning</b>:", "PHP warning"),
                (r"<b>Notice</b>:", "PHP notice"),
                (r"<b>Parse error</b>:", "PHP parse error"),
                (r"Undefined (?:variable|index|offset)", "PHP undefined"),
                
                # Generic
                (r"Exception in thread", "Java thread exception"),
                (r"NullPointerException", "Java NPE"),
                (r"TypeError:", "Type error"),
                (r"ReferenceError:", "Reference error"),
                (r"SyntaxError:", "Syntax error"),
                (r"Internal Server Error.*stack", "Server error with stack"),
            ]
            
            for trigger, trigger_desc in error_triggers:
                # Try different injection points
                test_urls = []
                
                # Query parameter
                if "?" in vuln.endpoint:
                    base, params = vuln.endpoint.split("?", 1)
                    test_urls.append(f"{base}?{params}&test={urllib.parse.quote(trigger)}")
                else:
                    test_urls.append(f"{vuln.endpoint}?test={urllib.parse.quote(trigger)}")
                
                # Path injection
                test_urls.append(f"{vuln.endpoint}/{urllib.parse.quote(trigger)}")
                
                for test_url in test_urls:
                    try:
                        status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                        
                        for pattern, description in verbose_patterns:
                            match = re.search(pattern, body, re.I)
                            if match:
                                # Extract snippet around the match
                                start = max(0, match.start() - 50)
                                end = min(len(body), match.end() + 100)
                                snippet = body[start:end].replace('\n', ' ')[:150]
                                
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"Verbose error exposed ({description}): ...{snippet}...",
                                    validation_method="Verbose Errors",
                                    details={
                                        "error_type": description,
                                        "trigger": trigger_desc,
                                        "pattern": pattern
                                    }
                                )
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No verbose errors detected",
                validation_method="Verbose Errors"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Verbose Errors"
            )
    
    # =========================================================================
    # DEFAULT CREDENTIALS
    # =========================================================================
    
    async def _validate_default_credentials(self, vuln: VulnReport) -> ValidationReport:
        """Check for default/common credentials on login forms"""
        try:
            default_creds = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("admin", "admin123"),
                ("admin", ""),
                ("administrator", "administrator"),
                ("root", "root"),
                ("root", "toor"),
                ("root", "password"),
                ("test", "test"),
                ("user", "user"),
                ("user", "password"),
                ("guest", "guest"),
                ("demo", "demo"),
                ("admin@admin.com", "admin"),
                ("admin", "P@ssw0rd"),
            ]
            
            # Try to find login endpoint if not specified
            login_endpoints = [vuln.endpoint]
            if "/login" not in vuln.endpoint.lower():
                base = vuln.endpoint.rstrip("/")
                login_endpoints.extend([
                    f"{base}/login",
                    f"{base}/admin",
                    f"{base}/admin/login",
                    f"{base}/user/login",
                    f"{base}/auth/login",
                ])
            
            for endpoint in login_endpoints:
                for username, password in default_creds:
                    # Try form-based auth
                    form_payloads = [
                        f"username={username}&password={password}",
                        f"user={username}&pass={password}",
                        f"email={username}&password={password}",
                        f"login={username}&password={password}",
                    ]
                    
                    for payload in form_payloads:
                        try:
                            status, body, resp_headers = await self._request(
                                "POST", endpoint,
                                headers={
                                    **vuln.headers,
                                    "Content-Type": "application/x-www-form-urlencoded"
                                },
                                data=payload
                            )
                            
                            # Check for successful login indicators
                            set_cookie = resp_headers.get("Set-Cookie", "").lower()
                            location = resp_headers.get("Location", "").lower()
                            
                            # Session cookie set
                            has_session = any(s in set_cookie for s in 
                                            ["session", "auth", "token", "jwt", "sid", "logged"])
                            
                            # Redirect to dashboard/admin
                            redirect_success = any(s in location for s in 
                                                 ["dashboard", "admin", "home", "profile", "welcome"])
                            
                            # Response body indicators (but NOT error messages)
                            body_lower = body.lower()
                            login_success = (
                                ("welcome" in body_lower or "dashboard" in body_lower or 
                                 "logout" in body_lower or "profile" in body_lower) and
                                not any(err in body_lower for err in 
                                       ["invalid", "incorrect", "failed", "error", "wrong"])
                            )
                            
                            if has_session or redirect_success or (status in (302, 303) and login_success):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"Default credentials accepted: {username}:{password if password else '(empty)'}",
                                    validation_method="Default Credentials",
                                    details={
                                        "username": username,
                                        "endpoint": endpoint,
                                        "has_session_cookie": has_session
                                    }
                                )
                        except:
                            continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Default credentials not accepted",
                validation_method="Default Credentials"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Default Credentials"
            )
    
    # =========================================================================
    # DEBUG MODE
    # =========================================================================
    
    async def _validate_debug_mode(self, vuln: VulnReport) -> ValidationReport:
        """Check for debug/development mode enabled in production"""
        try:
            status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            debug_indicators = [
                # Framework debug modes
                (r"DEBUG\s*=\s*True", "Django DEBUG=True"),
                (r"FLASK_DEBUG\s*=\s*1", "Flask debug mode"),
                (r"Werkzeug Debugger", "Werkzeug interactive debugger"),
                (r"Laravel.*APP_DEBUG.*true", "Laravel debug mode"),
                (r"Rails\.env.*development", "Rails development mode"),
                (r"Express.*NODE_ENV.*development", "Express development mode"),
                (r"Symfony.*kernel\.debug.*true", "Symfony debug mode"),
                (r"ASP\.NET.*customErrors.*Off", "ASP.NET custom errors off"),
                
                # Debug panels/toolbars
                (r"django-debug-toolbar", "Django Debug Toolbar"),
                (r"Symfony.*Profiler", "Symfony Web Profiler"),
                (r"__debug__/", "Debug URL path"),
                (r"_debugbar", "Laravel Debugbar"),
                (r"phpinfo\(\)", "phpinfo() exposed"),
                
                # Debug output
                (r"<!--.*DEBUG", "HTML debug comment"),
                (r"console\.(?:log|debug|trace)\(", "JavaScript console debug"),
                (r"var_dump\(", "PHP var_dump"),
                (r"print_r\(", "PHP print_r"),
                (r"dd\(", "Laravel dd()"),
                
                # Development indicators
                (r"localhost:\d{4}", "Localhost reference"),
                (r"127\.0\.0\.1:\d{4}", "Loopback reference"),
                (r"TODO:|FIXME:|HACK:|XXX:", "Dev comments"),
            ]
            
            for pattern, description in debug_indicators:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Debug mode enabled: {description}",
                        validation_method="Debug Mode",
                        details={"indicator": description}
                    )
            
            # Check for debug headers
            debug_headers = {
                "x-debug-token": "Symfony debug token",
                "x-debug-token-link": "Symfony profiler link",
                "x-debug": "Generic debug header",
                "x-aspnet-version": "ASP.NET version disclosure",
                "x-aspnetmvc-version": "ASP.NET MVC version",
                "x-powered-by": "Technology disclosure",
            }
            
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for header, description in debug_headers.items():
                if header in headers_lower:
                    if header == "x-powered-by":
                        # Only flag if it reveals specific version
                        value = headers_lower[header]
                        if re.search(r'\d+\.\d+', value):
                            return ValidationReport(
                                result=ValidationResult.HIGH,
                                confidence=0.85,
                                evidence=f"Version disclosure via {header}: {value}",
                                validation_method="Debug Mode",
                                details={"header": header, "value": value}
                            )
                    else:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.95,
                            evidence=f"Debug header present: {header}",
                            validation_method="Debug Mode",
                            details={"header": header}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Debug mode not detected",
                validation_method="Debug Mode"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Debug Mode"
            )
    
    # =========================================================================
    # EXPOSED SENSITIVE FILES
    # =========================================================================
    
    async def _validate_exposed_files(self, vuln: VulnReport) -> ValidationReport:
        """Check for exposed sensitive configuration files"""
        try:
            # ── FIX: If specific endpoint provided, ONLY check that file ──
            # Don't run shotgun of 50 files and attach wrong evidence.
            if vuln.endpoint and not vuln.endpoint.endswith("/"):
                # Specific file requested - validate ONLY that file
                endpoint = vuln.endpoint
                if not endpoint.startswith("http"):
                    endpoint = f"{self.target_url}/{endpoint.lstrip('/')}"
                
                status, body, _ = await self._request("GET", endpoint, headers=vuln.headers)
                
                if status == 200 and len(body) > 0:
                    # File exists - check if it contains sensitive patterns
                    sensitive_patterns = {
                        ".env": r"(?:DB_|API_|SECRET|PASSWORD|KEY|TOKEN|AWS_)=",
                        ".git": r"ref:|^\[core\]",
                        "phpinfo": r"phpinfo\(\)|PHP Version",
                        ".sql": r"CREATE TABLE|INSERT INTO",
                        "config": r"password|secret|key",
                    }
                    
                    # Find matching pattern for this file type
                    for file_type, pattern in sensitive_patterns.items():
                        if file_type in endpoint.lower():
                            if re.search(pattern, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"Sensitive file exposed: {endpoint} (contains {file_type} patterns)",
                                    validation_method="Exposed Sensitive Files",
                                    details={"file": endpoint}
                                )
                            else:
                                # File exists but no sensitive patterns
                                return ValidationReport(
                                    result=ValidationResult.REJECTED,
                                    confidence=0.0,
                                    evidence=f"File exists but contains no sensitive patterns: {endpoint}",
                                    validation_method="Exposed Sensitive Files"
                                )
                    
                    # File exists but unknown type - cautiously confirm
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"Potentially sensitive file accessible: {endpoint}",
                        validation_method="Exposed Sensitive Files"
                    )
                else:
                    # File doesn't exist or error
                    return ValidationReport(
                        result=ValidationResult.REJECTED,
                        confidence=0.0,
                        evidence=f"File not accessible: {endpoint} (HTTP {status})",
                        validation_method="Exposed Sensitive Files"
                    )
            
            # ── Original shotgun scan (only if no specific endpoint) ──
            # Get base URL
            base_url = vuln.endpoint.rstrip("/") if vuln.endpoint else self.target_url
            if "?" in base_url:
                base_url = base_url.split("?")[0]
            # Get root
            parts = base_url.split("/")
            if len(parts) >= 3:
                root_url = "/".join(parts[:3])
            else:
                root_url = base_url
            
            # Sensitive files to check: (path, validation_pattern, description, severity)
            sensitive_files = [
                # Version Control
                ("/.git/config", r"\[core\]|\[remote", ".git config exposed", "CRITICAL"),
                ("/.git/HEAD", r"ref: refs/", ".git HEAD exposed", "CRITICAL"),
                ("/.git/index", None, ".git index exposed", "CRITICAL"),
                ("/.svn/entries", r"svn|dir", ".svn exposed", "HIGH"),
                ("/.svn/wc.db", None, ".svn database exposed", "HIGH"),
                ("/.hg/hgrc", r"\[paths\]", "Mercurial config exposed", "HIGH"),
                
                # Environment files
                ("/.env", r"(?:DB_|API_|SECRET|PASSWORD|KEY|TOKEN|AWS_)=", ".env file exposed", "CRITICAL"),
                ("/.env.local", r"(?:DB_|API_|SECRET|PASSWORD)=", ".env.local exposed", "CRITICAL"),
                ("/.env.production", r"(?:DB_|API_|SECRET|PASSWORD)=", ".env.production exposed", "CRITICAL"),
                ("/.env.backup", r"(?:DB_|API_|SECRET|PASSWORD)=", ".env.backup exposed", "CRITICAL"),
                ("/config/.env", r"(?:DB_|API_|SECRET|PASSWORD)=", "config/.env exposed", "CRITICAL"),
                
                # Server configs
                ("/.htaccess", r"RewriteRule|Deny|Allow|Auth", ".htaccess exposed", "HIGH"),
                ("/.htpasswd", r":", ".htpasswd exposed", "CRITICAL"),
                ("/web.config", r"<configuration", "web.config exposed", "HIGH"),
                ("/nginx.conf", r"server\s*{|location", "nginx.conf exposed", "HIGH"),
                ("/httpd.conf", r"ServerRoot|DocumentRoot", "httpd.conf exposed", "HIGH"),
                
                # Application configs
                ("/config.php", r"<\?php|\$.*=", "config.php exposed", "HIGH"),
                ("/config.inc.php", r"<\?php|\$.*=", "config.inc.php exposed", "HIGH"),
                ("/settings.py", r"SECRET_KEY|DATABASE", "Django settings exposed", "CRITICAL"),
                ("/config/database.yml", r"adapter:|password:", "database.yml exposed", "CRITICAL"),
                ("/application.properties", r"spring\.|password=", "Spring config exposed", "HIGH"),
                ("/application.yml", r"spring:|password:", "Spring YAML config exposed", "HIGH"),
                ("/appsettings.json", r'"ConnectionStrings"|"Password"', "appsettings.json exposed", "HIGH"),
                
                # Package files (may reveal dependencies)
                ("/package.json", r'"dependencies"|"devDependencies"', "package.json exposed", "MEDIUM"),
                ("/composer.json", r'"require"|"autoload"', "composer.json exposed", "MEDIUM"),
                ("/Gemfile", r"gem ['\"]|source", "Gemfile exposed", "MEDIUM"),
                ("/requirements.txt", r"==|>=", "requirements.txt exposed", "MEDIUM"),
                
                # Debug/Info pages
                ("/phpinfo.php", r"PHP Version|phpinfo\(\)", "phpinfo.php exposed", "HIGH"),
                ("/info.php", r"PHP Version|phpinfo", "info.php exposed", "HIGH"),
                ("/server-status", r"Apache Server Status", "Apache status exposed", "MEDIUM"),
                ("/server-info", r"Apache Server Information", "Apache info exposed", "MEDIUM"),
                
                # Logs
                ("/error.log", r"\[error\]|\[warn\]", "Error log exposed", "HIGH"),
                ("/access.log", r"GET |POST |HTTP/", "Access log exposed", "MEDIUM"),
                ("/debug.log", r"DEBUG|ERROR|WARNING", "Debug log exposed", "HIGH"),
                ("/logs/error.log", r"\[error\]|\[warn\]", "Error log exposed", "HIGH"),
                
                # Database files
                ("/database.sql", r"CREATE TABLE|INSERT INTO", "SQL dump exposed", "CRITICAL"),
                ("/dump.sql", r"CREATE TABLE|INSERT INTO", "SQL dump exposed", "CRITICAL"),
                ("/backup.sql", r"CREATE TABLE|INSERT INTO", "SQL backup exposed", "CRITICAL"),
                ("/db.sqlite", None, "SQLite database exposed", "CRITICAL"),
                ("/database.sqlite", None, "SQLite database exposed", "CRITICAL"),
            ]
            
            for file_path, pattern, description, severity in sensitive_files:
                url = root_url + file_path
                try:
                    status, body, _ = await self._request("GET", url, headers=vuln.headers)
                    
                    if status == 200 and len(body) > 0:
                        # Validate content if pattern provided
                        if pattern is None or re.search(pattern, body, re.I):
                            confidence = 1.0 if severity == "CRITICAL" else 0.95
                            result = ValidationResult.CONFIRMED if severity in ["CRITICAL", "HIGH"] else ValidationResult.HIGH
                            
                            return ValidationReport(
                                result=result,
                                confidence=confidence,
                                evidence=f"{description} at {file_path}",
                                validation_method="Exposed Sensitive Files",
                                details={
                                    "file": file_path,
                                    "severity": severity,
                                    "url": url
                                }
                            )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No exposed sensitive files found",
                validation_method="Exposed Sensitive Files"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Exposed Sensitive Files"
            )
    
    # =========================================================================
    # BACKUP FILES
    # =========================================================================
    
    async def _validate_backup_files(self, vuln: VulnReport) -> ValidationReport:
        """Check for exposed backup files"""
        try:
            base_url = vuln.endpoint.rstrip("/")
            if "?" in base_url:
                base_url = base_url.split("?")[0]
            
            # Extract filename if present
            if "/" in base_url:
                path_parts = base_url.rsplit("/", 1)
                if "." in path_parts[-1]:
                    base_file = path_parts[-1]
                    base_path = path_parts[0]
                else:
                    base_file = None
                    base_path = base_url
            else:
                base_file = None
                base_path = base_url
            
            backup_extensions = [
                ".bak", ".backup", ".old", ".orig", ".copy", ".tmp",
                ".save", ".swp", "~", ".1", ".2", "_backup", "_old",
                ".zip", ".tar", ".tar.gz", ".gz", ".rar"
            ]
            
            # Try backup versions of current file
            if base_file:
                for ext in backup_extensions:
                    url = f"{base_path}/{base_file}{ext}"
                    try:
                        status, body, _ = await self._request("GET", url, headers=vuln.headers)
                        if status == 200 and len(body) > 50:
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.95,
                                evidence=f"Backup file accessible: {base_file}{ext}",
                                validation_method="Backup Files",
                                details={"url": url, "size": len(body)}
                            )
                    except:
                        continue
            
            # Try common backup file names at root
            parts = base_url.split("/")
            root_url = "/".join(parts[:3]) if len(parts) >= 3 else base_url
            
            common_backups = [
                "/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip",
                "/db_backup.sql", "/database_backup.sql", "/backup.sql",
                "/wp-content/backup.zip", "/admin/backup.zip"
            ]
            
            for backup in common_backups:
                url = root_url + backup
                try:
                    status, body, _ = await self._request("GET", url, headers=vuln.headers)
                    if status == 200 and len(body) > 100:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.95,
                            evidence=f"Backup file accessible: {backup}",
                            validation_method="Backup Files",
                            details={"url": url, "size": len(body)}
                        )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No backup files found",
                validation_method="Backup Files"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Backup Files"
            )
    
    # =========================================================================
    # HTTP METHODS
    # =========================================================================
    
    async def _validate_http_methods(self, vuln: VulnReport) -> ValidationReport:
        """Check for dangerous HTTP methods enabled"""
        try:
            # Send OPTIONS request
            status, body, headers = await self._request("OPTIONS", vuln.endpoint, headers=vuln.headers)
            
            allow_header = headers.get("Allow", headers.get("allow", ""))
            
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
            found_dangerous = []
            
            for method in dangerous_methods:
                if method in allow_header.upper():
                    found_dangerous.append(method)
            
            if found_dangerous:
                # Verify by actually trying a dangerous method
                for method in found_dangerous:
                    if method == "TRACE":
                        try:
                            status, body, _ = await self._request("TRACE", vuln.endpoint, headers=vuln.headers)
                            if status == 200 and "TRACE" in body:
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"TRACE method enabled - XST vulnerability",
                                    validation_method="HTTP Methods",
                                    details={"methods": found_dangerous}
                                )
                        except:
                            pass
                
                return ValidationReport(
                    result=ValidationResult.HIGH,
                    confidence=0.85,
                    evidence=f"Potentially dangerous HTTP methods enabled: {', '.join(found_dangerous)}",
                    validation_method="HTTP Methods",
                    details={"methods": found_dangerous}
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No dangerous HTTP methods detected",
                validation_method="HTTP Methods"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="HTTP Methods"
            )
    
    # =========================================================================
    # CLOUD MISCONFIGURATION
    # =========================================================================
    
    async def _validate_cloud_misconfig(self, vuln: VulnReport) -> ValidationReport:
        """Check for cloud storage misconfiguration (S3, Azure, GCS)"""
        try:
            # S3 bucket patterns
            s3_patterns = [
                r's3\.amazonaws\.com/([a-zA-Z0-9\-\.]+)',
                r'([a-zA-Z0-9\-\.]+)\.s3\.amazonaws\.com',
                r'([a-zA-Z0-9\-\.]+)\.s3-[a-z0-9\-]+\.amazonaws\.com',
            ]
            
            # Azure blob patterns
            azure_patterns = [
                r'([a-zA-Z0-9]+)\.blob\.core\.windows\.net',
            ]
            
            # GCS patterns
            gcs_patterns = [
                r'storage\.googleapis\.com/([a-zA-Z0-9\-\.]+)',
                r'([a-zA-Z0-9\-\.]+)\.storage\.googleapis\.com',
            ]
            
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            # Check S3
            for pattern in s3_patterns:
                match = re.search(pattern, body)
                if match:
                    bucket = match.group(1)
                    # Try to list bucket
                    bucket_url = f"https://{bucket}.s3.amazonaws.com/"
                    try:
                        b_status, b_body, _ = await self._request("GET", bucket_url)
                        if b_status == 200 and "<Contents>" in b_body:
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=1.0,
                                evidence=f"S3 bucket publicly listable: {bucket}",
                                validation_method="Cloud Misconfiguration",
                                details={"bucket": bucket, "type": "S3"}
                            )
                    except:
                        pass
            
            # Check Azure
            for pattern in azure_patterns:
                match = re.search(pattern, body)
                if match:
                    account = match.group(1)
                    return ValidationReport(
                        result=ValidationResult.MEDIUM,
                        confidence=0.7,
                        evidence=f"Azure blob storage detected: {account} - verify access controls",
                        validation_method="Cloud Misconfiguration",
                        details={"account": account, "type": "Azure"}
                    )
            
            # Check GCS
            for pattern in gcs_patterns:
                match = re.search(pattern, body)
                if match:
                    bucket = match.group(1)
                    return ValidationReport(
                        result=ValidationResult.MEDIUM,
                        confidence=0.7,
                        evidence=f"GCS bucket detected: {bucket} - verify access controls",
                        validation_method="Cloud Misconfiguration",
                        details={"bucket": bucket, "type": "GCS"}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No cloud misconfiguration detected",
                validation_method="Cloud Misconfiguration"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Cloud Misconfiguration"
            )
    
    # =========================================================================
    # ADMIN INTERFACE EXPOSURE
    # =========================================================================
    
    async def _validate_admin_exposure(self, vuln: VulnReport) -> ValidationReport:
        """Check for exposed admin interfaces"""
        try:
            parts = vuln.endpoint.split("/")
            root_url = "/".join(parts[:3]) if len(parts) >= 3 else vuln.endpoint
            
            admin_paths = [
                "/admin", "/admin/", "/administrator", "/administrator/",
                "/admin/login", "/admin/index.php", "/admin.php",
                "/wp-admin", "/wp-admin/", "/wp-login.php",
                "/phpmyadmin", "/phpmyadmin/", "/pma",
                "/adminer", "/adminer.php",
                "/manager", "/manager/html",  # Tomcat
                "/console", "/console/",  # WebLogic
                "/admin-console",  # JBoss
                "/_admin", "/__admin",
                "/cpanel", "/plesk",
                "/directadmin", "/webmin",
            ]
            
            for path in admin_paths:
                url = root_url + path
                try:
                    status, body, _ = await self._request("GET", url, headers=vuln.headers)
                    
                    if status == 200:
                        admin_indicators = [
                            r"admin.*login", r"administrator.*login",
                            r"<title>.*admin", r"<title>.*login",
                            r"username.*password", r"sign.?in",
                            r"phpmyadmin", r"adminer",
                            r"tomcat.*manager", r"weblogic",
                        ]
                        
                        for indicator in admin_indicators:
                            if re.search(indicator, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=0.95,
                                    evidence=f"Admin interface exposed at {path}",
                                    validation_method="Admin Exposure",
                                    details={"path": path, "url": url}
                                )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No exposed admin interfaces found",
                validation_method="Admin Exposure"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Admin Exposure"
            )
    
    # =========================================================================
    # SAMPLE/TEST FILES
    # =========================================================================
    
    async def _validate_sample_files(self, vuln: VulnReport) -> ValidationReport:
        """Check for sample/test applications not removed"""
        try:
            parts = vuln.endpoint.split("/")
            root_url = "/".join(parts[:3]) if len(parts) >= 3 else vuln.endpoint
            
            sample_paths = [
                "/examples", "/examples/", "/sample", "/samples",
                "/test", "/test/", "/tests", "/testing",
                "/demo", "/demo/", "/demos",
                "/temp", "/tmp",
                "/cgi-bin/test", "/cgi-bin/printenv",
                "/servlet/SnoopServlet", "/snoop",
                "/status", "/jmx-console",
                "/axis2", "/axis2-web",
                "/web-console",
            ]
            
            for path in sample_paths:
                url = root_url + path
                try:
                    status, body, _ = await self._request("GET", url, headers=vuln.headers)
                    
                    if status == 200 and len(body) > 100:
                        sample_indicators = [
                            r"sample", r"example", r"test", r"demo",
                            r"hello.?world", r"success", r"it works",
                        ]
                        
                        for indicator in sample_indicators:
                            if re.search(indicator, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.HIGH,
                                    confidence=0.85,
                                    evidence=f"Sample/test application found at {path}",
                                    validation_method="Sample Files",
                                    details={"path": path}
                                )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No sample/test files found",
                validation_method="Sample Files"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Sample Files"
            )
    
    # =========================================================================
    # GENERIC MISCONFIGURATION
    # =========================================================================
    
    async def _validate_generic_misconfig(self, vuln: VulnReport) -> ValidationReport:
        """Generic misconfiguration validation - try multiple checks"""
        results = [
            await self._validate_verbose_errors(vuln),
            await self._validate_debug_mode(vuln),
            await self._validate_exposed_files(vuln),
            await self._validate_admin_exposure(vuln),
        ]
        # Note: Don't include missing_headers here as it's informational
        
        # Return best result
        best = max(results, key=lambda r: r.confidence)
        
        if best.confidence > 0:
            return best
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="Could not confirm security misconfiguration",
            validation_method="Generic Misconfiguration"
        )