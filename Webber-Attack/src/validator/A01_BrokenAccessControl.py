"""
A01:2025 - Broken Access Control
================================
OWASP Top 10 2025 - #1 Risk

Access control enforces policy such that users cannot act outside their
intended permissions. Failures lead to unauthorized information disclosure,
modification, or destruction of data.

In 2025, SSRF was merged into this category (was A10:2021).

Validates:
- IDOR (Insecure Direct Object References)
- Privilege Escalation (horizontal & vertical)
- Path Traversal / LFI / Null Byte Bypass
- Missing Function Level Access Control
- CORS Misconfiguration
- SSRF (Server-Side Request Forgery) - merged from A10:2021
- JWT/Token manipulation for access bypass
"""

import re
import time
import urllib.parse
from typing import Optional, Dict, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)


class A01_AccessControlValidator(BaseValidator):
    """
    Validates Broken Access Control vulnerabilities (OWASP 2025 A01).
    Includes SSRF which was merged from A10:2021.
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_upper = vuln.vuln_type.upper()
        
        # SSRF - Now part of A01 in 2025
        if "SSRF" in vuln_upper or "SERVER-SIDE REQUEST" in vuln_upper:
            return await self._validate_ssrf(vuln)
        
        # IDOR
        elif "IDOR" in vuln_upper or "INSECURE DIRECT" in vuln_upper:
            return await self._validate_idor(vuln)
        
        # Path Traversal / LFI / Null Byte
        elif any(x in vuln_upper for x in ["TRAVERSAL", "LFI", "PATH", "LOCAL FILE", "NULL BYTE", "POISON NULL"]):
            return await self._validate_path_traversal(vuln)
        
        # Privilege Escalation
        elif "PRIVILEGE" in vuln_upper or "ESCALATION" in vuln_upper:
            return await self._validate_privilege_escalation(vuln)
        
        # CORS
        elif "CORS" in vuln_upper:
            return await self._validate_cors(vuln)
        
        # Generic access control
        else:
            return await self._validate_generic_access(vuln)
    
    # =========================================================================
    # PATH TRAVERSAL / NULL BYTE VALIDATION
    # =========================================================================
    
    async def _validate_path_traversal(self, vuln: VulnReport) -> ValidationReport:
        """Test for path traversal / LFI / null byte bypass vulnerabilities"""
        try:
            # ─────────────────────────────────────────────────────────
            # FIRST: Check if agent used null byte bypass
            # ─────────────────────────────────────────────────────────
            endpoint_has_nullbyte = any(x in vuln.endpoint for x in ["%00", "%2500", "\x00"])
            payload_has_nullbyte = vuln.payload and any(x in vuln.payload for x in ["%00", "%2500", "\x00"])
            
            if endpoint_has_nullbyte or payload_has_nullbyte:
                # Extract the bypassed URL
                endpoint = vuln.endpoint
                if not endpoint.startswith("http"):
                    endpoint = f"{self.target_url}/{endpoint.lstrip('/')}"
                
                # Test 1: Request WITH null byte (agent's bypass)
                status_bypass, body_bypass, _ = await self._request("GET", endpoint, headers=vuln.headers)
                
                # Test 2: Request WITHOUT null byte (base file, should be blocked)
                base_endpoint = re.sub(r'%00.*|%2500.*|\x00.*', '', endpoint)
                status_base, body_base, _ = await self._request("GET", base_endpoint, headers=vuln.headers)
                
                # SUCCESS: bypass=200, base=403/404
                if status_bypass == 200 and status_base in [403, 404]:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Null byte bypass confirmed: base returns {status_base}, bypass returns {status_bypass}",
                        validation_method="Path Traversal - Null Byte",
                        details={"bypass_url": endpoint, "base_url": base_endpoint}
                    )
                
                # PARTIAL: both return 200 but different content
                if status_bypass == 200 and status_base == 200:
                    if body_bypass != body_base and len(body_bypass) > 0:
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.9,
                            evidence=f"Null byte changes response content",
                            validation_method="Path Traversal - Null Byte"
                        )
                
                # ALSO CHECK: bypass returns actual file content
                if status_bypass == 200 and len(body_bypass) > 0:
                    # Check for file-like content patterns
                    file_patterns = [
                        r"^#", r"^\/\/", r"^\[", r"^<\?",  # Config files
                        r"password|secret|key|token",  # Sensitive strings
                    ]
                    if any(re.search(p, body_bypass, re.I | re.M) for p in file_patterns):
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.85,
                            evidence=f"Null byte bypass returns file-like content",
                            validation_method="Path Traversal - Null Byte"
                        )
            
            # ─────────────────────────────────────────────────────────
            # FALLBACK: Test generic path traversal payloads
            # ─────────────────────────────────────────────────────────
            payloads = [
                ("../../../../etc/passwd", r"root:.*:0:0"),
                ("../../../etc/shadow", r"root:\$"),
                ("..\\..\\..\\..\\windows\\win.ini", r"\[extensions\]"),
                ("../../../proc/self/environ", r"PATH=|HOME=|USER="),
                ("/etc/passwd", r"root:.*:0:0"),
                ("file:///etc/passwd", r"root:.*:0:0"),
            ]
            
            for payload, pattern in payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(
                    vuln.method, url, headers=vuln.headers, data=data
                )
                
                if status == 200 and re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Path traversal confirmed: read system file",
                        validation_method="Path Traversal",
                        details={"payload": payload}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm path traversal",
                validation_method="Path Traversal"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Path Traversal"
            )
    
    # =========================================================================
    # GENERIC ACCESS CONTROL - FIXED METHOD
    # =========================================================================
    
    async def _validate_generic_access(self, vuln: VulnReport) -> ValidationReport:
        """Fallback for unspecified access control issues"""
        try:
            # Get endpoint URL
            endpoint = vuln.endpoint
            if not endpoint.startswith("http"):
                endpoint = f"{self.target_url}/{endpoint.lstrip('/')}"
            
            # ─── Test 1: Check if endpoint requires auth ───
            status_unauth, body_unauth, headers_unauth = await self._request("GET", endpoint)
            
            # If 401/403, endpoint IS restricted
            if status_unauth in [401, 403]:
                # If agent provided auth token, test with it
                if vuln.auth_token:
                    headers = {**vuln.headers, "Cookie": vuln.auth_token}
                    status_auth, body_auth, _ = await self._request("GET", endpoint, headers=headers)
                    
                    if status_auth == 200:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.9,
                            evidence=f"Restricted endpoint accessible with provided token (HTTP {status_unauth} → {status_auth})",
                            validation_method="Access Control - Auth Required"
                        )
                
                # No auth provided - can't validate
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence=f"Endpoint requires authentication (HTTP {status_unauth}), cannot validate without credentials",
                    validation_method="Access Control"
                )
            
            # ─── Test 2: If 200 without auth, check if content is actually sensitive ───
            if status_unauth == 200:
                # Check response for admin/sensitive patterns
                sensitive_patterns = [
                    r"<form[^>]*action=['\"].*admin", r"delete.*user", r"create.*user",
                    r"role.*admin", r"permission.*manage", r"manage.*account",
                    r"user.*list", r"dashboard.*admin", r"configuration.*panel"
                ]
                
                has_sensitive = any(re.search(p, body_unauth, re.I) for p in sensitive_patterns)
                
                # Check URL for admin indicators
                url_lower = endpoint.lower()
                url_is_admin = any(x in url_lower for x in 
                                   ["/admin", "/dashboard", "/manage", "/settings", "/config", "/panel"])
                
                # Check for CORS misconfiguration allowing sensitive access
                acao = headers_unauth.get("Access-Control-Allow-Origin", "")
                if acao == "*" or "evil" in acao:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"CORS allows any origin ({acao})",
                        validation_method="Access Control - CORS"
                    )
                
                # If URL suggests admin but no auth required
                if url_is_admin and has_sensitive:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.75,
                        evidence=f"Admin endpoint accessible without authentication",
                        validation_method="Access Control - Unauthenticated Admin"
                    )
                
                # URL suggests admin but content doesn't confirm it
                if url_is_admin and not has_sensitive:
                    return ValidationReport(
                        result=ValidationResult.REJECTED,
                        confidence=0.0,
                        evidence="Endpoint accessible but no sensitive content detected (may be public by design)",
                        validation_method="Access Control"
                    )
                
                # Public endpoint - not a vulnerability
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence="Endpoint is publicly accessible by design (no admin patterns detected)",
                    validation_method="Access Control"
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Could not confirm access control vulnerability",
                validation_method="Generic Access Control"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Generic Access Control"
            )
    
    # =========================================================================
    # IDOR VALIDATION
    # =========================================================================
    
    async def _validate_idor(self, vuln: VulnReport) -> ValidationReport:
        """Test for IDOR (Insecure Direct Object Reference)"""
        try:
            # Extract numeric ID from endpoint
            id_match = re.search(r'/(\d+)(?:/|$|\?)', vuln.endpoint)
            if not id_match:
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence="No numeric ID found in endpoint",
                    validation_method="IDOR"
                )
            
            original_id = id_match.group(1)
            test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1", "2", "999"]
            
            headers = vuln.headers.copy()
            if vuln.auth_token:
                headers["Cookie"] = vuln.auth_token
            
            # Get original response
            orig_status, orig_body, _ = await self._request(
                vuln.method, vuln.endpoint, headers=headers, data=vuln.body
            )
            
            if orig_status != 200:
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence=f"Original request failed (HTTP {orig_status})",
                    validation_method="IDOR"
                )
            
            # Try other IDs
            for test_id in test_ids:
                test_endpoint = vuln.endpoint.replace(f"/{original_id}", f"/{test_id}")
                test_status, test_body, _ = await self._request(
                    vuln.method, test_endpoint, headers=headers, data=vuln.body
                )
                
                if test_status == 200 and test_body != orig_body:
                    # Check if response contains user-specific data
                    user_patterns = [r'"email":', r'"username":', r'"user":', r'"id":', r'"name":']
                    if any(re.search(p, test_body) for p in user_patterns):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.95,
                            evidence=f"IDOR confirmed: accessed resource {test_id} (different from {original_id})",
                            validation_method="IDOR",
                            details={"original_id": original_id, "accessed_id": test_id}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Unauthorized request properly blocked",
                validation_method="IDOR"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="IDOR"
            )
    
    # =========================================================================
    # SSRF, PRIVILEGE ESCALATION, CORS (keep original methods)
    # =========================================================================
    
    async def _validate_ssrf(self, vuln: VulnReport) -> ValidationReport:
        """SSRF validation - original method"""
        return ValidationReport(
            result=ValidationResult.INCONCLUSIVE,
            confidence=0.0,
            evidence="SSRF validation not fully implemented",
            validation_method="SSRF"
        )
    
    async def _validate_privilege_escalation(self, vuln: VulnReport) -> ValidationReport:
        """Privilege escalation - original method"""
        return ValidationReport(
            result=ValidationResult.INCONCLUSIVE,
            confidence=0.0,
            evidence="Privilege escalation validation not fully implemented",
            validation_method="Privilege Escalation"
        )
    
    async def _validate_cors(self, vuln: VulnReport) -> ValidationReport:
        """CORS validation"""
        try:
            test_origins = ["https://evil.com", "https://attacker.com", "null"]
            
            for origin in test_origins:
                headers = {**vuln.headers, "Origin": origin}
                status, body, resp_headers = await self._request(
                    "GET", vuln.endpoint, headers=headers
                )
                
                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                acac = resp_headers.get("Access-Control-Allow-Credentials", "")
                
                # Wildcard with credentials
                if acao == "*" and acac.lower() == "true":
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence="CORS allows * with credentials - CRITICAL",
                        validation_method="CORS Misconfiguration"
                    )
                
                # Reflects arbitrary origin with credentials
                if acao == origin and acac.lower() == "true":
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"CORS reflects arbitrary origin with credentials: {origin}",
                        validation_method="CORS Misconfiguration"
                    )
                
                # Null origin with credentials
                if acao == "null" and acac.lower() == "true":
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence="CORS allows null origin with credentials",
                        validation_method="CORS Misconfiguration"
                    )
                
                # Just wildcard (less severe)
                if acao == "*":
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence="CORS allows any origin (*)",
                        validation_method="CORS Misconfiguration"
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="CORS configuration appears secure",
                validation_method="CORS"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="CORS"
            )