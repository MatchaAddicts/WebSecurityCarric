# =============================================================================
# A08: DATA INTEGRITY FAILURES VALIDATOR (unchanged)
# =============================================================================
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

class A08_IntegrityValidator(BaseValidator):
    """
    Validates:
    - Insecure deserialization
    - Unsigned cookies/tokens
    - JWT vulnerabilities
    - Unverified updates
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "JWT" in vuln_subtype:
            return await self._validate_jwt_vuln(vuln)
        elif "COOKIE" in vuln_subtype or "UNSIGNED" in vuln_subtype:
            return await self._validate_unsigned_cookie(vuln)
        elif "DESERIAL" in vuln_subtype:
            return await self._validate_deserialization(vuln)
        else:
            return await self._validate_generic_integrity(vuln)
    
    async def _validate_jwt_vuln(self, vuln: VulnReport) -> ValidationReport:
        """Check for JWT vulnerabilities (none algorithm, weak secret, etc.)"""
        try:
            # Extract JWT from headers or body
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            
            if vuln.auth_token:
                jwt_match = re.search(jwt_pattern, vuln.auth_token)
            else:
                _, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
                jwt_match = re.search(jwt_pattern, body + str(headers))
            
            if not jwt_match:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="No JWT found",
                    validation_method="JWT Check"
                )
            
            jwt_token = jwt_match.group(0)
            parts = jwt_token.split(".")
            
            if len(parts) != 3:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="Invalid JWT format",
                    validation_method="JWT Check"
                )
            
            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_b64))
            except:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="Could not decode JWT header",
                    validation_method="JWT Check"
                )
            
            # Test 1: None algorithm
            none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
            payload_b64 = parts[1]
            none_jwt = f"{none_header}.{payload_b64}."
            
            test_headers = {**vuln.headers, "Authorization": f"Bearer {none_jwt}"}
            status, body, _ = await self._request("GET", vuln.endpoint, headers=test_headers)
            
            if status == 200 and "unauthorized" not in body.lower() and "invalid" not in body.lower():
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=1.0,
                    evidence="JWT 'none' algorithm accepted - critical vulnerability",
                    validation_method="JWT None Algorithm",
                    details={"original_alg": header.get("alg")}
                )
            
            # Test 2: Check for weak algorithm
            if header.get("alg") in ("HS256", "HS384", "HS512"):
                # Could try common secrets but that's intensive
                return ValidationReport(
                    result=ValidationResult.MEDIUM,
                    confidence=0.6,
                    evidence=f"JWT uses symmetric algorithm ({header.get('alg')}) - may be vulnerable to secret brute-force",
                    validation_method="JWT Algorithm Check"
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="JWT appears secure",
                validation_method="JWT Check"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="JWT Check"
            )
    
    async def _validate_unsigned_cookie(self, vuln: VulnReport) -> ValidationReport:
        """Check if cookies can be tampered with"""
        try:
            # Get initial cookies
            status1, body1, headers1 = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            cookies = headers1.get("set-cookie", "")
            if not cookies:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="No cookies found",
                    validation_method="Cookie Integrity"
                )
            
            # Try to tamper with cookie values
            cookie_match = re.search(r'(\w+)=([^;]+)', cookies)
            if not cookie_match:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="Could not parse cookies",
                    validation_method="Cookie Integrity"
                )
            
            cookie_name = cookie_match.group(1)
            cookie_value = cookie_match.group(2)
            
            # Tamper with the cookie
            if cookie_value.isdigit():
                tampered = str(int(cookie_value) + 1)
            else:
                tampered = cookie_value + "TAMPERED"
            
            tampered_headers = {**vuln.headers, "Cookie": f"{cookie_name}={tampered}"}
            status2, body2, _ = await self._request("GET", vuln.endpoint, headers=tampered_headers)
            
            # If tampered cookie is accepted without error
            if status2 == 200 and "invalid" not in body2.lower() and "error" not in body2.lower():
                # Check if behavior changed (indicating the value was used)
                if body1 != body2:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Cookie '{cookie_name}' accepted with tampered value",
                        validation_method="Unsigned Cookie",
                        details={"cookie_name": cookie_name}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Cookie tampering was rejected or had no effect",
                validation_method="Cookie Integrity"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Cookie Integrity"
            )
    
    async def _validate_deserialization(self, vuln: VulnReport) -> ValidationReport:
        """Check for insecure deserialization"""
        # This is complex and often language-specific
        # For now, check if common serialized formats are accepted
        try:
            payloads = [
                # PHP serialize
                ('O:8:"stdClass":0:{}', "php"),
                # Java serialize header
                (b'\xac\xed\x00\x05'.hex(), "java"),
                # Python pickle
                ("cos\nsystem\n(S'id'\ntR.", "python"),
            ]
            
            for payload, lang in payloads:
                status, body, _ = await self._request(
                    "POST", vuln.endpoint,
                    headers={**vuln.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=f"data={urllib.parse.quote(str(payload))}"
                )
                
                # Look for deserialization errors (indicates it's processing serialized data)
                error_indicators = [
                    r"unserialize", r"deserialize", r"pickle",
                    r"ObjectInputStream", r"ClassNotFoundException",
                    r"unmarshall"
                ]
                
                for indicator in error_indicators:
                    if re.search(indicator, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.85,
                            evidence=f"Application processes serialized data ({lang})",
                            validation_method="Deserialization Check",
                            details={"language": lang}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No deserialization vulnerability detected",
                validation_method="Deserialization"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Deserialization"
            )
    
    async def _validate_generic_integrity(self, vuln: VulnReport) -> ValidationReport:
        """Generic integrity check"""
        results = [
            await self._validate_jwt_vuln(vuln),
            await self._validate_unsigned_cookie(vuln),
        ]
        
        best = max(results, key=lambda r: r.confidence)
        return best