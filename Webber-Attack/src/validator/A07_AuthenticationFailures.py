# =============================================================================
# A07: AUTHENTICATION FAILURES VALIDATOR (unchanged)
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

class A07_AuthValidator(BaseValidator):
    """
    Validates:
    - Weak passwords accepted
    - No account lockout
    - Session fixation
    - Missing MFA
    - Credential stuffing possible
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "LOCKOUT" in vuln_subtype or "BRUTE" in vuln_subtype:
            return await self._validate_no_lockout(vuln)
        elif "SESSION" in vuln_subtype or "FIXATION" in vuln_subtype:
            return await self._validate_session_fixation(vuln)
        elif "WEAK" in vuln_subtype or "PASSWORD" in vuln_subtype:
            return await self._validate_weak_password(vuln)
        else:
            return await self._validate_generic_auth(vuln)
    
    async def _validate_no_lockout(self, vuln: VulnReport) -> ValidationReport:
        """Check for missing account lockout"""
        try:
            failed_attempts = 0
            attempts_needed = 15
            
            for i in range(attempts_needed):
                login_data = f"username=admin&password=wrongpassword{i}"
                status, body, _ = await self._request(
                    "POST", vuln.endpoint,
                    headers={**vuln.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=login_data
                )
                
                # Check for lockout indicators
                lockout_indicators = [
                    r"locked", r"too many", r"try again later",
                    r"account.*disabled", r"blocked", r"captcha"
                ]
                
                for indicator in lockout_indicators:
                    if re.search(indicator, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.REJECTED,
                            confidence=0.0,
                            evidence=f"Lockout triggered after {i+1} attempts",
                            validation_method="Account Lockout"
                        )
                
                if status not in (200, 401, 403):
                    break
                    
                failed_attempts += 1
                await asyncio.sleep(0.2)
            
            if failed_attempts >= 10:
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.95,
                    evidence=f"No lockout after {failed_attempts} failed login attempts",
                    validation_method="No Account Lockout",
                    details={"attempts": failed_attempts}
                )
            
            return ValidationReport(
                result=ValidationResult.MEDIUM,
                confidence=0.6,
                evidence=f"Completed {failed_attempts} attempts without clear lockout",
                validation_method="Account Lockout Check"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Account Lockout"
            )
    
    async def _validate_session_fixation(self, vuln: VulnReport) -> ValidationReport:
        """Check for session fixation vulnerability"""
        try:
            # Step 1: Get initial session
            status1, body1, headers1 = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            initial_cookies = headers1.get("set-cookie", "")
            session_match = re.search(r'(session|sess|sid|PHPSESSID|JSESSIONID)[=]([^;]+)', initial_cookies, re.I)
            
            if not session_match:
                return ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence="No session cookie found",
                    validation_method="Session Fixation"
                )
            
            session_name = session_match.group(1)
            session_value = session_match.group(2)
            
            # Step 2: Login with fixed session
            login_headers = {**vuln.headers, "Cookie": f"{session_name}={session_value}"}
            
            if vuln.body:
                status2, body2, headers2 = await self._request(
                    "POST", vuln.endpoint, headers=login_headers, data=vuln.body
                )
            else:
                # Try default login
                login_data = "username=test&password=test"
                status2, body2, headers2 = await self._request(
                    "POST", vuln.endpoint,
                    headers={**login_headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=login_data
                )
            
            # Step 3: Check if session changed after login
            new_cookies = headers2.get("set-cookie", "")
            new_session_match = re.search(rf'{session_name}[=]([^;]+)', new_cookies, re.I)
            
            if new_session_match:
                new_session_value = new_session_match.group(1)
                if new_session_value == session_value:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence="Session ID not regenerated after authentication",
                        validation_method="Session Fixation",
                        details={"session_name": session_name}
                    )
            elif session_name not in new_cookies:
                # Session wasn't regenerated
                return ValidationReport(
                    result=ValidationResult.HIGH,
                    confidence=0.85,
                    evidence="Session may not be regenerated after authentication",
                    validation_method="Session Fixation"
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Session appears to be regenerated after auth",
                validation_method="Session Fixation"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Session Fixation"
            )
    
    async def _validate_weak_password(self, vuln: VulnReport) -> ValidationReport:
        """Check if weak passwords are accepted during registration/password change"""
        try:
            weak_passwords = ["123456", "password", "abc123", "111111", "admin"]
            
            for weak_pw in weak_passwords:
                # Try registration or password change
                reg_data = f"username=testuser{int(time.time())}&password={weak_pw}&confirm_password={weak_pw}"
                status, body, _ = await self._request(
                    "POST", vuln.endpoint,
                    headers={**vuln.headers, "Content-Type": "application/x-www-form-urlencoded"},
                    data=reg_data
                )
                
                # Check for rejection of weak password
                rejection_indicators = [
                    r"too weak", r"password.*requirements",
                    r"must contain", r"minimum.*characters",
                    r"stronger password"
                ]
                
                rejected = False
                for indicator in rejection_indicators:
                    if re.search(indicator, body, re.I):
                        rejected = True
                        break
                
                if not rejected and status in (200, 201, 302):
                    success_indicators = [
                        r"success", r"created", r"registered",
                        r"welcome", r"account"
                    ]
                    
                    for indicator in success_indicators:
                        if re.search(indicator, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.95,
                                evidence=f"Weak password accepted: {weak_pw}",
                                validation_method="Weak Password Policy",
                                details={"password": weak_pw}
                            )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Weak passwords appear to be rejected",
                validation_method="Weak Password Policy"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Weak Password Policy"
            )
    
    async def _validate_generic_auth(self, vuln: VulnReport) -> ValidationReport:
        """Generic authentication failure validation"""
        results = [
            await self._validate_no_lockout(vuln),
            await self._validate_session_fixation(vuln),
        ]
        
        best = max(results, key=lambda r: r.confidence)
        return best