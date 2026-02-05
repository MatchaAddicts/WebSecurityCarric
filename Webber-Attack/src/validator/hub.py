"""
Vulnerability Validator Hub v3.0
=================================
Main router that dispatches to appropriate OWASP 2025 category validators.

FIXES v1.0 → v1.1:
- validate() now receives mcp + target at call-time (mcp is short-lived, created
  per phase/agent — storing it at __init__ time was always wrong)
- Category validators are instantiated with the correct 4 args:
      validator_class(mcp, target, timeout, retries)
  Was: validator_class(timeout, retries)   ← timeout landed in mcp_client slot,
                                             retries (int 2) landed in target_url slot
                                             → target_url.rstrip('/') crashed immediately
- Removed "async with validator_class(...)" — BaseValidator has no __aenter__/__aexit__,
  so this would have been the next crash after the arg fix.

CALLERS must now pass mcp and target:
    await validator.validate(vuln_report, mcp=mcp, target=target)
"""

import re
import logging
from typing import Dict, List, Any, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
    logger,
)

# Import all OWASP 2025 category validators
from .A01_BrokenAccessControl import A01_AccessControlValidator
from .A02_SecurityMisconfiguration import A02_MisconfigValidator
from .A03_SoftwareSupplyChainFailures import A03_SupplyChainValidator
from .A04_CryptographicFailures import A04_CryptoValidator
from .A05_Injection import A05_InjectionValidator
from .A06_InsecureDesign import A06_InsecureDesignValidator
from .A07_AuthenticationFailures import A07_AuthValidator
from .A08_SoftwareOrDataIntegrityFailures import A08_IntegrityValidator
from .A09_SecurityLoggingAndAlertingFailures import A09_LoggingValidator
from .A10_MishandlingOfExceptionalConditions import A10_ExceptionalConditionsValidator


class VulnerabilityValidator:
    """
    Main validator hub — routes to the appropriate OWASP category validator.

    Usage:
        # Create once per scan (target is stable)
        validator = VulnerabilityValidator(target="http://127.0.0.1:3000")

        # Call per-finding, passing the current mcp connection
        report = await validator.validate(vuln_report, mcp=mcp)
    """

    def __init__(self, target: str = "", timeout: int = 10, retries: int = 2):
        self.target  = target.rstrip('/') if target else ""
        self.timeout = timeout
        self.retries = retries

        # OWASP 2025 category → validator class mapping
        self.validators: Dict[str, type] = {
            "A01": A01_AccessControlValidator,
            "A02": A02_MisconfigValidator,
            "A03": A03_SupplyChainValidator,
            "A04": A04_CryptoValidator,
            "A05": A05_InjectionValidator,
            "A06": A06_InsecureDesignValidator,
            "A07": A07_AuthValidator,
            "A08": A08_IntegrityValidator,
            "A09": A09_LoggingValidator,
            "A10": A10_ExceptionalConditionsValidator,
        }

    # ─────────────────────────────────────────────────────────────
    # CORE VALIDATE
    # ─────────────────────────────────────────────────────────────

    async def validate(self, vuln: VulnReport, mcp=None, target: str = None) -> ValidationReport:
        """
        Validate a single vulnerability report.

        Args:
            vuln:   The standardised VulnReport to validate.
            mcp:    MCPClientHub instance (required — used by category validators
                    to make HTTP requests via curl).  Pass the one that is already
                    initialised in the current phase/agent.
            target: Override target URL.  Falls back to self.target if omitted.

        Returns:
            ValidationReport with result, confidence, evidence.
        """
        # ── guard: mcp is required ──────────────────────────────
        if mcp is None:
            logger.error("validate() called without mcp — cannot make HTTP requests")
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence="Validator misconfiguration: mcp not passed to validate()",
                validation_method="Config Error"
            )

        target = (target or self.target).rstrip('/')

        # ── route to the right OWASP category ───────────────────
        category = self._extract_category(vuln.owasp_category, vuln.vuln_type)

        if category not in self.validators:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Unknown OWASP category: {category}",
                validation_method="Category Check"
            )

        validator_class = self.validators[category]

        try:
            # FIXED: pass all 4 required args — was (timeout, retries) only
            # FIXED: plain instantiation — was "async with" but BaseValidator
            #        has no __aenter__ / __aexit__
            validator = validator_class(mcp, target, self.timeout, self.retries)
            return await validator.validate(vuln)

        except Exception as e:
            logger.error(f"Validation error for {vuln.vuln_type}: {vuln.endpoint}: {e}")
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Validation error: {str(e)}",
                validation_method="Error"
            )

    # ─────────────────────────────────────────────────────────────
    # BATCH VALIDATE
    # ─────────────────────────────────────────────────────────────

    async def validate_batch(
        self,
        vulns: List[VulnReport],
        mcp=None,
        target: str = None
    ) -> List[Tuple[VulnReport, ValidationReport]]:
        """Validate multiple vulnerabilities concurrently."""
        import asyncio

        tasks   = [self.validate(v, mcp=mcp, target=target) for v in vulns]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for vuln, result in zip(vulns, results):
            if isinstance(result, Exception):
                result = ValidationReport(
                    result=ValidationResult.INCONCLUSIVE,
                    confidence=0.0,
                    evidence=f"Exception: {str(result)}",
                    validation_method="Error"
                )
            output.append((vuln, result))

        return output

    # ─────────────────────────────────────────────────────────────
    # SYSTEMATIC SCANNER HELPER
    # ─────────────────────────────────────────────────────────────

    async def validate_systematic_findings(
        self,
        findings: List[Dict[str, Any]],
        mcp=None,
        target: str = None
    ) -> List[Tuple[Dict[str, Any], ValidationReport]]:
        """
        Validate raw findings from the systematic scanner.
        Only findings where report.is_valid() == True should be stored.
        """
        results = []

        for finding in findings:
            vuln   = create_vuln_report_from_systematic(finding)
            report = await self.validate(vuln, mcp=mcp, target=target)
            results.append((finding, report))

            # Log outcome
            if report.is_valid():
                logger.info(f"✓ VALIDATED: {finding.get('type', 'Unknown')} — {report.result.value}")
            elif report.is_informational:
                logger.info(f"ℹ INFORMATIONAL: {finding.get('type', 'Unknown')} — not counted")
            else:
                logger.warning(f"✗ REJECTED: {finding.get('type', 'Unknown')} — {report.evidence[:50]}")

        return results

    # ─────────────────────────────────────────────────────────────
    # OWASP CATEGORY EXTRACTION
    # ─────────────────────────────────────────────────────────────

    def _extract_category(self, owasp_category: str, vuln_type: str) -> str:
        """Extract OWASP category code — OWASP 2025 ordering."""
        
        # ─── CRITICAL: Force certain keywords to specific categories ───
        # These override agent's owasp_category to fix common misrouting
        vuln_upper = vuln_type.upper()
        
        if any(x in vuln_upper for x in ["STACK", "TRACE", "VERBOSE ERROR", "ERROR MESSAGE"]):
            return "A02"  # Force to misconfiguration, NOT A09/A10
        
        if "NULL BYTE" in vuln_upper or "POISON NULL" in vuln_upper:
            return "A01"  # Null byte = path traversal = access control
        
        # Direct A0x match
        category_match = re.search(r'A0?(\d{1,2})', owasp_category.upper())
        if category_match:
            num = int(category_match.group(1))
            if 1 <= num <= 10:
                return f"A{num:02d}"

        # Infer from vuln_type keywords
        vuln_upper = vuln_type.upper()

        type_to_category = {
            # A01 — Broken Access Control (includes SSRF in 2025)
            "IDOR": "A01", "ACCESS": "A01", "AUTHORIZATION": "A01",
            "PRIVILEGE": "A01", "TRAVERSAL": "A01", "LFI": "A01",
            "SSRF": "A01", "SERVER-SIDE REQUEST": "A01",

            # A02 — Security Misconfiguration
            "MISCONFIG": "A02", "DIRECTORY": "A02", "HEADER": "A02",
            "DEBUG": "A02", "DEFAULT": "A02", "VERBOSE": "A02",
            "EXPOSED": "A02", "LISTING": "A02", "STACK": "A02",
            "TRACE": "A02", "ERROR MESSAGE": "A02",

            # A03 — Software Supply Chain Failures
            "SUPPLY CHAIN": "A03", "DEPENDENCY": "A03", "COMPONENT": "A03",
            "OUTDATED": "A03", "VERSION": "A03", "CVE": "A03",
            "LIBRARY": "A03", "PACKAGE": "A03", "NPM": "A03",
            "MALICIOUS": "A03",

            # A04 — Cryptographic Failures
            "CRYPTO": "A04", "PLAINTEXT": "A04", "HASH": "A04",
            "ENCRYPTION": "A04", "TLS": "A04", "SSL": "A04",
            "CERTIFICATE": "A04", "WEAK CIPHER": "A04",

            # A05 — Injection
            "SQL": "A05", "XSS": "A05", "INJECTION": "A05",
            "COMMAND": "A05", "LDAP": "A05", "XXE": "A05",
            "SSTI": "A05", "TEMPLATE": "A05", "NOSQL": "A05",

            # A06 — Insecure Design
            "DESIGN": "A06", "LOGIC": "A06", "RATE": "A06",
            "LIMIT": "A06", "PRICE": "A06", "BYPASS": "A06",
            "BUSINESS LOGIC": "A06", "WORKFLOW": "A06",

            # A07 — Authentication Failures
            "AUTH": "A07", "SESSION": "A07", "PASSWORD": "A07",
            "LOGIN": "A07", "CREDENTIAL": "A07", "BRUTE": "A07",
            "LOCKOUT": "A07", "MFA": "A07", "2FA": "A07",

            # A08 — Software & Data Integrity Failures
            "INTEGRITY": "A08", "JWT": "A08", "COOKIE": "A08",
            "DESERIAL": "A08", "UNSIGNED": "A08", "CI/CD": "A08",
            "UPDATE": "A08",

            # A09 — Security Logging & Alerting Failures
            "LOG": "A09", "MONITOR": "A09", "AUDIT": "A09",
            "ALERT": "A09",

            # A10 — Mishandling of Exceptional Conditions
            "ERROR": "A10", "EXCEPTION": "A10", "FAIL": "A10",
            "CRASH": "A10", "TIMEOUT": "A10", "OVERFLOW": "A10",
            "RESOURCE": "A10", "DENIAL": "A10", "DOS": "A10",
        }

        for keyword, category in type_to_category.items():
            if keyword in vuln_upper:
                return category

        return "A05"  # Default — Injection is most common


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_vuln_report_from_agent(agent_data: Dict[str, Any]) -> VulnReport:
    """Convert agent's vulnerability report dict → VulnReport."""
    return VulnReport(
        vuln_type=agent_data.get("type", agent_data.get("title", "Unknown")),
        owasp_category=agent_data.get("owasp", agent_data.get("category", "A05")),
        endpoint=agent_data.get("endpoint", agent_data.get("url", "")),
        method=agent_data.get("method", "GET"),
        parameter=agent_data.get("parameter", agent_data.get("param", "")),
        payload=agent_data.get("payload", ""),
        evidence=agent_data.get("evidence", agent_data.get("description", "")),
        auth_token=agent_data.get("auth_token", agent_data.get("session", None)),
        headers=agent_data.get("headers", {}),
        body=agent_data.get("body", agent_data.get("data", None)),
    )


def create_vuln_report_from_systematic(finding: Dict[str, Any]) -> VulnReport:
    """Convert systematic scanner's finding dict → VulnReport."""
    return VulnReport(
        vuln_type=finding.get("type", finding.get("vuln_type", finding.get("title", "Unknown"))),
        owasp_category=finding.get("owasp", finding.get("owasp_category", finding.get("category", "A05"))),
        endpoint=finding.get("endpoint", finding.get("url", finding.get("target", ""))),
        method=finding.get("method", "GET"),
        parameter=finding.get("parameter", finding.get("param", finding.get("vulnerable_param", ""))),
        payload=finding.get("payload", finding.get("attack_payload", "")),
        evidence=finding.get("evidence", finding.get("description", finding.get("details", ""))),
        auth_token=finding.get("auth_token", finding.get("session", finding.get("cookie", None))),
        headers=finding.get("headers", {}),
        body=finding.get("body", finding.get("data", finding.get("request_body", None))),
    )