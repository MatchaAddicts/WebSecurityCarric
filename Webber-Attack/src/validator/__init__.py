"""
Validator Package - OWASP 2025
==============================
Modular vulnerability validation system for Webber-Attack.
Uses MCP for all HTTP requests.

Usage in systematic_scanner:
    from validator import VulnerabilityValidator, create_vuln_report_from_systematic
    
    # Initialize with MCP client
    validator = VulnerabilityValidator(mcp_client, target_url)
    
    # Validate a finding
    vuln_report = create_vuln_report_from_systematic({
        "title": "SQL Injection",
        "owasp": "A05",
        "endpoint": "/api/users?id=1",
        "evidence": "SQL error in response",
        "payload": "' OR '1'='1"
    })
    
    report = await validator.validate(vuln_report)
    
    if report.is_valid():
        # Store the vulnerability
        pass
    elif report.is_informational:
        # Store but don't count
        pass
    else:
        # Reject - false positive
        pass
"""

from .base import (
    ValidationResult,
    ValidationReport,
    VulnReport,
    BaseValidator,
)

from .hub import (
    VulnerabilityValidator,
    create_vuln_report_from_agent,
    create_vuln_report_from_systematic,
)

__all__ = [
    # Core types
    "ValidationResult",
    "ValidationReport", 
    "VulnReport",
    "BaseValidator",
    
    # Main validator
    "VulnerabilityValidator",
    
    # Helper functions
    "create_vuln_report_from_agent",
    "create_vuln_report_from_systematic",
]

__version__ = "2.0.0"  # MCP Edition