"""
A03:2025 - Software Supply Chain Failures Validator
===================================================
OWASP Top 10 2025 - A03 (NEW)

This is a NEW category for 2025, replacing "Vulnerable and Outdated Components" (A06:2021).
50% of survey respondents ranked it #1 concern.

Uses OSV (Open Source Vulnerabilities) API for real-time vulnerability checking:
- https://osv.dev/ - Google's free vulnerability database
- No API key required
- Covers: npm, PyPI, Go, Maven, NuGet, RubyGems, Packagist, crates.io, etc.

Validates:
- Outdated software versions with known CVEs (via OSV API)
- Vulnerable JavaScript libraries
- Vulnerable server software
- Vulnerable frameworks
- Known vulnerable dependencies
- Version disclosure
"""

import re
import json
import asyncio
from typing import Optional, Dict, List, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)


class A03_SupplyChainValidator(BaseValidator):
    """
    Validates Software Supply Chain Failures (OWASP 2025 A03).
    Uses OSV API for real-time vulnerability checking.
    """
    
    # OSV API endpoint (free, no auth required)
    OSV_API_URL = "https://api.osv.dev/v1/query"
    
    # Package detection patterns: (regex, package_name, ecosystem)
    PACKAGE_PATTERNS = [
        # JavaScript / npm
        (r'jquery[/-]v?(\d+\.\d+\.\d+)', 'jquery', 'npm'),
        (r'jquery.*version["\s:]+["\']?(\d+\.\d+\.\d+)', 'jquery', 'npm'),
        (r'angular(?:\.min)?\.js[/-]?(\d+\.\d+\.\d+)', 'angular', 'npm'),
        (r'@angular/core[@/](\d+\.\d+\.\d+)', '@angular/core', 'npm'),
        (r'vue(?:\.min)?\.js[/-]?(\d+\.\d+\.\d+)', 'vue', 'npm'),
        (r'react(?:\.min)?\.js[/-]?(\d+\.\d+\.\d+)', 'react', 'npm'),
        (r'react-dom[/-](\d+\.\d+\.\d+)', 'react-dom', 'npm'),
        (r'bootstrap[/-]v?(\d+\.\d+\.\d+)', 'bootstrap', 'npm'),
        (r'lodash[/-]v?(\d+\.\d+\.\d+)', 'lodash', 'npm'),
        (r'moment[/-]v?(\d+\.\d+\.\d+)', 'moment', 'npm'),
        (r'axios[/-]v?(\d+\.\d+\.\d+)', 'axios', 'npm'),
        (r'express[/-]v?(\d+\.\d+\.\d+)', 'express', 'npm'),
        (r'next[/-]v?(\d+\.\d+\.\d+)', 'next', 'npm'),
        (r'node[/-]v?(\d+\.\d+\.\d+)', 'node', 'npm'),
        (r'dompurify[/-]v?(\d+\.\d+\.\d+)', 'dompurify', 'npm'),
        (r'marked[/-]v?(\d+\.\d+\.\d+)', 'marked', 'npm'),
        (r'handlebars[/-]v?(\d+\.\d+\.\d+)', 'handlebars', 'npm'),
        (r'underscore[/-]v?(\d+\.\d+\.\d+)', 'underscore', 'npm'),
        (r'backbone[/-]v?(\d+\.\d+\.\d+)', 'backbone', 'npm'),
        (r'ember[/-]v?(\d+\.\d+\.\d+)', 'ember-source', 'npm'),
        (r'socket\.io[/-]v?(\d+\.\d+\.\d+)', 'socket.io', 'npm'),
        
        # Python / PyPI
        (r'Django[/-]v?(\d+\.\d+\.?\d*)', 'django', 'PyPI'),
        (r'Flask[/-]v?(\d+\.\d+\.?\d*)', 'flask', 'PyPI'),
        (r'requests[/-]v?(\d+\.\d+\.?\d*)', 'requests', 'PyPI'),
        (r'numpy[/-]v?(\d+\.\d+\.?\d*)', 'numpy', 'PyPI'),
        (r'pandas[/-]v?(\d+\.\d+\.?\d*)', 'pandas', 'PyPI'),
        (r'Pillow[/-]v?(\d+\.\d+\.?\d*)', 'pillow', 'PyPI'),
        (r'urllib3[/-]v?(\d+\.\d+\.?\d*)', 'urllib3', 'PyPI'),
        (r'cryptography[/-]v?(\d+\.\d+\.?\d*)', 'cryptography', 'PyPI'),
        (r'PyYAML[/-]v?(\d+\.\d+\.?\d*)', 'pyyaml', 'PyPI'),
        (r'Jinja2[/-]v?(\d+\.\d+\.?\d*)', 'jinja2', 'PyPI'),
        
        # Java / Maven
        (r'spring-core[/-]v?(\d+\.\d+\.?\d*)', 'org.springframework:spring-core', 'Maven'),
        (r'spring-boot[/-]v?(\d+\.\d+\.?\d*)', 'org.springframework.boot:spring-boot', 'Maven'),
        (r'log4j[/-]v?(\d+\.\d+\.?\d*)', 'org.apache.logging.log4j:log4j-core', 'Maven'),
        (r'struts[/-]v?(\d+\.\d+\.?\d*)', 'org.apache.struts:struts2-core', 'Maven'),
        (r'jackson-databind[/-]v?(\d+\.\d+\.?\d*)', 'com.fasterxml.jackson.core:jackson-databind', 'Maven'),
        
        # PHP / Packagist
        (r'laravel[/-]v?(\d+\.\d+\.?\d*)', 'laravel/framework', 'Packagist'),
        (r'symfony[/-]v?(\d+\.\d+\.?\d*)', 'symfony/symfony', 'Packagist'),
        (r'wordpress[/-]v?(\d+\.\d+\.?\d*)', 'wordpress', 'Packagist'),
        (r'drupal[/-]v?(\d+\.?\d*)', 'drupal/core', 'Packagist'),
        
        # Ruby / RubyGems
        (r'rails[/-]v?(\d+\.\d+\.?\d*)', 'rails', 'RubyGems'),
        (r'rack[/-]v?(\d+\.\d+\.?\d*)', 'rack', 'RubyGems'),
        
        # Go
        (r'gin[/-]v?(\d+\.\d+\.?\d*)', 'github.com/gin-gonic/gin', 'Go'),
    ]
    
    # Server software patterns (not in OSV, use local checks)
    SERVER_PATTERNS = [
        (r'Apache[/-](\d+\.\d+\.\d+)', 'Apache', '2.4.58'),
        (r'nginx[/-](\d+\.\d+\.\d+)', 'nginx', '1.25.3'),
        (r'PHP[/-](\d+\.\d+\.\d+)', 'PHP', '8.3.0'),
        (r'Tomcat[/-](\d+\.\d+\.\d+)', 'Tomcat', '10.1.16'),
        (r'IIS[/-](\d+\.\d+)', 'IIS', '10.0'),
        (r'OpenSSL[/-](\d+\.\d+\.\d+)', 'OpenSSL', '3.2.0'),
    ]
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "VERSION" in vuln_subtype or "OUTDATED" in vuln_subtype:
            return await self._validate_with_osv(vuln)
        
        elif "CVE" in vuln_subtype:
            return await self._validate_specific_cve(vuln)
        
        elif "LIBRARY" in vuln_subtype or "JAVASCRIPT" in vuln_subtype or "JS" in vuln_subtype:
            return await self._validate_js_libraries(vuln)
        
        elif "COMPONENT" in vuln_subtype or "DEPENDENCY" in vuln_subtype or "PACKAGE" in vuln_subtype:
            return await self._validate_with_osv(vuln)
        
        else:
            return await self._validate_generic_supply_chain(vuln)
    
    # =========================================================================
    # OSV API INTEGRATION
    # =========================================================================
    
    async def _query_osv(self, package: str, version: str, ecosystem: str) -> List[Dict]:
        """
        Query OSV API for vulnerabilities in a specific package version.
        
        OSV API: https://osv.dev/docs/
        Free, no authentication required.
        
        Returns list of vulnerabilities found.
        """
        try:
            payload = {
                "version": version,
                "package": {
                    "name": package,
                    "ecosystem": ecosystem
                }
            }
            
            # Make POST request to OSV API
            async with self.session.post(
                self.OSV_API_URL,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("vulns", [])
                else:
                    return []
                    
        except Exception as e:
            # API failed, return empty (will fall back to local checks)
            return []
    
    async def _validate_with_osv(self, vuln: VulnReport) -> ValidationReport:
        """
        Validate using OSV API for real-time vulnerability data.
        """
        try:
            status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            combined = body + str(headers)
            
            all_vulnerabilities = []
            
            # Check each package pattern
            for pattern, package_name, ecosystem in self.PACKAGE_PATTERNS:
                match = re.search(pattern, combined, re.I)
                if match:
                    detected_version = match.group(1)
                    
                    # Query OSV API
                    vulns = await self._query_osv(package_name, detected_version, ecosystem)
                    
                    if vulns:
                        # Extract CVE IDs and severity
                        cve_ids = []
                        max_severity = "UNKNOWN"
                        
                        for v in vulns:
                            # Get CVE aliases
                            for alias in v.get("aliases", []):
                                if alias.startswith("CVE-"):
                                    cve_ids.append(alias)
                            
                            # Get severity from database_specific or severity field
                            severity_info = v.get("database_specific", {}).get("severity", "")
                            if not severity_info:
                                for sev in v.get("severity", []):
                                    severity_info = sev.get("score", "")
                                    break
                            
                            severity_upper = str(severity_info).upper()
                            if "CRITICAL" in severity_upper:
                                max_severity = "CRITICAL"
                            elif "HIGH" in severity_upper and max_severity not in ["CRITICAL"]:
                                max_severity = "HIGH"
                            elif "MEDIUM" in severity_upper and max_severity not in ["CRITICAL", "HIGH"]:
                                max_severity = "MEDIUM"
                        
                        all_vulnerabilities.append({
                            "package": package_name,
                            "version": detected_version,
                            "ecosystem": ecosystem,
                            "vuln_count": len(vulns),
                            "cves": cve_ids[:5],  # Limit to first 5
                            "severity": max_severity
                        })
            
            # Also check server software (local patterns, not in OSV)
            server_vulns = await self._check_server_versions(combined)
            all_vulnerabilities.extend(server_vulns)
            
            if all_vulnerabilities:
                # Sort by severity
                critical = [v for v in all_vulnerabilities if v.get("severity") == "CRITICAL"]
                high = [v for v in all_vulnerabilities if v.get("severity") == "HIGH"]
                
                if critical:
                    v = critical[0]
                    cve_str = ', '.join(v['cves'][:3]) if v['cves'] else 'check OSV database'
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"CRITICAL: {v['package']} {v['version']} has {v['vuln_count']} known vulnerabilities. CVEs: {cve_str}",
                        validation_method="Supply Chain - OSV API",
                        details={"vulnerabilities": all_vulnerabilities}
                    )
                elif high:
                    v = high[0]
                    cve_str = ', '.join(v['cves'][:3]) if v['cves'] else 'check OSV database'
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"HIGH: {v['package']} {v['version']} has {v['vuln_count']} known vulnerabilities. CVEs: {cve_str}",
                        validation_method="Supply Chain - OSV API",
                        details={"vulnerabilities": all_vulnerabilities}
                    )
                else:
                    v = all_vulnerabilities[0]
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.9,
                        evidence=f"Vulnerable: {v['package']} {v['version']} has {v['vuln_count']} known vulnerabilities",
                        validation_method="Supply Chain - OSV API",
                        details={"vulnerabilities": all_vulnerabilities}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No vulnerable components detected via OSV",
                validation_method="Supply Chain - OSV API"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error querying OSV: {str(e)}",
                validation_method="Supply Chain - OSV API"
            )
    
    async def _check_server_versions(self, content: str) -> List[Dict]:
        """Check server software versions against known vulnerable versions"""
        vulnerabilities = []
        
        for pattern, name, min_safe_version in self.SERVER_PATTERNS:
            match = re.search(pattern, content, re.I)
            if match:
                detected_version = match.group(1)
                if self._version_compare(detected_version, min_safe_version) < 0:
                    vulnerabilities.append({
                        "package": name,
                        "version": detected_version,
                        "ecosystem": "Server",
                        "vuln_count": 1,
                        "cves": [f"Outdated {name}"],
                        "severity": "HIGH",
                        "min_safe": min_safe_version
                    })
        
        return vulnerabilities
    
    # =========================================================================
    # SPECIFIC CVE VALIDATION
    # =========================================================================
    
    async def _validate_specific_cve(self, vuln: VulnReport) -> ValidationReport:
        """Validate when a specific CVE is reported"""
        try:
            # Extract CVE ID from evidence
            cve_match = re.search(r'CVE-\d{4}-\d+', vuln.evidence, re.I)
            
            if not cve_match:
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence="No CVE ID found in report",
                    validation_method="Supply Chain - CVE"
                )
            
            cve_id = cve_match.group(0).upper()
            
            # Get page content and check for affected software
            status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            combined = body + str(headers)
            
            # Try to detect the package and version
            for pattern, package_name, ecosystem in self.PACKAGE_PATTERNS:
                match = re.search(pattern, combined, re.I)
                if match:
                    detected_version = match.group(1)
                    
                    # Query OSV to verify this CVE affects this version
                    vulns = await self._query_osv(package_name, detected_version, ecosystem)
                    
                    for v in vulns:
                        if cve_id in v.get("aliases", []):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=1.0,
                                evidence=f"{cve_id} CONFIRMED: {package_name} {detected_version} is affected",
                                validation_method="Supply Chain - CVE Verification",
                                details={
                                    "cve": cve_id,
                                    "package": package_name,
                                    "version": detected_version,
                                    "vuln_details": v.get("summary", "")[:200]
                                }
                            )
            
            # CVE reported but couldn't verify via OSV
            return ValidationReport(
                result=ValidationResult.MEDIUM,
                confidence=0.6,
                evidence=f"{cve_id} reported but version not verified via OSV - manual check recommended",
                validation_method="Supply Chain - CVE",
                details={"cve": cve_id}
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Supply Chain - CVE"
            )
    
    # =========================================================================
    # JS LIBRARIES
    # =========================================================================
    
    async def _validate_js_libraries(self, vuln: VulnReport) -> ValidationReport:
        """Check specifically for vulnerable JavaScript libraries"""
        try:
            status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            js_packages = [
                (r'jquery[/-]v?(\d+\.\d+\.\d+)', 'jquery', 'npm'),
                (r'jquery.*version["\s:]+["\']?(\d+\.\d+\.\d+)', 'jquery', 'npm'),
                (r'angular(?:\.min)?\.js.*?(\d+\.\d+\.\d+)', 'angular', 'npm'),
                (r'vue(?:\.min)?\.js.*?(\d+\.\d+\.\d+)', 'vue', 'npm'),
                (r'react(?:-dom)?(?:\.min)?\.js.*?(\d+\.\d+\.\d+)', 'react', 'npm'),
                (r'bootstrap[/-]v?(\d+\.\d+\.\d+)', 'bootstrap', 'npm'),
                (r'lodash[/-]v?(\d+\.\d+\.\d+)', 'lodash', 'npm'),
                (r'moment[/-]v?(\d+\.\d+\.\d+)', 'moment', 'npm'),
                (r'axios[/-]v?(\d+\.\d+\.\d+)', 'axios', 'npm'),
                (r'dompurify[/-]v?(\d+\.\d+\.\d+)', 'dompurify', 'npm'),
                (r'marked[/-]v?(\d+\.\d+\.\d+)', 'marked', 'npm'),
                (r'handlebars[/-]v?(\d+\.\d+\.\d+)', 'handlebars', 'npm'),
            ]
            
            found_vulns = []
            
            for pattern, package_name, ecosystem in js_packages:
                match = re.search(pattern, body, re.I)
                if match:
                    detected_version = match.group(1)
                    
                    # Query OSV for this JS library
                    vulns = await self._query_osv(package_name, detected_version, ecosystem)
                    
                    if vulns:
                        cve_ids = []
                        for v in vulns:
                            for alias in v.get("aliases", []):
                                if alias.startswith("CVE-"):
                                    cve_ids.append(alias)
                        
                        found_vulns.append({
                            "library": package_name,
                            "version": detected_version,
                            "vuln_count": len(vulns),
                            "cves": cve_ids[:3]
                        })
            
            if found_vulns:
                v = found_vulns[0]
                cve_str = ', '.join(v['cves']) if v['cves'] else 'check OSV'
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.95,
                    evidence=f"Vulnerable JS library: {v['library']} {v['version']} ({v['vuln_count']} vulns). CVEs: {cve_str}",
                    validation_method="Supply Chain - JS Library (OSV)",
                    details={"vulnerable_libraries": found_vulns}
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No vulnerable JavaScript libraries detected",
                validation_method="Supply Chain - JS Library"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Supply Chain - JS Library"
            )
    
    # =========================================================================
    # GENERIC SUPPLY CHAIN
    # =========================================================================
    
    async def _validate_generic_supply_chain(self, vuln: VulnReport) -> ValidationReport:
        """Generic supply chain validation - comprehensive scan"""
        # Use OSV-based validation as primary method
        result = await self._validate_with_osv(vuln)
        
        if result.result in (ValidationResult.CONFIRMED, ValidationResult.HIGH):
            return result
        
        # If OSV found nothing, check JS libraries specifically
        js_result = await self._validate_js_libraries(vuln)
        
        if js_result.result in (ValidationResult.CONFIRMED, ValidationResult.HIGH):
            return js_result
        
        # If agent provided evidence, give partial credit
        if vuln.evidence:
            return ValidationReport(
                result=ValidationResult.MEDIUM,
                confidence=0.5,
                evidence=f"Supply chain issue reported: {vuln.evidence[:100]} - manual verification recommended",
                validation_method="Supply Chain - Agent Report"
            )
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="No vulnerable components detected",
            validation_method="Supply Chain"
        )
    
    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        def normalize(v):
            parts = re.sub(r'[^\d.]', '', str(v)).split('.')
            return [int(x) if x else 0 for x in parts]
        
        try:
            v1_parts = normalize(v1)
            v2_parts = normalize(v2)
            
            for i in range(max(len(v1_parts), len(v2_parts))):
                p1 = v1_parts[i] if i < len(v1_parts) else 0
                p2 = v2_parts[i] if i < len(v2_parts) else 0
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            return 0
        except:
            return 0