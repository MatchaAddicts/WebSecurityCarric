"""
A04:2025 - Cryptographic Failures Validator
===========================================
OWASP Top 10 2025 - A04 (was A02 in 2021)

Focuses on failures related to cryptography which often lead to 
sensitive data exposure or system compromise.

This category shifted from "Sensitive Data Exposure" (symptom) to 
"Cryptographic Failures" (root cause) to better address the underlying issues.

Validates:
- Sensitive data transmitted in cleartext (HTTP instead of HTTPS)
- Weak/deprecated cryptographic algorithms (MD5, SHA1, DES, RC4)
- Weak password hashing
- Missing/improper TLS configuration
- Exposed credentials/secrets/API keys
- Hardcoded cryptographic keys
- Sensitive data in URLs (tokens, passwords in query strings)
- Improper certificate validation
- Weak random number generation
- Sensitive data in browser storage
"""

import re
import base64
import hashlib
from typing import Optional, Dict, List, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)


class A04_CryptoValidator(BaseValidator):
    """
    Validates Cryptographic Failures (OWASP 2025 A04).
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if "PLAINTEXT" in vuln_subtype or "CLEARTEXT" in vuln_subtype or "HTTP" in vuln_subtype:
            return await self._validate_plaintext_transmission(vuln)
        
        elif "HASH" in vuln_subtype or "MD5" in vuln_subtype or "SHA1" in vuln_subtype:
            return await self._validate_weak_hashing(vuln)
        
        elif "TLS" in vuln_subtype or "SSL" in vuln_subtype or "HTTPS" in vuln_subtype or "CERTIFICATE" in vuln_subtype:
            return await self._validate_tls_issues(vuln)
        
        elif any(x in vuln_subtype for x in ["CREDENTIAL", "PASSWORD", "SECRET", "API", "KEY", "TOKEN"]):
            return await self._validate_exposed_secrets(vuln)
        
        elif "HARDCODED" in vuln_subtype or "HARDCODE" in vuln_subtype:
            return await self._validate_hardcoded_secrets(vuln)
        
        elif "CIPHER" in vuln_subtype or "ENCRYPTION" in vuln_subtype or "DES" in vuln_subtype or "RC4" in vuln_subtype:
            return await self._validate_weak_cipher(vuln)
        
        elif "URL" in vuln_subtype or "QUERY" in vuln_subtype:
            return await self._validate_sensitive_url_data(vuln)
        
        elif "RANDOM" in vuln_subtype or "PRNG" in vuln_subtype:
            return await self._validate_weak_randomness(vuln)
        
        elif "STORAGE" in vuln_subtype or "LOCALSTORAGE" in vuln_subtype or "COOKIE" in vuln_subtype:
            return await self._validate_insecure_storage(vuln)
        
        else:
            return await self._validate_generic_crypto(vuln)
    
    # =========================================================================
    # PLAINTEXT TRANSMISSION
    # =========================================================================
    
    async def _validate_plaintext_transmission(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for sensitive data transmitted over HTTP (not HTTPS).
        This is a root cause of many data breaches.
        """
        try:
            # Check if endpoint is HTTP
            is_http = vuln.endpoint.startswith("http://")
            
            if is_http:
                status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
                
                # Sensitive data patterns in response
                sensitive_patterns = [
                    # Form fields
                    (r'type\s*=\s*["\']?password', "Password input field"),
                    (r'name\s*=\s*["\']?password', "Password field"),
                    (r'name\s*=\s*["\']?(?:credit.?card|cc.?num|card.?number)', "Credit card field"),
                    (r'name\s*=\s*["\']?(?:ssn|social.?security)', "SSN field"),
                    (r'name\s*=\s*["\']?(?:cvv|cvc|security.?code)', "CVV field"),
                    (r'autocomplete\s*=\s*["\']?cc-', "Credit card autocomplete"),
                    
                    # API responses
                    (r'"password"\s*:', "Password in JSON"),
                    (r'"credit.?card"\s*:', "Credit card in JSON"),
                    (r'"ssn"\s*:', "SSN in JSON"),
                    (r'"api.?key"\s*:', "API key in JSON"),
                    (r'"secret"\s*:', "Secret in JSON"),
                    (r'"token"\s*:\s*"[^"]{20,}"', "Token in JSON"),
                    (r'"private.?key"\s*:', "Private key in JSON"),
                    
                    # Login/Auth pages
                    (r'<form[^>]*action\s*=\s*["\']?http://', "Form submits to HTTP"),
                    (r'login|signin|authenticate', "Authentication page"),
                ]
                
                for pattern, description in sensitive_patterns:
                    if re.search(pattern, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=1.0,
                            evidence=f"Sensitive data ({description}) transmitted over HTTP (unencrypted)",
                            validation_method="Plaintext Transmission",
                            details={"pattern": description, "protocol": "HTTP"}
                        )
                
                # Even without obvious sensitive fields, HTTP for any page is concerning
                return ValidationReport(
                    result=ValidationResult.HIGH,
                    confidence=0.85,
                    evidence="Page served over HTTP - all data transmitted in plaintext",
                    validation_method="Plaintext Transmission",
                    details={"url": vuln.endpoint}
                )
            
            # Check if HTTPS page loads HTTP resources (mixed content)
            if vuln.endpoint.startswith("https://"):
                status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
                
                mixed_content_patterns = [
                    r'src\s*=\s*["\']http://',
                    r'href\s*=\s*["\']http://[^"\']*\.(js|css)',
                    r'action\s*=\s*["\']http://',
                    r'url\s*\(\s*["\']?http://',
                ]
                
                for pattern in mixed_content_patterns:
                    if re.search(pattern, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.9,
                            evidence="Mixed content: HTTPS page loads HTTP resources",
                            validation_method="Plaintext Transmission - Mixed Content"
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No plaintext transmission issues detected",
                validation_method="Plaintext Transmission"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Plaintext Transmission"
            )
    
    # =========================================================================
    # WEAK HASHING
    # =========================================================================
    
    async def _validate_weak_hashing(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for weak hashing algorithms used for passwords or sensitive data.
        MD5 and SHA1 are cryptographically broken for password storage.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            # Patterns for exposed hashes
            weak_hash_patterns = [
                # MD5 hashes (32 hex chars)
                (r'["\']?(?:password|pass|pwd|hash)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{32})["\']?', "MD5 hash"),
                (r'\b([a-fA-F0-9]{32})\b', "Potential MD5 hash"),
                
                # SHA1 hashes (40 hex chars)
                (r'["\']?(?:password|pass|pwd|hash)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{40})["\']?', "SHA1 hash"),
                
                # Unsalted hash function calls in code
                (r'md5\s*\([^)]*password', "MD5 password hashing"),
                (r'sha1\s*\([^)]*password', "SHA1 password hashing"),
                (r'hashlib\.md5\s*\(', "Python MD5"),
                (r'hashlib\.sha1\s*\(', "Python SHA1"),
                (r'MessageDigest\.getInstance\s*\(\s*["\']MD5', "Java MD5"),
                (r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1', "Java SHA1"),
                (r'hash\s*\(\s*["\']md5', "PHP MD5"),
                (r'hash\s*\(\s*["\']sha1', "PHP SHA1"),
                (r'Digest::MD5', "Ruby MD5"),
                (r'Digest::SHA1', "Ruby SHA1"),
                (r'crypto\.createHash\s*\(\s*["\']md5', "Node.js MD5"),
                (r'crypto\.createHash\s*\(\s*["\']sha1', "Node.js SHA1"),
                
                # MySQL weak password functions
                (r'PASSWORD\s*\(\s*["\']', "MySQL PASSWORD() - weak"),
                (r'OLD_PASSWORD\s*\(', "MySQL OLD_PASSWORD() - very weak"),
                
                # Unsalted patterns
                (r'(?:password|secret)\s*=\s*(?:md5|sha1)\(', "Unsalted hash"),
            ]
            
            for pattern, description in weak_hash_patterns:
                match = re.search(pattern, body, re.I)
                if match:
                    # Validate if it's really a hash (for the generic patterns)
                    if "Potential MD5" in description:
                        # Check context - only flag if near sensitive keywords
                        start = max(0, match.start() - 50)
                        context = body[start:match.end() + 50].lower()
                        if not any(kw in context for kw in ['password', 'pass', 'hash', 'user', 'auth', 'login']):
                            continue
                    
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Weak hashing detected: {description}",
                        validation_method="Weak Hashing",
                        details={"type": description}
                    )
            
            # Check response headers for hash disclosure
            # Some apps incorrectly expose hashes in custom headers
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No weak hashing detected",
                validation_method="Weak Hashing"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Weak Hashing"
            )
    
    # =========================================================================
    # TLS/SSL ISSUES
    # =========================================================================
    
    async def _validate_tls_issues(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for TLS/SSL configuration issues.
        """
        try:
            # Test 1: Check if HTTP is available without redirect
            if vuln.endpoint.startswith("https://"):
                http_url = vuln.endpoint.replace("https://", "http://")
            else:
                http_url = vuln.endpoint
            
            try:
                status, body, headers = await self._request(
                    "GET", http_url, 
                    headers=vuln.headers,
                    allow_redirects=False
                )
                
                # Check if HTTP redirects to HTTPS
                location = headers.get("Location", headers.get("location", ""))
                
                if status in (301, 302, 307, 308) and "https://" in location.lower():
                    # Good - redirects to HTTPS
                    pass
                elif status == 200:
                    # Bad - HTTP accessible without redirect
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence="Site accessible over HTTP without redirect to HTTPS",
                        validation_method="TLS Issues - No HTTPS Redirect",
                        details={"http_status": status}
                    )
            except:
                pass  # HTTP not accessible is fine
            
            # Test 2: Check HSTS header
            https_url = vuln.endpoint if vuln.endpoint.startswith("https://") else vuln.endpoint.replace("http://", "https://")
            
            try:
                status, body, headers = await self._request("GET", https_url, headers=vuln.headers)
                headers_lower = {k.lower(): v for k, v in headers.items()}
                
                if "strict-transport-security" not in headers_lower:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.85,
                        evidence="Missing HSTS header - vulnerable to SSL stripping attacks",
                        validation_method="TLS Issues - Missing HSTS",
                        details={"recommendation": "Add Strict-Transport-Security header"}
                    )
                else:
                    # Check HSTS configuration
                    hsts_value = headers_lower["strict-transport-security"]
                    
                    # Check max-age
                    max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts_value, re.I)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 31536000:  # Less than 1 year
                            return ValidationReport(
                                result=ValidationResult.MEDIUM,
                                confidence=0.75,
                                evidence=f"HSTS max-age too short: {max_age} seconds (should be >= 31536000)",
                                validation_method="TLS Issues - Weak HSTS"
                            )
                    
                    # Check for includeSubDomains
                    if "includesubdomains" not in hsts_value.lower():
                        return ValidationReport(
                            result=ValidationResult.MEDIUM,
                            confidence=0.7,
                            evidence="HSTS missing includeSubDomains directive",
                            validation_method="TLS Issues - Incomplete HSTS"
                        )
            except:
                pass
            
            # Test 3: Check for certificate validation bypass in code
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            cert_bypass_patterns = [
                (r'verify\s*=\s*False', "Python requests verify=False"),
                (r'CERT_NONE', "SSL CERT_NONE"),
                (r'InsecureRequestWarning', "Insecure request warning suppressed"),
                (r'check_hostname\s*=\s*False', "Hostname check disabled"),
                (r'ssl[_-]?verify[_-]?peer\s*=\s*(?:false|0)', "Peer verification disabled"),
                (r'CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)', "CURL SSL verify disabled"),
                (r'CURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)', "CURL host verify disabled"),
                (r'rejectUnauthorized\s*:\s*false', "Node.js rejectUnauthorized=false"),
                (r'ServerCertificateValidationCallback\s*=.*true', ".NET cert validation bypass"),
                (r'TrustSelfSignedStrategy', "Java trust self-signed"),
                (r'X509TrustManager.*checkServerTrusted.*\{\s*\}', "Java empty trust manager"),
            ]
            
            for pattern, description in cert_bypass_patterns:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Certificate validation bypass: {description}",
                        validation_method="TLS Issues - Cert Bypass",
                        details={"issue": description}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No TLS/SSL issues detected",
                validation_method="TLS Issues"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="TLS Issues"
            )
    
    # =========================================================================
    # EXPOSED SECRETS
    # =========================================================================
    
    async def _validate_exposed_secrets(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for exposed credentials, API keys, tokens, and other secrets.
        """
        try:
            status, body, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            # Comprehensive secret patterns
            secret_patterns = [
                # AWS
                (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
                (r'(?:aws)?[_-]?secret[_-]?(?:access)?[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
                (r'(?:aws)?[_-]?session[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]+)', "AWS Session Token"),
                
                # GCP
                (r'"type"\s*:\s*"service_account"', "GCP Service Account JSON"),
                (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
                (r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com', "Google OAuth Client ID"),
                
                # Azure
                (r'AccountKey=[A-Za-z0-9+/=]{88}', "Azure Storage Key"),
                (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', "Azure Client ID (GUID)"),
                
                # GitHub
                (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
                (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
                (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Token"),
                (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server Token"),
                (r'ghr_[a-zA-Z0-9]{36}', "GitHub Refresh Token"),
                
                # Stripe
                (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Live Secret Key"),
                (r'sk_test_[a-zA-Z0-9]{24,}', "Stripe Test Secret Key"),
                (r'rk_live_[a-zA-Z0-9]{24,}', "Stripe Restricted Key"),
                
                # Slack
                (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', "Slack Token"),
                (r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+', "Slack Webhook"),
                
                # Discord
                (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', "Discord Bot Token"),
                (r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', "Discord Webhook"),
                
                # Twilio
                (r'SK[a-f0-9]{32}', "Twilio API Key"),
                (r'AC[a-f0-9]{32}', "Twilio Account SID"),
                
                # SendGrid
                (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
                
                # Mailgun
                (r'key-[a-zA-Z0-9]{32}', "Mailgun API Key"),
                
                # Database Connection Strings
                (r'(?:mysql|postgres|postgresql|mongodb|redis)://[^:]+:([^@]+)@', "Database Password in URL"),
                (r'(?:mongodb\+srv|postgres|mysql)://[^\s"\']+', "Database Connection String"),
                
                # Generic Patterns
                (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', "API Key"),
                (r'(?:auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_.-]{20,})', "Auth Token"),
                (r'(?:secret[_-]?key|private[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', "Secret Key"),
                (r'bearer\s+[a-zA-Z0-9_.-]{20,}', "Bearer Token"),
                (r'basic\s+[a-zA-Z0-9+/=]{20,}', "Basic Auth Credentials"),
                
                # Private Keys
                (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
                (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key"),
                
                # JWT with sensitive data
                (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),
                
                # Password patterns
                (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
                (r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
            ]
            
            found_secrets = []
            
            for pattern, description in secret_patterns:
                matches = re.finditer(pattern, body, re.I)
                for match in matches:
                    # Avoid false positives
                    secret_value = match.group(0)
                    
                    # Skip obvious placeholders
                    if any(placeholder in secret_value.lower() for placeholder in 
                           ['example', 'xxxxx', '00000', 'your_', 'insert', 'placeholder', 'changeme']):
                        continue
                    
                    found_secrets.append({
                        "type": description,
                        "location": match.start()
                    })
            
            if found_secrets:
                # Group by type and report
                secret_types = list(set([s["type"] for s in found_secrets]))
                
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=1.0,
                    evidence=f"Exposed secrets found: {', '.join(secret_types[:3])}{'...' if len(secret_types) > 3 else ''}",
                    validation_method="Exposed Secrets",
                    details={
                        "secret_types": secret_types,
                        "count": len(found_secrets)
                    }
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No exposed secrets detected",
                validation_method="Exposed Secrets"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Exposed Secrets"
            )
    
    # =========================================================================
    # HARDCODED SECRETS
    # =========================================================================
    
    async def _validate_hardcoded_secrets(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for hardcoded cryptographic keys and secrets in code.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            hardcoded_patterns = [
                # Encryption keys
                (r'(?:aes|des|rsa|encryption)[_-]?key\s*=\s*["\'][a-zA-Z0-9+/=]{16,}["\']', "Hardcoded encryption key"),
                (r'(?:secret|private)[_-]?key\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded secret key"),
                (r'crypto\.(?:createCipheriv|createDecipheriv)\s*\([^,]+,\s*["\'][^"\']+["\']', "Hardcoded cipher key"),
                
                # IV/Nonce (should be random, not hardcoded)
                (r'(?:iv|nonce|initialization.?vector)\s*=\s*["\'][a-fA-F0-9]{16,}["\']', "Hardcoded IV/Nonce"),
                (r'(?:iv|nonce)\s*=\s*(?:new\s+)?(?:byte|Uint8Array)\s*\[\s*\]\s*\{[^}]+\}', "Hardcoded IV bytes"),
                
                # Salt (should be random per-password)
                (r'salt\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded salt"),
                (r'\.pbkdf2[^(]*\([^,]+,\s*["\'][^"\']+["\']', "Hardcoded PBKDF2 salt"),
                
                # JWT secrets
                (r'jwt[_-]?secret\s*=\s*["\'][^"\']{16,}["\']', "Hardcoded JWT secret"),
                (r'\.sign\s*\([^,]+,\s*["\'][^"\']{16,}["\']', "Hardcoded signing secret"),
                
                # Base64 encoded keys
                (r'key\s*=\s*(?:atob|base64\.decode|Base64\.decode)\s*\(["\'][A-Za-z0-9+/=]{20,}["\']', "Base64 encoded key"),
                
                # Hex encoded keys
                (r'key\s*=\s*(?:hex\.decode|Buffer\.from)\s*\(["\'][a-fA-F0-9]{32,}["\']', "Hex encoded key"),
            ]
            
            for pattern, description in hardcoded_patterns:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Hardcoded cryptographic secret: {description}",
                        validation_method="Hardcoded Secrets",
                        details={"type": description}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No hardcoded secrets detected",
                validation_method="Hardcoded Secrets"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Hardcoded Secrets"
            )
    
    # =========================================================================
    # WEAK CIPHER
    # =========================================================================
    
    async def _validate_weak_cipher(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for weak/deprecated cipher usage.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            weak_cipher_patterns = [
                # DES (56-bit, broken)
                (r'DES(?!ede|3)', "DES cipher (56-bit, broken)"),
                (r'DESede', "3DES cipher (deprecated)"),
                (r'(?:create|get).*(?:DES|TripleDES)', "DES/3DES usage"),
                
                # RC4 (biased keystream)
                (r'RC4|ARCFOUR|ARC4', "RC4 cipher (broken)"),
                
                # RC2 (weak)
                (r'RC2', "RC2 cipher (weak)"),
                
                # Blowfish (limited block size)
                (r'Blowfish', "Blowfish cipher (limited)"),
                
                # ECB mode (no diffusion)
                (r'ECB', "ECB mode (no diffusion)"),
                (r'AES/ECB', "AES with ECB mode"),
                (r'createCipher\s*\(\s*["\'](?:aes|des)[^"\']*["\']', "Deprecated createCipher (uses ECB)"),
                
                # NULL cipher
                (r'NULL', "NULL cipher"),
                (r'eNULL', "Export NULL cipher"),
                
                # Export ciphers
                (r'EXPORT', "Export cipher (weak)"),
                (r'EXP-', "Export cipher suite"),
                
                # Anonymous ciphers
                (r'aNULL|ADH|AECDH', "Anonymous cipher (no auth)"),
                
                # MD5 in cipher suites
                (r'MD5WithRSA|MD5withRSA', "MD5 with RSA"),
                (r'-MD5\b', "MD5 in cipher suite"),
                
                # Low strength ciphers
                (r'LOW', "Low strength cipher"),
                (r'MEDIUM', "Medium strength cipher"),
                
                # SSLv2/SSLv3
                (r'SSLv2|SSLv3', "Deprecated SSL version"),
                (r'TLSv1(?:[^.12]|$)', "Deprecated TLS 1.0"),
            ]
            
            for pattern, description in weak_cipher_patterns:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Weak cipher detected: {description}",
                        validation_method="Weak Cipher",
                        details={"cipher": description}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No weak ciphers detected",
                validation_method="Weak Cipher"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Weak Cipher"
            )
    
    # =========================================================================
    # SENSITIVE DATA IN URL
    # =========================================================================
    
    async def _validate_sensitive_url_data(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for sensitive data in URLs (query strings, paths).
        URLs are logged, cached, and visible in browser history.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            # Check for sensitive data in links
            url_patterns = [
                # Password in URL
                (r'href\s*=\s*["\'][^"\']*[?&](?:password|passwd|pwd)=[^&"\']+', "Password in URL"),
                (r'href\s*=\s*["\'][^"\']*[?&](?:token|auth|session)=[^&"\']+', "Auth token in URL"),
                (r'href\s*=\s*["\'][^"\']*[?&](?:api[_-]?key|apikey)=[^&"\']+', "API key in URL"),
                (r'href\s*=\s*["\'][^"\']*[?&](?:secret|private)=[^&"\']+', "Secret in URL"),
                (r'href\s*=\s*["\'][^"\']*[?&](?:credit|card|cc)=[^&"\']+', "Credit card in URL"),
                (r'href\s*=\s*["\'][^"\']*[?&]ssn=[^&"\']+', "SSN in URL"),
                
                # Form action with sensitive params
                (r'action\s*=\s*["\'][^"\']*[?&](?:password|token|secret)=[^&"\']+', "Sensitive data in form action"),
                
                # JavaScript URLs
                (r'(?:location|window\.location|document\.location)[^=]*=\s*[^;]*[?&](?:password|token|api[_-]?key)', "Sensitive data in redirect"),
                
                # Fetch/XHR with sensitive params
                (r'fetch\s*\([^)]*[?&](?:password|token|api[_-]?key)', "Sensitive data in fetch URL"),
                (r'\.(?:get|post|ajax)\s*\([^)]*[?&](?:password|token|api[_-]?key)', "Sensitive data in AJAX URL"),
            ]
            
            for pattern, description in url_patterns:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"Sensitive data in URL: {description}",
                        validation_method="Sensitive URL Data",
                        details={"issue": description}
                    )
            
            # Check the current URL itself
            url_lower = vuln.endpoint.lower()
            sensitive_params = ['password', 'passwd', 'pwd', 'token', 'auth', 'session', 'api_key', 'apikey', 'secret', 'private_key']
            
            for param in sensitive_params:
                if f'{param}=' in url_lower:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=1.0,
                        evidence=f"Sensitive parameter '{param}' in request URL",
                        validation_method="Sensitive URL Data",
                        details={"parameter": param}
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No sensitive data in URLs detected",
                validation_method="Sensitive URL Data"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Sensitive URL Data"
            )
    
    # =========================================================================
    # WEAK RANDOMNESS
    # =========================================================================
    
    async def _validate_weak_randomness(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for weak random number generation.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            weak_random_patterns = [
                # JavaScript
                (r'Math\.random\s*\(\s*\)', "Math.random() - not cryptographically secure"),
                (r'new Date\(\)\.getTime\(\)', "Timestamp as random seed"),
                (r'Date\.now\(\)', "Date.now() as random value"),
                
                # Python
                (r'random\.random\s*\(', "Python random.random() - not secure"),
                (r'random\.randint\s*\(', "Python random.randint() - not secure"),
                (r'random\.choice\s*\(', "Python random.choice() - not secure"),
                
                # Java
                (r'new\s+Random\s*\(', "Java Random - not secure"),
                (r'Math\.random\s*\(', "Java Math.random() - not secure"),
                
                # PHP
                (r'\brand\s*\(', "PHP rand() - not secure"),
                (r'\bmt_rand\s*\(', "PHP mt_rand() - not secure"),
                (r'uniqid\s*\(', "PHP uniqid() - predictable"),
                
                # Ruby
                (r'Random\.rand', "Ruby Random.rand - not secure"),
                (r'rand\s*\(', "Ruby rand() - not secure"),
                
                # C/C++
                (r'\brand\s*\(', "C rand() - not secure"),
                (r'srand\s*\(\s*time', "C srand(time()) - predictable"),
                
                # .NET
                (r'new\s+Random\s*\(', ".NET Random - not secure"),
            ]
            
            for pattern, description in weak_random_patterns:
                # Check context - only flag if used for security purposes
                matches = list(re.finditer(pattern, body, re.I))
                for match in matches:
                    start = max(0, match.start() - 100)
                    end = min(len(body), match.end() + 100)
                    context = body[start:end].lower()
                    
                    security_keywords = ['token', 'secret', 'password', 'key', 'session', 'auth', 
                                        'nonce', 'salt', 'iv', 'seed', 'crypto', 'secure']
                    
                    if any(kw in context for kw in security_keywords):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.9,
                            evidence=f"Weak randomness for security: {description}",
                            validation_method="Weak Randomness",
                            details={"pattern": description}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No weak randomness detected in security context",
                validation_method="Weak Randomness"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Weak Randomness"
            )
    
    # =========================================================================
    # INSECURE STORAGE
    # =========================================================================
    
    async def _validate_insecure_storage(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for sensitive data stored insecurely in browser.
        """
        try:
            status, body, _ = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            insecure_storage_patterns = [
                # LocalStorage
                (r'localStorage\.setItem\s*\([^,]*(?:password|token|secret|key|auth|session|credit)', "Sensitive data in localStorage"),
                (r'localStorage\[[\'"]\s*(?:password|token|secret|key|auth|session)', "Sensitive data in localStorage"),
                
                # SessionStorage
                (r'sessionStorage\.setItem\s*\([^,]*(?:password|token|secret|key|auth)', "Sensitive data in sessionStorage"),
                
                # Cookies without security flags
                (r'document\.cookie\s*=\s*[^;]*(?:password|token|secret)', "Sensitive data in JS cookie"),
                
                # IndexedDB
                (r'(?:indexedDB|IDBDatabase)[^;]*(?:password|token|secret|key)', "Sensitive data in IndexedDB"),
                
                # WebSQL (deprecated but still used)
                (r'openDatabase[^;]*(?:password|token|secret)', "Sensitive data in WebSQL"),
            ]
            
            for pattern, description in insecure_storage_patterns:
                if re.search(pattern, body, re.I):
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.9,
                        evidence=f"Insecure browser storage: {description}",
                        validation_method="Insecure Storage",
                        details={"issue": description}
                    )
            
            # Check for cookies without Secure/HttpOnly flags in Set-Cookie header
            _, _, headers = await self._request("GET", vuln.endpoint, headers=vuln.headers)
            
            set_cookie = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
            if set_cookie:
                # Check for sensitive-looking cookies without security flags
                sensitive_cookie_names = ['session', 'auth', 'token', 'jwt', 'user', 'login', 'credential']
                
                for name in sensitive_cookie_names:
                    if name in set_cookie.lower():
                        if 'secure' not in set_cookie.lower():
                            return ValidationReport(
                                result=ValidationResult.HIGH,
                                confidence=0.85,
                                evidence=f"Sensitive cookie '{name}' missing Secure flag",
                                validation_method="Insecure Storage - Cookie"
                            )
                        if 'httponly' not in set_cookie.lower():
                            return ValidationReport(
                                result=ValidationResult.HIGH,
                                confidence=0.85,
                                evidence=f"Sensitive cookie '{name}' missing HttpOnly flag",
                                validation_method="Insecure Storage - Cookie"
                            )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No insecure storage issues detected",
                validation_method="Insecure Storage"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Insecure Storage"
            )
    
    # =========================================================================
    # GENERIC CRYPTO VALIDATION
    # =========================================================================
    
    async def _validate_generic_crypto(self, vuln: VulnReport) -> ValidationReport:
        """Generic cryptographic failure validation - try multiple checks"""
        results = [
            await self._validate_exposed_secrets(vuln),
            await self._validate_weak_hashing(vuln),
            await self._validate_plaintext_transmission(vuln),
            await self._validate_tls_issues(vuln),
        ]
        
        # Return best result
        best = max(results, key=lambda r: r.confidence)
        
        if best.confidence > 0:
            return best
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="Could not confirm cryptographic failure",
            validation_method="Generic Crypto"
        )