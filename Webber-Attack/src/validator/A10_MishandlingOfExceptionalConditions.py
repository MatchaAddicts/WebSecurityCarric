"""
A10:2025 - Mishandling of Exceptional Conditions Validator
==========================================================
OWASP Top 10 2025 - A10 (NEW)

This is a NEW category for 2025, containing 24 CWEs focusing on:
- Improper error handling
- Logical errors
- Failing open (instead of failing secure)
- Resource exhaustion
- Unhandled exceptions
- Improper state management

Previously grouped under "poor code quality", these issues now have 
their own category due to their significant security impact.

Key principle: Systems should FAIL CLOSED (deny by default on error),
not FAIL OPEN (allow by default on error).

Validates:
- Fail open behavior (auth bypass on error)
- Unhandled exceptions exposing sensitive info
- Resource exhaustion / DoS conditions
- Improper null/empty handling
- Integer overflow/underflow
- Divide by zero handling
- Timeout handling issues
- Memory exhaustion
- File handle exhaustion
- Connection pool exhaustion
- Improper state transitions
- Error-based information disclosure
- Crash-inducing inputs
"""

import re
import time
import asyncio
import urllib.parse
from typing import Optional, Dict, List, Tuple

from .base import (
    BaseValidator,
    ValidationResult,
    ValidationReport,
    VulnReport,
)


class A10_ExceptionalConditionsValidator(BaseValidator):
    """
    Validates Mishandling of Exceptional Conditions (OWASP 2025 A10 - NEW).
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if any(x in vuln_subtype for x in ["FAIL OPEN", "FAILOPEN", "BYPASS"]):
            return await self._validate_fail_open(vuln)
        
        elif any(x in vuln_subtype for x in ["EXCEPTION", "UNHANDLED", "CRASH"]):
            return await self._validate_unhandled_exception(vuln)
        
        elif any(x in vuln_subtype for x in ["DOS", "DENIAL", "EXHAUST", "RESOURCE"]):
            return await self._validate_resource_exhaustion(vuln)
        
        elif any(x in vuln_subtype for x in ["NULL", "EMPTY", "UNDEFINED"]):
            return await self._validate_null_handling(vuln)
        
        elif any(x in vuln_subtype for x in ["OVERFLOW", "UNDERFLOW", "INTEGER"]):
            return await self._validate_integer_issues(vuln)
        
        elif any(x in vuln_subtype for x in ["DIVIDE", "ZERO", "DIVISION"]):
            return await self._validate_divide_by_zero(vuln)
        
        elif any(x in vuln_subtype for x in ["TIMEOUT", "HANG", "DEADLOCK"]):
            return await self._validate_timeout_handling(vuln)
        
        elif any(x in vuln_subtype for x in ["STATE", "TRANSITION", "INCONSISTENT"]):
            return await self._validate_state_handling(vuln)
        
        elif any(x in vuln_subtype for x in ["ERROR", "DISCLOSURE", "LEAK"]):
            return await self._validate_error_disclosure(vuln)
        
        elif any(x in vuln_subtype for x in ["MEMORY", "OOM", "HEAP"]):
            return await self._validate_memory_exhaustion(vuln)
        
        else:
            return await self._validate_generic_exceptional(vuln)
    
    # =========================================================================
    # FAIL OPEN BEHAVIOR
    # =========================================================================
    
    async def _validate_fail_open(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for fail-open behavior where errors cause security bypass.
        
        Fail Open: System grants access when an error occurs (INSECURE)
        Fail Closed: System denies access when an error occurs (SECURE)
        
        Example: Auth service timeout = user granted access (BAD!)
        """
        try:
            # Test 1: Malformed authentication data
            malformed_auth_tests = [
                # Malformed tokens
                {"Authorization": "Bearer INVALID_TOKEN_12345"},
                {"Authorization": "Bearer "},
                {"Authorization": "Bearer null"},
                {"Authorization": "Bearer undefined"},
                {"Authorization": "Basic AAAAAAAA"},  # Invalid base64
                {"Authorization": "InvalidScheme token"},
                
                # Malformed cookies
                {"Cookie": "session=INVALID; auth=BROKEN"},
                {"Cookie": "session=; auth="},
                {"Cookie": "session=null"},
                
                # Malformed headers
                {"X-Auth-Token": "MALFORMED"},
                {"X-API-Key": "INVALID_KEY"},
            ]
            
            for auth_header in malformed_auth_tests:
                headers = {**vuln.headers, **auth_header}
                
                try:
                    status, body, resp_headers = await self._request(
                        vuln.method or "GET",
                        vuln.endpoint,
                        headers=headers,
                        data=vuln.body
                    )
                    
                    # Check if access was granted despite invalid auth
                    if status == 200:
                        # Look for signs of authenticated content
                        auth_content_indicators = [
                            r'dashboard',
                            r'welcome.*user',
                            r'logout',
                            r'profile',
                            r'settings',
                            r'account',
                            r'"authenticated"\s*:\s*true',
                            r'"loggedIn"\s*:\s*true',
                            r'admin',
                        ]
                        
                        for indicator in auth_content_indicators:
                            if re.search(indicator, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"FAIL OPEN: Access granted with malformed auth ({list(auth_header.keys())[0]})",
                                    validation_method="Fail Open - Auth Bypass",
                                    details={"malformed_header": auth_header}
                                )
                except asyncio.TimeoutError:
                    # Timeout might also trigger fail-open
                    pass
            
            # Test 2: Trigger errors to see if they cause bypass
            error_triggers = [
                ("Content-Type", "invalid/type"),
                ("Content-Length", "-1"),
                ("Content-Length", "99999999999"),
                ("Accept", "../../../etc/passwd"),
                ("Host", "localhost:0"),
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Original-URL", "/admin"),
                ("X-Rewrite-URL", "/admin"),
            ]
            
            for header_name, header_value in error_triggers:
                headers = {**vuln.headers, header_name: header_value}
                
                try:
                    status, body, _ = await self._request(
                        vuln.method or "GET",
                        vuln.endpoint,
                        headers=headers
                    )
                    
                    # Check if error caused unexpected access
                    if status == 200 and len(body) > 100:
                        # Check for sensitive content that shouldn't be accessible
                        sensitive_patterns = [
                            r'password',
                            r'secret',
                            r'api[_-]?key',
                            r'private',
                            r'internal',
                            r'admin',
                            r'root',
                        ]
                        
                        for pattern in sensitive_patterns:
                            if re.search(pattern, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.HIGH,
                                    confidence=0.85,
                                    evidence=f"Potential fail-open: Malformed {header_name} header returned sensitive content",
                                    validation_method="Fail Open - Header Manipulation",
                                    details={"header": header_name, "value": header_value}
                                )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No fail-open behavior detected",
                validation_method="Fail Open"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Fail Open"
            )
    
    # =========================================================================
    # UNHANDLED EXCEPTIONS
    # =========================================================================
    
    async def _validate_unhandled_exception(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for unhandled exceptions that crash the application or expose info.
        """
        try:
            # Payloads designed to trigger exceptions
            exception_triggers = [
                # Type confusion
                ("[]", "Array where string expected"),
                ("{}", "Object where string expected"),
                ("null", "Null value"),
                ("undefined", "Undefined value"),
                ("NaN", "Not a Number"),
                ("Infinity", "Infinity"),
                ("-Infinity", "Negative Infinity"),
                
                # Encoding issues
                ("%C0%AE", "Overlong UTF-8"),
                ("%EF%BF%BD", "Replacement character"),
                ("\x00", "Null byte"),
                ("\xff\xfe", "BOM"),
                
                # Format string
                ("%s%s%s%s%s", "Format string"),
                ("%n%n%n%n", "Format string write"),
                ("%x%x%x%x", "Format string hex"),
                
                # Large/special numbers
                ("9" * 100, "Very large number"),
                ("0." + "0" * 100 + "1", "Very small decimal"),
                ("-" + "9" * 100, "Large negative"),
                ("1e999", "Huge exponent"),
                ("1e-999", "Tiny exponent"),
                
                # Special strings
                ("'\"<>&;|`$(){}[]\\", "Special characters"),
                ("\r\n\r\n", "CRLF injection"),
                ("../../../", "Path traversal"),
                ("<!--", "XML comment"),
                ("]]>", "CDATA end"),
            ]
            
            crash_indicators = [
                # Server errors
                (r'500\s+Internal Server Error', "500 Error"),
                (r'503\s+Service Unavailable', "503 Error"),
                (r'502\s+Bad Gateway', "502 Error"),
                
                # Exception traces
                (r'Traceback \(most recent call last\)', "Python traceback"),
                (r'Exception in thread', "Java exception"),
                (r'Unhandled Exception', "Unhandled exception"),
                (r'Fatal error', "Fatal error"),
                (r'Segmentation fault', "Segfault"),
                (r'Stack trace:', "Stack trace"),
                (r'at [\w.]+\.(java|php|py|rb|js|cs):\d+', "Code location"),
                
                # Framework crashes
                (r'Application Error', "Application error"),
                (r'Runtime Error', "Runtime error"),
                (r'Server Error in', "ASP.NET error"),
                (r'has encountered an error', "Generic crash"),
                
                # Specific exceptions
                (r'NullPointerException', "NPE"),
                (r'NullReferenceException', "Null reference"),
                (r'TypeError:', "Type error"),
                (r'ValueError:', "Value error"),
                (r'IndexError:', "Index error"),
                (r'KeyError:', "Key error"),
                (r'AttributeError:', "Attribute error"),
                (r'OutOfMemoryError', "OOM"),
                (r'StackOverflowError', "Stack overflow"),
            ]
            
            for trigger, description in exception_triggers:
                # Try in URL parameter
                test_url = f"{vuln.endpoint}?test={urllib.parse.quote(str(trigger), safe='')}"
                
                try:
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    # Check for crash indicators
                    for pattern, crash_type in crash_indicators:
                        if re.search(pattern, body, re.I) or status >= 500:
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.95,
                                evidence=f"Unhandled exception triggered by {description}: {crash_type}",
                                validation_method="Unhandled Exception",
                                details={
                                    "trigger": description,
                                    "crash_type": crash_type,
                                    "status": status
                                }
                            )
                except asyncio.TimeoutError:
                    # Timeout could indicate crash/hang
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"Request timeout (possible crash) triggered by: {description}",
                        validation_method="Unhandled Exception - Timeout"
                    )
                except:
                    continue
            
            # Try in POST body
            if vuln.body:
                for trigger, description in exception_triggers[:10]:  # Test subset
                    try:
                        modified_body = f"{vuln.body}&crash_test={urllib.parse.quote(str(trigger), safe='')}"
                        
                        status, body, _ = await self._request(
                            "POST",
                            vuln.endpoint,
                            headers=vuln.headers,
                            data=modified_body
                        )
                        
                        if status >= 500:
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence=f"Server error (HTTP {status}) triggered by: {description}",
                                validation_method="Unhandled Exception",
                                details={"trigger": description, "status": status}
                            )
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No unhandled exceptions detected",
                validation_method="Unhandled Exception"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Unhandled Exception"
            )
    
    # =========================================================================
    # RESOURCE EXHAUSTION / DOS
    # =========================================================================
    
    async def _validate_resource_exhaustion(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for resource exhaustion vulnerabilities (DoS conditions).
        """
        try:
            # Test 1: Large input handling
            large_inputs = [
                ("A" * 10000, "10KB string"),
                ("A" * 100000, "100KB string"),
                ("&param=value" * 1000, "1000 parameters"),
                ('{"a":' * 100 + '"x"' + '}' * 100, "Deeply nested JSON"),
                ("<a>" * 100 + "x" + "</a>" * 100, "Deeply nested XML"),
            ]
            
            baseline_time = None
            
            # Get baseline response time
            try:
                start = time.time()
                await self._request("GET", vuln.endpoint, headers=vuln.headers)
                baseline_time = time.time() - start
            except:
                baseline_time = 1.0
            
            for payload, description in large_inputs:
                try:
                    test_url = f"{vuln.endpoint}?data={urllib.parse.quote(payload[:1000], safe='')}"
                    
                    start = time.time()
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    elapsed = time.time() - start
                    
                    # Check for significant slowdown (potential DoS)
                    if elapsed > baseline_time * 10 and elapsed > 5:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.9,
                            evidence=f"Resource exhaustion: {description} caused {elapsed:.2f}s response (baseline: {baseline_time:.2f}s)",
                            validation_method="Resource Exhaustion - Slowdown",
                            details={
                                "payload_type": description,
                                "response_time": elapsed,
                                "baseline": baseline_time
                            }
                        )
                    
                    # Check for error indicating resource issue
                    if status in (500, 502, 503, 504):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.85,
                            evidence=f"Resource exhaustion: {description} caused HTTP {status}",
                            validation_method="Resource Exhaustion - Server Error",
                            details={"payload_type": description, "status": status}
                        )
                        
                except asyncio.TimeoutError:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.9,
                        evidence=f"Resource exhaustion: {description} caused timeout",
                        validation_method="Resource Exhaustion - Timeout"
                    )
                except:
                    continue
            
            # Test 2: Regex DoS (ReDoS)
            redos_payloads = [
                ("a" * 30 + "!", "ReDoS - repeated char"),
                ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "ReDoS - a{30}!"),
                ("x]" * 20, "ReDoS - alternation"),
            ]
            
            for payload, description in redos_payloads:
                try:
                    test_url = f"{vuln.endpoint}?search={urllib.parse.quote(payload, safe='')}"
                    
                    start = time.time()
                    status, _, _ = await self._request("GET", test_url, headers=vuln.headers)
                    elapsed = time.time() - start
                    
                    if elapsed > 5:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.95,
                            evidence=f"ReDoS vulnerability: {description} caused {elapsed:.2f}s delay",
                            validation_method="Resource Exhaustion - ReDoS"
                        )
                except asyncio.TimeoutError:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.95,
                        evidence=f"ReDoS vulnerability: {description} caused timeout",
                        validation_method="Resource Exhaustion - ReDoS"
                    )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No resource exhaustion detected",
                validation_method="Resource Exhaustion"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Resource Exhaustion"
            )
    
    # =========================================================================
    # NULL/EMPTY HANDLING
    # =========================================================================
    
    async def _validate_null_handling(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for improper null/empty value handling.
        """
        try:
            null_values = [
                ("", "Empty string"),
                ("null", "null string"),
                ("NULL", "NULL string"),
                ("None", "None string"),
                ("undefined", "undefined string"),
                ("nil", "nil string"),
                ("%00", "Null byte"),
                ("\\0", "Escaped null"),
                ("\\x00", "Hex null"),
                ("[]", "Empty array"),
                ("{}", "Empty object"),
                ("0", "Zero"),
                ("-0", "Negative zero"),
                ("false", "false string"),
                ("NaN", "NaN"),
            ]
            
            for value, description in null_values:
                # Try as parameter value
                if vuln.parameter:
                    test_url = re.sub(
                        rf'{re.escape(vuln.parameter)}=[^&]*',
                        f'{vuln.parameter}={urllib.parse.quote(value, safe="")}',
                        vuln.endpoint
                    )
                else:
                    test_url = f"{vuln.endpoint}?param={urllib.parse.quote(value, safe='')}"
                
                try:
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    # Check for errors caused by null handling
                    null_error_patterns = [
                        r'null.*pointer',
                        r'cannot.*null',
                        r'undefined.*not.*function',
                        r'TypeError.*null',
                        r'NullReferenceException',
                        r'NoneType.*has no attribute',
                        r'nil.*error',
                        r'empty.*not allowed',
                        r'required.*field',
                    ]
                    
                    for pattern in null_error_patterns:
                        if re.search(pattern, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence=f"Improper null handling: {description} caused error",
                                validation_method="Null Handling",
                                details={"value": value, "description": description}
                            )
                    
                    if status >= 500:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.85,
                            evidence=f"Null handling error: {description} caused HTTP {status}",
                            validation_method="Null Handling",
                            details={"value": value, "status": status}
                        )
                        
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Null values handled properly",
                validation_method="Null Handling"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Null Handling"
            )
    
    # =========================================================================
    # INTEGER OVERFLOW/UNDERFLOW
    # =========================================================================
    
    async def _validate_integer_issues(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for integer overflow/underflow vulnerabilities.
        """
        try:
            integer_tests = [
                # Signed 32-bit overflow
                ("2147483647", "INT32_MAX"),
                ("2147483648", "INT32_MAX + 1"),
                ("-2147483648", "INT32_MIN"),
                ("-2147483649", "INT32_MIN - 1"),
                
                # Signed 64-bit overflow
                ("9223372036854775807", "INT64_MAX"),
                ("9223372036854775808", "INT64_MAX + 1"),
                ("-9223372036854775808", "INT64_MIN"),
                
                # Unsigned overflow
                ("4294967295", "UINT32_MAX"),
                ("4294967296", "UINT32_MAX + 1"),
                ("18446744073709551615", "UINT64_MAX"),
                
                # Edge cases
                ("-1", "Negative one"),
                ("0", "Zero"),
                ("-0", "Negative zero"),
                
                # Scientific notation
                ("1e10", "Scientific notation"),
                ("1e308", "Near double max"),
                ("1e309", "Overflow double"),
            ]
            
            for value, description in integer_tests:
                # Find numeric parameters to test
                if vuln.parameter:
                    test_url = re.sub(
                        rf'{re.escape(vuln.parameter)}=[^&]*',
                        f'{vuln.parameter}={value}',
                        vuln.endpoint
                    )
                else:
                    # Try common numeric parameter names
                    test_url = f"{vuln.endpoint}?id={value}&quantity={value}&amount={value}"
                
                try:
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    # Check for overflow indicators
                    overflow_patterns = [
                        r'overflow',
                        r'out of range',
                        r'too large',
                        r'too small',
                        r'exceeds.*maximum',
                        r'exceeds.*limit',
                        r'NumberFormatException',
                        r'ArithmeticException',
                        r'OverflowError',
                        r'integer.*overflow',
                    ]
                    
                    for pattern in overflow_patterns:
                        if re.search(pattern, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence=f"Integer handling issue: {description} caused overflow error",
                                validation_method="Integer Overflow",
                                details={"value": value, "description": description}
                            )
                    
                    # Check for unexpected behavior (negative total, wrapped value)
                    if "-1" in value or "INT" in description:
                        # Check if negative value caused unexpected positive result
                        if re.search(r'total.*[1-9]\d{9,}|amount.*[1-9]\d{9,}', body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.85,
                                evidence=f"Integer overflow: {description} caused wrapped value",
                                validation_method="Integer Overflow"
                            )
                    
                    if status >= 500:
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.8,
                            evidence=f"Integer handling: {description} caused server error",
                            validation_method="Integer Overflow"
                        )
                        
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Integer handling appears correct",
                validation_method="Integer Overflow"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Integer Overflow"
            )
    
    # =========================================================================
    # DIVIDE BY ZERO
    # =========================================================================
    
    async def _validate_divide_by_zero(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for divide by zero vulnerabilities.
        """
        try:
            zero_tests = [
                ("0", "Zero"),
                ("0.0", "Zero float"),
                ("0.00", "Zero decimal"),
                ("-0", "Negative zero"),
                ("0e0", "Scientific zero"),
            ]
            
            # Common parameters that might be used in division
            division_params = ["divisor", "divider", "count", "quantity", "rate", 
                             "percentage", "ratio", "denominator", "split", "portions"]
            
            for value, description in zero_tests:
                for param in division_params:
                    test_url = f"{vuln.endpoint}?{param}={value}"
                    
                    try:
                        status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                        
                        divide_error_patterns = [
                            r'division by zero',
                            r'divide by zero',
                            r'ZeroDivisionError',
                            r'ArithmeticException.*zero',
                            r'DivideByZeroException',
                            r'cannot divide by zero',
                            r'infinity',
                            r'NaN',
                        ]
                        
                        for pattern in divide_error_patterns:
                            if re.search(pattern, body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=0.95,
                                    evidence=f"Division by zero with {param}={value}",
                                    validation_method="Divide By Zero",
                                    details={"parameter": param, "value": value}
                                )
                        
                        if status >= 500:
                            return ValidationReport(
                                result=ValidationResult.HIGH,
                                confidence=0.8,
                                evidence=f"Possible divide by zero: {param}={value} caused HTTP {status}",
                                validation_method="Divide By Zero"
                            )
                            
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Division by zero handled properly",
                validation_method="Divide By Zero"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Divide By Zero"
            )
    
    # =========================================================================
    # TIMEOUT HANDLING
    # =========================================================================
    
    async def _validate_timeout_handling(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for improper timeout handling that could cause hangs or bypass.
        """
        try:
            # Test 1: Check if slow requests cause issues
            slow_payloads = [
                # Time-based payloads
                ("sleep(10)", "Sleep function"),
                ("WAITFOR DELAY '0:0:10'", "SQL wait"),
                ("pg_sleep(10)", "PostgreSQL sleep"),
            ]
            
            for payload, description in slow_payloads:
                test_url = f"{vuln.endpoint}?delay={urllib.parse.quote(payload)}"
                
                try:
                    start = time.time()
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    elapsed = time.time() - start
                    
                    # If response took significantly longer, timeout handling may be an issue
                    if elapsed > 8:
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.85,
                            evidence=f"Timeout handling issue: {description} caused {elapsed:.2f}s delay",
                            validation_method="Timeout Handling",
                            details={"payload": description, "elapsed": elapsed}
                        )
                        
                except asyncio.TimeoutError:
                    # Application doesn't have proper timeout
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"No timeout protection: request hung on {description}",
                        validation_method="Timeout Handling"
                    )
                except:
                    continue
            
            # Test 2: Connection holding
            # Try to hold connection open
            try:
                # Send partial request (if possible)
                start = time.time()
                status, body, _ = await self._request(
                    "POST",
                    vuln.endpoint,
                    headers={**vuln.headers, "Content-Length": "1000000"},  # Claim large body
                    data="x"  # Send tiny body
                )
                elapsed = time.time() - start
                
                # If server waited for full body, timeout handling may be weak
                if elapsed > 5:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.75,
                        evidence=f"Server waited {elapsed:.2f}s for incomplete request",
                        validation_method="Timeout Handling - Slowloris"
                    )
            except:
                pass
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Timeout handling appears adequate",
                validation_method="Timeout Handling"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Timeout Handling"
            )
    
    # =========================================================================
    # STATE HANDLING
    # =========================================================================
    
    async def _validate_state_handling(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for improper state management issues.
        """
        try:
            # Test: Race condition in state transitions
            async def send_state_request():
                try:
                    return await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                except:
                    return None
            
            # Send concurrent requests
            tasks = [send_state_request() for _ in range(5)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check for inconsistent states
            statuses = []
            for r in results:
                if r and isinstance(r, tuple) and len(r) >= 1:
                    statuses.append(r[0])
            
            # If we got mixed success/failure, state handling might be inconsistent
            if len(set(statuses)) > 1:
                success_count = sum(1 for s in statuses if s in (200, 201))
                
                if success_count > 1:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"Inconsistent state: {success_count}/5 concurrent requests succeeded",
                        validation_method="State Handling - Race Condition"
                    )
            
            # Test: Out-of-order operations
            state_bypass_tests = [
                # Try to skip to final state
                ("status", "completed"),
                ("state", "approved"),
                ("step", "final"),
                ("phase", "done"),
            ]
            
            for param, value in state_bypass_tests:
                test_body = f"{param}={value}"
                if vuln.body:
                    test_body = f"{vuln.body}&{param}={value}"
                
                try:
                    status, body, _ = await self._request(
                        "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=test_body
                    )
                    
                    if status in (200, 201):
                        if re.search(r'success|completed|approved|done', body, re.I):
                            if not re.search(r'invalid|error|denied|forbidden', body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=0.85,
                                    evidence=f"State bypass: {param}={value} accepted",
                                    validation_method="State Handling - Bypass"
                                )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="State handling appears correct",
                validation_method="State Handling"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="State Handling"
            )
    
    # =========================================================================
    # ERROR DISCLOSURE
    # =========================================================================
    
    async def _validate_error_disclosure(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for sensitive information disclosure through error messages.
        """
        try:
            # Trigger various errors
            error_triggers = [
                ("/nonexistent_page_12345", "404 error"),
                ("?invalid_param[]='test", "Parameter error"),
                ("?id=-99999999", "Invalid ID"),
                ("?file=../../../etc/passwd", "Path error"),
                ("?query=SELECT * FROM", "SQL-like query"),
            ]
            
            # Get base URL
            base_url = vuln.endpoint.split("?")[0]
            
            sensitive_patterns = [
                # File paths
                (r'/var/www/|/home/\w+/|C:\\', "File path"),
                (r'/usr/local/|/opt/', "System path"),
                
                # Database info
                (r'mysql|postgres|oracle|mongodb', "Database type"),
                (r'database.*error|sql.*error', "DB error"),
                (r'table.*not found|column.*not found', "Schema info"),
                
                # Framework info
                (r'django|flask|rails|laravel|express', "Framework"),
                (r'version.*\d+\.\d+', "Version info"),
                
                # Code info
                (r'line \d+|at .*:\d+', "Code location"),
                (r'function.*\(|method.*\(', "Function name"),
                (r'class [\w]+', "Class name"),
                
                # Credentials
                (r'password|secret|key|token', "Credential hint"),
                (r'username|user.*:', "User info"),
                
                # Internal IPs
                (r'10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+', "Internal IP"),
            ]
            
            for trigger, trigger_desc in error_triggers:
                test_url = base_url + trigger
                
                try:
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    for pattern, info_type in sensitive_patterns:
                        if re.search(pattern, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence=f"Error disclosure: {trigger_desc} revealed {info_type}",
                                validation_method="Error Disclosure",
                                details={"trigger": trigger_desc, "info_type": info_type}
                            )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No sensitive error disclosure detected",
                validation_method="Error Disclosure"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Error Disclosure"
            )
    
    # =========================================================================
    # MEMORY EXHAUSTION
    # =========================================================================
    
    async def _validate_memory_exhaustion(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for memory exhaustion vulnerabilities.
        """
        try:
            # Test payloads that could cause memory issues
            memory_tests = [
                # Large allocation requests
                ("size=999999999", "Large size parameter"),
                ("length=999999999", "Large length parameter"),
                ("count=999999999", "Large count parameter"),
                ("limit=999999999", "Large limit parameter"),
                
                # Decompression bombs (zip bomb style)
                ("A" * 10000, "Large repeated string"),
                
                # Recursive/nested structures
                ('{"a":' * 100 + '1' + '}' * 100, "Deeply nested JSON"),
                ("<a>" * 100 + "x" + "</a>" * 100, "Deeply nested XML"),
            ]
            
            for payload, description in memory_tests:
                test_url = f"{vuln.endpoint}?{payload}" if "=" in payload else f"{vuln.endpoint}?data={urllib.parse.quote(payload[:500])}"
                
                try:
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    # Check for memory-related errors
                    memory_errors = [
                        r'out of memory',
                        r'memory.*exhausted',
                        r'allocation.*failed',
                        r'MemoryError',
                        r'OutOfMemoryError',
                        r'heap.*space',
                        r'GC overhead',
                        r'too large',
                        r'maximum.*exceeded',
                    ]
                    
                    for pattern in memory_errors:
                        if re.search(pattern, body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence=f"Memory exhaustion: {description} caused memory error",
                                validation_method="Memory Exhaustion",
                                details={"payload": description}
                            )
                    
                    if status in (500, 502, 503):
                        return ValidationReport(
                            result=ValidationResult.HIGH,
                            confidence=0.75,
                            evidence=f"Possible memory exhaustion: {description} caused HTTP {status}",
                            validation_method="Memory Exhaustion"
                        )
                        
                except asyncio.TimeoutError:
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence=f"Memory exhaustion: {description} caused timeout",
                        validation_method="Memory Exhaustion"
                    )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="No memory exhaustion detected",
                validation_method="Memory Exhaustion"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Memory Exhaustion"
            )
    
    # =========================================================================
    # GENERIC EXCEPTIONAL CONDITIONS
    # =========================================================================
    
    async def _validate_generic_exceptional(self, vuln: VulnReport) -> ValidationReport:
        """Generic exceptional condition validation - try multiple checks"""
        results = [
            await self._validate_unhandled_exception(vuln),
            await self._validate_error_disclosure(vuln),
            await self._validate_null_handling(vuln),
            await self._validate_fail_open(vuln),
        ]
        
        best = max(results, key=lambda r: r.confidence)
        
        if best.confidence > 0:
            return best
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="Could not confirm exceptional condition handling issue",
            validation_method="Generic Exceptional Conditions"
        )