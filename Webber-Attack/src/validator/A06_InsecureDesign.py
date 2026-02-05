"""
A06:2025 - Insecure Design Validator
====================================
OWASP Top 10 2025 - A06 (was A04 in 2021)

Insecure Design is a broad category representing different weaknesses,
expressed as "missing or ineffective control design."

This focuses on DESIGN FLAWS, not implementation bugs. The difference:
- Implementation bug: SQL injection due to missing input sanitization
- Design flaw: No rate limiting on password reset = unlimited attempts by design

Secure design requires:
- Threat modeling
- Secure design patterns
- Reference architecture
- Security requirements

Validates:
- Business logic flaws (price manipulation, quantity abuse)
- Missing rate limiting / brute force protection
- Workflow/process bypass (skipping steps)
- Race conditions (TOCTOU)
- Trust boundary violations
- Missing authentication on critical functions
- Insufficient anti-automation
- Coupon/discount abuse
- Negative quantity/price attacks
- Referral/reward abuse
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


class A06_InsecureDesignValidator(BaseValidator):
    """
    Validates Insecure Design vulnerabilities (OWASP 2025 A06).
    """
    
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        vuln_subtype = vuln.vuln_type.upper()
        
        if any(x in vuln_subtype for x in ["RATE", "LIMIT", "BRUTE", "THROTTL"]):
            return await self._validate_missing_rate_limit(vuln)
        
        elif any(x in vuln_subtype for x in ["PRICE", "COST", "AMOUNT", "TOTAL"]):
            return await self._validate_price_manipulation(vuln)
        
        elif any(x in vuln_subtype for x in ["QUANTITY", "QTY", "COUNT", "NEGATIVE"]):
            return await self._validate_quantity_manipulation(vuln)
        
        elif any(x in vuln_subtype for x in ["WORKFLOW", "PROCESS", "STEP", "BYPASS", "SKIP"]):
            return await self._validate_workflow_bypass(vuln)
        
        elif any(x in vuln_subtype for x in ["RACE", "TOCTOU", "CONCURRENT"]):
            return await self._validate_race_condition(vuln)
        
        elif any(x in vuln_subtype for x in ["COUPON", "DISCOUNT", "PROMO", "VOUCHER"]):
            return await self._validate_coupon_abuse(vuln)
        
        elif any(x in vuln_subtype for x in ["REFERRAL", "REWARD", "BONUS", "POINTS"]):
            return await self._validate_referral_abuse(vuln)
        
        elif any(x in vuln_subtype for x in ["CAPTCHA", "BOT", "AUTOMAT"]):
            return await self._validate_missing_anti_automation(vuln)
        
        elif any(x in vuln_subtype for x in ["LOGIC", "BUSINESS"]):
            return await self._validate_business_logic(vuln)
        
        elif any(x in vuln_subtype for x in ["TRUST", "BOUNDARY"]):
            return await self._validate_trust_boundary(vuln)
        
        elif any(x in vuln_subtype for x in ["FUNCTION", "ENDPOINT", "UNAUTH"]):
            return await self._validate_missing_function_auth(vuln)
        
        else:
            return await self._validate_generic_design(vuln)
    
    # =========================================================================
    # MISSING RATE LIMITING
    # =========================================================================
    
    async def _validate_missing_rate_limit(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for missing rate limiting on sensitive endpoints.
        Design flaw: allowing unlimited attempts enables brute force attacks.
        """
        try:
            # Determine if this is a sensitive endpoint that should have rate limiting
            sensitive_endpoints = [
                (r'/login', "Login endpoint"),
                (r'/auth', "Authentication endpoint"),
                (r'/signin', "Sign-in endpoint"),
                (r'/password', "Password endpoint"),
                (r'/reset', "Password reset"),
                (r'/forgot', "Forgot password"),
                (r'/register', "Registration"),
                (r'/signup', "Sign-up"),
                (r'/otp', "OTP verification"),
                (r'/verify', "Verification endpoint"),
                (r'/2fa', "2FA endpoint"),
                (r'/mfa', "MFA endpoint"),
                (r'/api/v', "API endpoint"),
                (r'/token', "Token endpoint"),
            ]
            
            endpoint_type = None
            for pattern, description in sensitive_endpoints:
                if re.search(pattern, vuln.endpoint, re.I):
                    endpoint_type = description
                    break
            
            if not endpoint_type:
                endpoint_type = "Endpoint"
            
            # Send multiple rapid requests
            num_requests = 10
            successful_requests = 0
            rate_limit_triggered = False
            
            for i in range(num_requests):
                try:
                    status, body, headers = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                    
                    # Check for rate limit responses
                    if status == 429:
                        rate_limit_triggered = True
                        break
                    
                    # Check for rate limit headers
                    rate_limit_headers = [
                        'x-ratelimit-remaining',
                        'x-rate-limit-remaining',
                        'ratelimit-remaining',
                        'retry-after',
                        'x-retry-after'
                    ]
                    
                    headers_lower = {k.lower(): v for k, v in headers.items()}
                    for rl_header in rate_limit_headers:
                        if rl_header in headers_lower:
                            remaining = headers_lower.get(rl_header, '')
                            if remaining == '0':
                                rate_limit_triggered = True
                                break
                    
                    # Check for rate limit message in body
                    rate_limit_messages = [
                        r'rate.?limit',
                        r'too many requests',
                        r'slow down',
                        r'try again later',
                        r'exceeded.*limit',
                        r'throttl',
                    ]
                    
                    for pattern in rate_limit_messages:
                        if re.search(pattern, body, re.I):
                            rate_limit_triggered = True
                            break
                    
                    if rate_limit_triggered:
                        break
                    
                    if status in (200, 201, 400, 401, 403):
                        successful_requests += 1
                        
                except Exception:
                    continue
            
            if not rate_limit_triggered and successful_requests >= num_requests - 1:
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.95,
                    evidence=f"No rate limiting on {endpoint_type}: {successful_requests}/{num_requests} requests succeeded without throttling",
                    validation_method="Missing Rate Limit",
                    details={
                        "endpoint_type": endpoint_type,
                        "requests_sent": num_requests,
                        "successful": successful_requests
                    }
                )
            elif rate_limit_triggered:
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence=f"Rate limiting is active on {endpoint_type}",
                    validation_method="Missing Rate Limit"
                )
            
            return ValidationReport(
                result=ValidationResult.MEDIUM,
                confidence=0.6,
                evidence=f"Rate limiting unclear on {endpoint_type} - partial success",
                validation_method="Missing Rate Limit"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Missing Rate Limit"
            )
    
    # =========================================================================
    # PRICE MANIPULATION
    # =========================================================================
    
    async def _validate_price_manipulation(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for price manipulation vulnerabilities.
        Design flaw: trusting client-side price data.
        """
        try:
            # Try to manipulate price in request
            manipulation_tests = [
                # Zero price
                {"price": "0", "amount": "0", "total": "0", "cost": "0"},
                # Negative price
                {"price": "-1", "amount": "-100", "total": "-50", "cost": "-1"},
                # Very small price
                {"price": "0.01", "amount": "0.001", "total": "0.01"},
                # String manipulation
                {"price": "0.00", "amount": "free", "total": "0"},
            ]
            
            original_body = vuln.body or ""
            
            for test_values in manipulation_tests:
                # Try each price field
                for field, value in test_values.items():
                    # Modify body if it exists
                    if original_body:
                        # URL-encoded body
                        modified_body = re.sub(
                            rf'{field}=[^&]*',
                            f'{field}={value}',
                            original_body,
                            flags=re.I
                        )
                        
                        # JSON body
                        if '{' in original_body:
                            modified_body = re.sub(
                                rf'"{field}"\s*:\s*[^,}}]+',
                                f'"{field}": {value}',
                                original_body,
                                flags=re.I
                            )
                    else:
                        modified_body = f"{field}={value}"
                    
                    try:
                        status, body, _ = await self._request(
                            vuln.method or "POST",
                            vuln.endpoint,
                            headers=vuln.headers,
                            data=modified_body
                        )
                        
                        # Check if manipulation was accepted
                        success_indicators = [
                            r'success',
                            r'order.*(?:placed|confirmed|created)',
                            r'thank you',
                            r'payment.*(?:received|processed)',
                            r'total.*(?:\$?0\.0|\$?0[^0-9]|free)',
                            r'"status"\s*:\s*"(?:success|ok|completed)"',
                        ]
                        
                        # Check if negative/zero was rejected
                        rejection_indicators = [
                            r'invalid.*price',
                            r'invalid.*amount',
                            r'price.*(?:must be|cannot be|should be)',
                            r'negative.*not allowed',
                            r'minimum.*price',
                            r'validation.*(?:error|failed)',
                        ]
                        
                        body_lower = body.lower()
                        
                        # Check for rejection first
                        rejected = any(re.search(p, body, re.I) for p in rejection_indicators)
                        
                        if not rejected and status in (200, 201):
                            for indicator in success_indicators:
                                if re.search(indicator, body, re.I):
                                    return ValidationReport(
                                        result=ValidationResult.CONFIRMED,
                                        confidence=1.0,
                                        evidence=f"Price manipulation accepted: {field}={value}",
                                        validation_method="Price Manipulation",
                                        details={"field": field, "value": value}
                                    )
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Price manipulation attempts rejected or not applicable",
                validation_method="Price Manipulation"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Price Manipulation"
            )
    
    # =========================================================================
    # QUANTITY MANIPULATION
    # =========================================================================
    
    async def _validate_quantity_manipulation(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for quantity manipulation (negative quantities, overflow).
        Design flaw: not validating quantity constraints server-side.
        """
        try:
            manipulation_tests = [
                # Negative quantity
                {"quantity": "-1", "qty": "-1", "count": "-1", "amount": "-1"},
                # Zero quantity
                {"quantity": "0", "qty": "0", "count": "0"},
                # Large quantity (integer overflow)
                {"quantity": "999999999", "qty": "2147483647"},
                # Decimal quantity for integer items
                {"quantity": "1.5", "qty": "0.5"},
            ]
            
            original_body = vuln.body or ""
            
            for test_values in manipulation_tests:
                for field, value in test_values.items():
                    if original_body:
                        modified_body = re.sub(
                            rf'{field}=[^&]*',
                            f'{field}={value}',
                            original_body,
                            flags=re.I
                        )
                        if '{' in original_body:
                            modified_body = re.sub(
                                rf'"{field}"\s*:\s*[^,}}]+',
                                f'"{field}": {value}',
                                original_body,
                                flags=re.I
                            )
                    else:
                        modified_body = f"{field}={value}"
                    
                    try:
                        status, body, _ = await self._request(
                            vuln.method or "POST",
                            vuln.endpoint,
                            headers=vuln.headers,
                            data=modified_body
                        )
                        
                        # Check for negative quantity acceptance (would result in credit/refund)
                        if "-" in value and status in (200, 201):
                            if not re.search(r'invalid|error|negative|minimum', body, re.I):
                                return ValidationReport(
                                    result=ValidationResult.CONFIRMED,
                                    confidence=1.0,
                                    evidence=f"Negative quantity accepted: {field}={value}",
                                    validation_method="Quantity Manipulation",
                                    details={"field": field, "value": value, "type": "negative"}
                                )
                        
                        # Check for integer overflow
                        if "999999" in value or "2147483647" in value:
                            if status in (200, 201):
                                # Check if total price is abnormally low (overflow)
                                if re.search(r'total.*(?:\$?0\.|\$?-|negative)', body, re.I):
                                    return ValidationReport(
                                        result=ValidationResult.CONFIRMED,
                                        confidence=0.95,
                                        evidence=f"Integer overflow in quantity: {value}",
                                        validation_method="Quantity Manipulation",
                                        details={"type": "overflow"}
                                    )
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Quantity manipulation attempts rejected",
                validation_method="Quantity Manipulation"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Quantity Manipulation"
            )
    
    # =========================================================================
    # WORKFLOW BYPASS
    # =========================================================================
    
    async def _validate_workflow_bypass(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for workflow/process bypass vulnerabilities.
        Design flaw: not enforcing sequential process steps server-side.
        """
        try:
            # Try to access later steps directly without completing earlier ones
            workflow_patterns = [
                # Checkout flow
                (r'/checkout', r'/payment|/confirm|/complete|/success'),
                (r'/cart', r'/checkout|/payment'),
                (r'/payment', r'/confirm|/complete|/success'),
                
                # Registration flow
                (r'/register', r'/verify|/confirm|/welcome'),
                (r'/signup', r'/activate|/confirm'),
                
                # Password reset flow
                (r'/forgot', r'/reset|/change'),
                (r'/reset-request', r'/reset-password|/new-password'),
                
                # Multi-step forms
                (r'/step1|/step-1', r'/step2|/step-2|/step3|/step-3|/final'),
                (r'/application/start', r'/application/submit|/application/complete'),
            ]
            
            # Extract base URL
            base_url = vuln.endpoint.rsplit('/', 1)[0] if '/' in vuln.endpoint else vuln.endpoint
            
            for current_pattern, next_patterns in workflow_patterns:
                if re.search(current_pattern, vuln.endpoint, re.I):
                    # Try to access next steps directly
                    for next_pattern in next_patterns.split('|'):
                        next_url = f"{base_url}{next_pattern}"
                        
                        try:
                            status, body, _ = await self._request(
                                "GET",
                                next_url,
                                headers=vuln.headers
                            )
                            
                            # Check if access was granted without completing previous step
                            if status == 200 and len(body) > 200:
                                # Check for form/content (not just error page)
                                if re.search(r'<form|<input|submit|confirm|complete', body, re.I):
                                    # Check it's not an error/redirect page
                                    if not re.search(r'please complete|go back|previous step|must first', body, re.I):
                                        return ValidationReport(
                                            result=ValidationResult.CONFIRMED,
                                            confidence=0.9,
                                            evidence=f"Workflow bypass: accessed {next_pattern} without completing previous steps",
                                            validation_method="Workflow Bypass",
                                            details={
                                                "current_step": current_pattern,
                                                "bypassed_to": next_pattern
                                            }
                                        )
                        except:
                            continue
            
            # Try direct access to success/confirmation pages
            success_paths = ['/success', '/complete', '/done', '/thank-you', '/confirmation', '/order-complete']
            
            for path in success_paths:
                try:
                    parts = vuln.endpoint.split('/')
                    root_url = '/'.join(parts[:3]) if len(parts) >= 3 else vuln.endpoint
                    test_url = root_url + path
                    
                    status, body, _ = await self._request("GET", test_url, headers=vuln.headers)
                    
                    if status == 200:
                        # Check if it shows actual order/confirmation data
                        if re.search(r'order.?(?:number|id)|confirmation|receipt|thank you for', body, re.I):
                            return ValidationReport(
                                result=ValidationResult.HIGH,
                                confidence=0.85,
                                evidence=f"Success page accessible directly: {path}",
                                validation_method="Workflow Bypass",
                                details={"path": path}
                            )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Workflow bypass not detected",
                validation_method="Workflow Bypass"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Workflow Bypass"
            )
    
    # =========================================================================
    # RACE CONDITION
    # =========================================================================
    
    async def _validate_race_condition(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for race condition (TOCTOU) vulnerabilities.
        Design flaw: not using proper locking/transactions.
        """
        try:
            # Send multiple concurrent requests
            num_concurrent = 5
            
            async def send_request():
                try:
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                    return {"status": status, "body": body}
                except Exception as e:
                    return {"error": str(e)}
            
            # Send requests concurrently
            tasks = [send_request() for _ in range(num_concurrent)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful = [r for r in results if isinstance(r, dict) and r.get("status") in (200, 201)]
            
            # For coupon/discount redemption, multiple successes indicate race condition
            if len(successful) > 1:
                # Check if this looks like a single-use resource
                single_use_indicators = [
                    r'coupon',
                    r'voucher',
                    r'redeem',
                    r'claim',
                    r'bonus',
                    r'one.?time',
                    r'limited',
                    r'balance',
                    r'transfer',
                    r'withdraw',
                ]
                
                endpoint_lower = vuln.endpoint.lower()
                body_content = successful[0].get("body", "").lower() if successful else ""
                
                is_single_use = any(ind in endpoint_lower or ind in body_content 
                                   for ind in single_use_indicators)
                
                if is_single_use:
                    return ValidationReport(
                        result=ValidationResult.CONFIRMED,
                        confidence=0.9,
                        evidence=f"Race condition: {len(successful)}/{num_concurrent} concurrent requests succeeded on single-use resource",
                        validation_method="Race Condition",
                        details={
                            "concurrent_requests": num_concurrent,
                            "successful": len(successful)
                        }
                    )
                else:
                    return ValidationReport(
                        result=ValidationResult.MEDIUM,
                        confidence=0.6,
                        evidence=f"Possible race condition: {len(successful)} concurrent requests succeeded",
                        validation_method="Race Condition"
                    )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Race condition not detected",
                validation_method="Race Condition"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Race Condition"
            )
    
    # =========================================================================
    # COUPON/DISCOUNT ABUSE
    # =========================================================================
    
    async def _validate_coupon_abuse(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for coupon/discount code abuse.
        Design flaws: reusable codes, stackable discounts, no validation.
        """
        try:
            # Test 1: Try to reuse same coupon
            reuse_results = []
            for _ in range(3):
                try:
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                    if status in (200, 201):
                        if re.search(r'applied|success|discount|saved', body, re.I):
                            reuse_results.append(True)
                        elif re.search(r'already.?used|invalid|expired|limit', body, re.I):
                            reuse_results.append(False)
                            break
                except:
                    continue
            
            if len([r for r in reuse_results if r]) >= 2:
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.95,
                    evidence="Coupon code can be reused multiple times",
                    validation_method="Coupon Abuse - Reuse"
                )
            
            # Test 2: Try stacking multiple coupons
            if vuln.body:
                # Try adding multiple coupon parameters
                original_body = vuln.body
                stacked_body = f"{original_body}&coupon2=TEST&coupon3=SAVE10"
                
                try:
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=stacked_body
                    )
                    
                    if status in (200, 201):
                        # Check if multiple discounts applied
                        discount_count = len(re.findall(r'discount|saved|\$\d+\s*off', body, re.I))
                        if discount_count >= 2:
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=0.9,
                                evidence="Multiple coupon codes can be stacked",
                                validation_method="Coupon Abuse - Stacking"
                            )
                except:
                    pass
            
            # Test 3: Try manipulated coupon codes
            test_codes = ['100OFF', 'FREE', 'ADMIN', 'TEST', '999', 'DISCOUNT100']
            
            for code in test_codes:
                try:
                    test_body = re.sub(r'coupon=[^&]*', f'coupon={code}', vuln.body or f'coupon={code}')
                    
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=test_body
                    )
                    
                    if status in (200, 201):
                        if re.search(r'100%|free|total.*\$?0\.00', body, re.I):
                            return ValidationReport(
                                result=ValidationResult.CONFIRMED,
                                confidence=1.0,
                                evidence=f"Test coupon code '{code}' gave 100% discount",
                                validation_method="Coupon Abuse - Test Code",
                                details={"code": code}
                            )
                except:
                    continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Coupon abuse not detected",
                validation_method="Coupon Abuse"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Coupon Abuse"
            )
    
    # =========================================================================
    # REFERRAL/REWARD ABUSE
    # =========================================================================
    
    async def _validate_referral_abuse(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for referral/reward program abuse.
        Design flaws: self-referral, unlimited rewards, no fraud detection.
        """
        try:
            # Test: Self-referral (using own referral code)
            status, body, _ = await self._request(
                vuln.method or "POST",
                vuln.endpoint,
                headers=vuln.headers,
                data=vuln.body
            )
            
            if status in (200, 201):
                # Check for success indicators
                if re.search(r'reward|bonus|credit|points.*added|success', body, re.I):
                    # This could be self-referral working
                    return ValidationReport(
                        result=ValidationResult.HIGH,
                        confidence=0.8,
                        evidence="Referral reward claimed - verify if self-referral is blocked",
                        validation_method="Referral Abuse"
                    )
            
            # Test: Multiple redemptions
            redemption_count = 0
            for _ in range(3):
                try:
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                    if status in (200, 201) and re.search(r'reward|bonus|success', body, re.I):
                        redemption_count += 1
                except:
                    continue
            
            if redemption_count >= 2:
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.9,
                    evidence=f"Referral reward can be claimed multiple times ({redemption_count}x)",
                    validation_method="Referral Abuse - Multiple Claims"
                )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Referral abuse not detected",
                validation_method="Referral Abuse"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Referral Abuse"
            )
    
    # =========================================================================
    # MISSING ANTI-AUTOMATION
    # =========================================================================
    
    async def _validate_missing_anti_automation(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for missing anti-automation controls (CAPTCHA, etc.).
        Design flaw: not protecting against bot abuse.
        """
        try:
            # Send automated requests without solving CAPTCHA
            success_count = 0
            captcha_required = False
            
            for i in range(5):
                try:
                    status, body, _ = await self._request(
                        vuln.method or "POST",
                        vuln.endpoint,
                        headers=vuln.headers,
                        data=vuln.body
                    )
                    
                    # Check if CAPTCHA is required
                    captcha_indicators = [
                        r'captcha',
                        r'recaptcha',
                        r'hcaptcha',
                        r'g-recaptcha',
                        r'cf-turnstile',
                        r'verify.*human',
                        r'robot',
                        r'challenge',
                    ]
                    
                    for indicator in captcha_indicators:
                        if re.search(indicator, body, re.I):
                            captcha_required = True
                            break
                    
                    if captcha_required:
                        break
                    
                    if status in (200, 201):
                        success_count += 1
                except:
                    continue
            
            if not captcha_required and success_count >= 4:
                return ValidationReport(
                    result=ValidationResult.CONFIRMED,
                    confidence=0.9,
                    evidence=f"No CAPTCHA/anti-automation: {success_count} automated requests succeeded",
                    validation_method="Missing Anti-Automation",
                    details={"successful_requests": success_count}
                )
            elif captcha_required:
                return ValidationReport(
                    result=ValidationResult.REJECTED,
                    confidence=0.0,
                    evidence="CAPTCHA/anti-automation is present",
                    validation_method="Missing Anti-Automation"
                )
            
            return ValidationReport(
                result=ValidationResult.MEDIUM,
                confidence=0.5,
                evidence="Anti-automation status unclear",
                validation_method="Missing Anti-Automation"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Missing Anti-Automation"
            )
    
    # =========================================================================
    # BUSINESS LOGIC
    # =========================================================================
    
    async def _validate_business_logic(self, vuln: VulnReport) -> ValidationReport:
        """
        Generic business logic flaw validation.
        """
        # Try common business logic tests
        results = [
            await self._validate_price_manipulation(vuln),
            await self._validate_quantity_manipulation(vuln),
            await self._validate_workflow_bypass(vuln),
        ]
        
        best = max(results, key=lambda r: r.confidence)
        
        if best.confidence > 0:
            return best
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="Business logic flaw not confirmed",
            validation_method="Business Logic"
        )
    
    # =========================================================================
    # TRUST BOUNDARY VIOLATION
    # =========================================================================
    
    async def _validate_trust_boundary(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for trust boundary violations.
        Design flaw: trusting data from untrusted sources.
        """
        try:
            # Check if client-provided data is trusted without validation
            trust_tests = [
                # Role/permission manipulation
                ({"role": "admin", "isAdmin": "true", "admin": "1"}, "Admin role injection"),
                # User ID manipulation
                ({"userId": "1", "user_id": "1", "uid": "1"}, "User ID manipulation"),
                # Price/discount trust
                ({"discount": "100", "price": "0"}, "Price trust"),
            ]
            
            for test_params, description in trust_tests:
                for param, value in test_params.items():
                    # Add parameter to request
                    if vuln.body:
                        test_body = f"{vuln.body}&{param}={value}"
                    else:
                        test_body = f"{param}={value}"
                    
                    try:
                        status, body, _ = await self._request(
                            vuln.method or "POST",
                            vuln.endpoint,
                            headers=vuln.headers,
                            data=test_body
                        )
                        
                        if status in (200, 201):
                            # Check if the parameter was accepted
                            if param in ["role", "isAdmin", "admin"]:
                                if re.search(r'admin.*dashboard|admin.*panel|elevated|privileged', body, re.I):
                                    return ValidationReport(
                                        result=ValidationResult.CONFIRMED,
                                        confidence=0.95,
                                        evidence=f"Trust boundary violation: {description} with {param}={value}",
                                        validation_method="Trust Boundary",
                                        details={"parameter": param, "value": value}
                                    )
                    except:
                        continue
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Trust boundary violation not detected",
                validation_method="Trust Boundary"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Trust Boundary"
            )
    
    # =========================================================================
    # MISSING FUNCTION AUTHENTICATION
    # =========================================================================
    
    async def _validate_missing_function_auth(self, vuln: VulnReport) -> ValidationReport:
        """
        Check for missing authentication on sensitive functions.
        Design flaw: not requiring auth for critical operations.
        """
        try:
            # Try accessing without auth headers
            headers_no_auth = {k: v for k, v in vuln.headers.items() 
                             if k.lower() not in ['authorization', 'cookie', 'x-auth-token']}
            
            status, body, _ = await self._request(
                vuln.method or "GET",
                vuln.endpoint,
                headers=headers_no_auth,
                data=vuln.body
            )
            
            # Check if sensitive function is accessible
            if status == 200:
                sensitive_indicators = [
                    r'admin',
                    r'user.*list',
                    r'delete',
                    r'modify',
                    r'settings',
                    r'config',
                    r'management',
                    r'dashboard',
                ]
                
                for indicator in sensitive_indicators:
                    if re.search(indicator, body, re.I):
                        return ValidationReport(
                            result=ValidationResult.CONFIRMED,
                            confidence=0.9,
                            evidence=f"Sensitive function accessible without authentication: {indicator}",
                            validation_method="Missing Function Auth",
                            details={"indicator": indicator}
                        )
            
            return ValidationReport(
                result=ValidationResult.REJECTED,
                confidence=0.0,
                evidence="Authentication appears to be required",
                validation_method="Missing Function Auth"
            )
            
        except Exception as e:
            return ValidationReport(
                result=ValidationResult.INCONCLUSIVE,
                confidence=0.0,
                evidence=f"Error: {str(e)}",
                validation_method="Missing Function Auth"
            )
    
    # =========================================================================
    # GENERIC DESIGN VALIDATION
    # =========================================================================
    
    async def _validate_generic_design(self, vuln: VulnReport) -> ValidationReport:
        """Generic insecure design validation - try multiple checks"""
        results = [
            await self._validate_missing_rate_limit(vuln),
            await self._validate_price_manipulation(vuln),
            await self._validate_workflow_bypass(vuln),
        ]
        
        best = max(results, key=lambda r: r.confidence)
        
        if best.confidence > 0:
            return best
        
        return ValidationReport(
            result=ValidationResult.REJECTED,
            confidence=0.0,
            evidence="Could not confirm insecure design vulnerability",
            validation_method="Generic Design"
        )