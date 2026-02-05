"""
Validator Base Classes - MCP Edition
=====================================
Core classes used by all OWASP category validators.
Uses MCP client for HTTP requests to maintain consistent architecture.
"""

import asyncio
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
from enum import Enum
from abc import ABC, abstractmethod
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("validator")


class ValidationResult(Enum):
    """Validation outcomes"""
    CONFIRMED = "confirmed"      # 100% certain - exploited successfully
    HIGH = "high"                # 90%+ confident - strong indicators
    MEDIUM = "medium"            # 70-90% - likely but not definitive
    LOW = "low"                  # <70% - possible but uncertain
    REJECTED = "rejected"        # False positive - could not reproduce
    INCONCLUSIVE = "inconclusive"  # Could not determine (network issues, etc.)
    INFORMATIONAL = "informational"  # Valid finding but not a "real" exploit (e.g., missing headers)


@dataclass
class ValidationReport:
    """Result of a validation attempt"""
    result: ValidationResult
    confidence: float  # 0.0 to 1.0
    evidence: str
    validation_method: str
    details: Dict[str, Any] = field(default_factory=dict)
    is_informational: bool = False  # True for findings that shouldn't count as "solved challenges"
    
    def is_valid(self) -> bool:
        """Returns True if vuln should be counted as a REAL exploit"""
        # Informational findings don't count even if high confidence
        if self.is_informational:
            return False
        return self.result in (ValidationResult.CONFIRMED, ValidationResult.HIGH)
    
    def is_worth_reporting(self) -> bool:
        """Returns True if vuln should be stored (but maybe not counted)"""
        return self.result in (
            ValidationResult.CONFIRMED, 
            ValidationResult.HIGH,
            ValidationResult.INFORMATIONAL
        )


@dataclass 
class VulnReport:
    """Standardized vulnerability report from agent"""
    vuln_type: str           # SQLi, XSS, IDOR, etc.
    owasp_category: str      # A01, A02, etc.
    endpoint: str            # Full URL
    method: str              # GET, POST, etc.
    parameter: str           # Vulnerable parameter name
    payload: str             # Payload that triggered the vuln
    evidence: str            # What made agent think it worked
    auth_token: Optional[str] = None  # Session/auth token if needed
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None  # Request body for POST
    baseline_response: Optional[str] = None  # Response without payload
    attack_response: Optional[str] = None    # Response with payload


class BaseValidator(ABC):
    """
    Base class for all validators.
    Uses MCP client for HTTP requests via curl commands.
    """
    
    def __init__(self, mcp_client, target_url: str, timeout: int = 10, retries: int = 2):
        """
        Args:
            mcp_client: MCPClientHub instance for executing commands
            target_url: Base target URL
            timeout: Request timeout in seconds
            retries: Number of retries on failure
        """
        self.mcp = mcp_client
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.retries = retries
    
    async def _request(
        self, 
        method: str, 
        url: str, 
        headers: Dict = None,
        data: Any = None,
        params: Dict = None,
        allow_redirects: bool = True
    ) -> Tuple[int, str, Dict]:
        """
        Make HTTP request via MCP using curl.
        Returns (status_code, body, headers).
        """
        headers = headers or {}

        # ── resolve relative paths ─────────────────────────────────
        # Several validators (A10 etc.) build test URLs manually as
        # "/endpoint?param=value".  Catch it here once rather than
        # patching each validator individually.
        if not url.startswith("http"):
            url = f"{self.target_url}/{url.lstrip('/')}"

        for attempt in range(self.retries + 1):
            try:
                # Build curl command
                cmd_parts = ["curl", "-s", "-i", f"--max-time {self.timeout}"]
                
                # Method
                if method.upper() != "GET":
                    cmd_parts.append(f"-X {method.upper()}")
                
                # Headers
                for key, value in headers.items():
                    safe_value = str(value).replace("'", "'\\''").replace('"', '\\"')
                    cmd_parts.append(f"-H '{key}: {safe_value}'")
                
                # Query params (for GET)
                final_url = url
                if params:
                    param_str = urllib.parse.urlencode(params)
                    if "?" in url:
                        final_url = f"{url}&{param_str}"
                    else:
                        final_url = f"{url}?{param_str}"
                
                # Data/body (for POST/PUT)
                if data:
                    if isinstance(data, dict):
                        safe_data = urllib.parse.urlencode(data)
                    else:
                        safe_data = str(data).replace("'", "'\\''")
                    # Auto Content-Type for JSON bodies
                    ct_set = any(k.lower() == "content-type" for k in headers)
                    if not ct_set and safe_data.lstrip().startswith("{"):
                        cmd_parts.append("-H 'Content-Type: application/json'")
                    cmd_parts.append(f"-d '{safe_data}'")
                
                # Redirects
                if allow_redirects:
                    cmd_parts.append("-L")
                
                # Escape URL
                safe_url = final_url.replace("'", "'\\''")
                cmd_parts.append(f"'{safe_url}'")
                
                # Full command
                cmd = " ".join(cmd_parts) + " 2>/dev/null"
                
                # Execute via MCP
                result = await self.mcp.execute("recon", "shell", {
                    "command": cmd, 
                    "timeout": self.timeout + 5
                })
                
                if not result.get("success"):
                    raise Exception(f"MCP execution failed: {result.get('error', 'Unknown')}")
                
                output = result.get("result", {}).get("output", "")
                
                # Parse curl -i output
                status, body, resp_headers = self._parse_curl_response(output)
                return status, body, resp_headers
                
            except asyncio.TimeoutError:
                if attempt == self.retries:
                    raise
                await asyncio.sleep(1)
            except Exception as e:
                if attempt == self.retries:
                    raise
                await asyncio.sleep(1)
        
        raise Exception("Request failed after retries")
    
    def _parse_curl_response(self, raw_output: str) -> Tuple[int, str, Dict]:
        """
        Parse curl -i output into (status_code, body, headers).
        curl -i returns headers followed by blank line followed by body.
        """
        if not raw_output:
            return 0, "", {}
        
        # Split headers and body (separated by \r\n\r\n or \n\n)
        parts = re.split(r'\r?\n\r?\n', raw_output, maxsplit=1)
        
        header_section = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""
        
        # Handle multiple response headers (redirects with -L)
        # Take the last HTTP response
        http_responses = re.split(r'(?=HTTP/[\d.]+\s+\d+)', header_section)
        http_responses = [r for r in http_responses if r.strip()]
        
        if http_responses:
            header_section = http_responses[-1]
        
        # Parse status code
        status_code = 0
        status_match = re.search(r'HTTP/[\d.]+\s+(\d+)', header_section)
        if status_match:
            status_code = int(status_match.group(1))
        
        # Parse headers into dict
        headers = {}
        for line in header_section.split('\n'):
            if ':' in line and not line.startswith('HTTP/'):
                key, _, value = line.partition(':')
                headers[key.strip()] = value.strip()
        
        return status_code, body, headers
    
    async def _timed_request(
        self,
        method: str,
        url: str,
        headers: Dict = None,
        data: Any = None
    ) -> Tuple[float, int, str]:
        """Make request and measure response time"""
        start = time.time()
        status, body, _ = await self._request(method, url, headers, data)
        elapsed = time.time() - start
        return elapsed, status, body
    
    async def _raw_cmd(self, cmd: str, timeout: int = None) -> Optional[str]:
        """
        Execute a raw shell command via MCP.
        Useful for custom curl commands or other tools.
        """
        try:
            result = await self.mcp.execute("recon", "shell", {
                "command": cmd,
                "timeout": timeout or self.timeout + 5
            })
            if result.get("success"):
                return result.get("result", {}).get("output", "")
            return None
        except:
            return None
    
    def _build_request_with_payload(self, vuln: VulnReport, payload: str) -> Tuple[str, Optional[str]]:
        """
        Build full URL and body with payload injected.

        FIXED v2.1:
        - Prepends self.target_url when endpoint is a relative path.
          Was: returned '/admin.php?search=...' → curl failed (no host).
        - Payload is NOT urllib.parse.quote'd — it must be sent raw to match
          what the scanner originally sent.  The scanner sends raw payloads
          (e.g. {{7*7}}, <script>…) via shell-escaped curl; the validator
          must re-test the exact same bytes.
        """
        # ── resolve relative path to full URL ─────────────────────
        endpoint = vuln.endpoint
        if not endpoint.startswith("http"):
            endpoint = f"{self.target_url}/{endpoint.lstrip('/')}"

        if vuln.method.upper() == "GET":
            if "?" in endpoint:
                url = re.sub(
                    rf'{re.escape(vuln.parameter)}=[^&]*',
                    f'{vuln.parameter}={payload}',
                    endpoint
                )
            else:
                url = f"{endpoint}?{vuln.parameter}={payload}"
            return url, None
        else:
            url = endpoint

            # ── JSON API detection ─────────────────────────────
            # /rest/* and /api/* endpoints expect JSON bodies.
            # Form-encoded payloads silently fail against them.
            is_json_api = bool(re.search(r'/(?:rest|api)/', endpoint, re.I))

            if vuln.body:
                # Existing body — try JSON parse first
                try:
                    import json as _json
                    parsed = _json.loads(vuln.body)
                    if isinstance(parsed, dict) and vuln.parameter in parsed:
                        parsed[vuln.parameter] = payload
                        return url, _json.dumps(parsed)
                except (ValueError, TypeError):
                    pass
                # Not JSON — regex-replace as form-encoded
                body = re.sub(
                    rf'{re.escape(vuln.parameter)}=[^&]*',
                    f'{vuln.parameter}={payload}',
                    vuln.body
                )
            elif is_json_api:
                # No body but JSON API — build minimal JSON
                import json as _json
                body = _json.dumps({vuln.parameter: payload})
            else:
                body = f"{vuln.parameter}={payload}"
            return url, body
    
    @abstractmethod
    async def validate(self, vuln: VulnReport) -> ValidationReport:
        """Validate the vulnerability - must be implemented by subclasses"""
        pass


def create_vuln_report_from_systematic(
    vuln_type: str,
    endpoint: str,
    evidence: str,
    method: str = "GET",
    headers: Dict = None,
    payload: str = "",
    parameter: str = "",
    owasp_category: str = "A05"
) -> VulnReport:
    """
    Helper to create VulnReport from systematic scanner findings.
    """
    return VulnReport(
        vuln_type=vuln_type,
        owasp_category=owasp_category,
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        payload=payload,
        evidence=evidence,
        headers=headers or {},
        body=None,
        baseline_response=None,
        attack_response=None
    )