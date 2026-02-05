"""
Systematic Scanner v6.0
- Phase 1 findings now routed through Validator Hub (zero false positives)
- Dedup uses exact endpoint + title match (was LIKE %/% matching everything)
- Removed URL encoding from XSS / SSTI / SSRF / Redirect — shell-escaped instead
- DB schema aligned to validation columns (removed orphan 'confidence' column)
- Removed dead SQLi payload ("1 AND 1=1" with empty indicators)
- Stripped trailing spaces from SSRF / Redirect / CORS payloads
- Added command counting to state (Phase 1 commands were invisible to orchestrator)

NOTE FOR ORCHESTRATOR: __init__ now takes `validator` — update the constructor call in
_systematic_phase to pass both `registry=self.registry` and `validator=self.validator`.
"""
import asyncio
import re
import json
from typing import Dict, Any, List, Set, Optional, Tuple
from urllib.parse import urlparse          # quote removed — no longer used
from dataclasses import dataclass, field

from src.mcp.client_hub import MCPClientHub
from src.db.database import Database

# ═══════════════════════════════════════════════════════════════
# VALIDATOR — all Phase 1 findings validated before DB write
# ═══════════════════════════════════════════════════════════════
from src.validator.hub import (
    VulnerabilityValidator,
    VulnReport,
    ValidationResult,
    create_vuln_report_from_agent
)


# ═══════════════════════════════════════════════════════════════
# PAYLOAD DEFINITIONS
# ═══════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    ("'",                  ["SQL", "mysql", "sqlite", "postgresql", "oracle", "syntax error", "query failed", "ORA-", "SQLSTATE", "Warning:", "You have an error"]),
    ('"',                  ["SQL", "mysql", "syntax error", "query failed"]),
    ("'--",                ["SQL", "mysql", "syntax"]),
    ("' OR '1'='1",        ["SQL", "mysql", "syntax"]),
    # REMOVED: ("1 AND 1=1", []) — empty indicators list meant it could never trigger
    ("' UNION SELECT NULL--", ["SQL", "UNION"]),
]

XSS_PAYLOADS = [
    ("<script>alert(1)</script>",            "<script>alert(1)</script>"),
    ("<img src=x onerror=alert(1)>",         "<img src=x onerror=alert(1)>"),
    ("'\"><script>alert(1)</script>",        "<script>alert(1)</script>"),
    ("<svg/onload=alert(1)>",                "<svg/onload=alert(1)>"),
    ('" onmouseover="alert(1)',              "onmouseover="),
]

LFI_PAYLOADS = [
    ("../../../etc/passwd",                                          "root:"),
    ("....//....//....//etc/passwd",                                 "root:"),
    ("..%2f..%2f..%2fetc/passwd",                                    "root:"),
    ("/etc/passwd",                                                  "root:"),
    ("..\\..\\..\\windows\\win.ini",                                 "[extensions]"),
    ("php://filter/convert.base64-encode/resource=index.php",        "PD9waHA"),
]

RCE_PAYLOADS = [
    ("; id",      "uid="),
    ("| id",      "uid="),
    ("$(id)",     "uid="),
    ("; whoami",  ["root", "www-data", "apache", "nginx"]),
    ("| whoami",  ["root", "www-data", "apache"]),
]

SSTI_PAYLOADS = [
    ("{{7*7}}",       "49"),
    ("{{7*'7'}}",     "7777777"),   # unique enough — no confirm needed
    ("${7*7}",        "49"),
    ("<%= 7*7 %>",    "49"),
]

# Two-probe confirmation: if primary check ("49") matches, send this second
# probe to the same endpoint+param.  "481" won't appear randomly in a normal
# page.  Payloads not in this dict skip confirmation — their expected value
# ("7777777") is already unique enough to not false-positive.
SSTI_CONFIRM = {
    "{{7*7}}":    ("{{13*37}}",    "481"),
    "${7*7}":     ("${13*37}",     "481"),
    "<%= 7*7 %>": ("<%= 13*37 %>", "481"),
}

SSRF_PAYLOADS = [
    # FIXED: trailing spaces removed — they were breaking URL matching
    ("http://127.0.0.1",                        ["localhost", "127.0.0.1", "root", "Apache", "nginx"]),
    ("http://localhost",                         ["localhost", "127.0.0.1"]),
    ("http://[::1]",                            ["localhost"]),
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
]

# FIXED: trailing space removed from first entry
OPEN_REDIRECT_PAYLOADS = ["https://evil.com", "//evil.com", "/\\evil.com"]

# Parameter names by vuln type
SQLI_PARAMS     = sorted(['id', 'cat', 'page', 'user', 'item', 'product', 'article', 'news', 'pid', 'uid', 'order', 'sort'])
XSS_PARAMS      = sorted(['search', 'q', 'query', 'name', 'user', 'msg', 'text', 'comment', 'keyword', 'message', 'content', 'title'])
LFI_PARAMS      = sorted(['file', 'page', 'path', 'include', 'doc', 'document', 'folder', 'root', 'pg', 'template', 'lang'])
RCE_PARAMS      = sorted(['cmd', 'exec', 'command', 'ping', 'host', 'ip', 'filename', 'code', 'run'])
SSRF_PARAMS     = sorted(['url', 'uri', 'path', 'src', 'dest', 'redirect', 'link', 'href', 'file', 'site', 'feed', 'target'])
REDIRECT_PARAMS = sorted(['url', 'redirect', 'next', 'return', 'goto', 'redir', 'return_url', 'continue', 'dest', 'out'])


class SystematicScanner:
    def __init__(self, target: str, scan_id: int, config: Dict, tui=None, state=None,
                 refresh_callback=None, registry=None, validator=None):
        self.target = target.rstrip('/')
        self.scan_id = scan_id
        self.config = config
        self.tui = tui
        self.state = state
        self.refresh_callback = refresh_callback
        self.registry = registry      # SharedRegistry — command cache
        self.validator = validator    # VulnerabilityValidator — zero false positives
        self.vulns_found = 0
        self.cmd_retries = config.get('cmd_retries', 2)

        # Mode-based settings
        mode = config.get('mode', 'normal')
        self.parallel_limit = {"quick": 10, "normal": 8, "thorough": 5}.get(mode, 8)
        self.payload_limit  = {"quick": 3,  "normal": 5, "thorough": 6}.get(mode, 5)

        if self.state is None:
            @dataclass
            class DummyState:
                endpoints:    set  = field(default_factory=set)
                parameters:   set  = field(default_factory=set)
                technologies: list = field(default_factory=set)
                commands_run: int  = 0
            self.state = DummyState()

    # ═══════════════════════════════════════════════════════════════
    # TUI HELPERS
    # ═══════════════════════════════════════════════════════════════

    def _log(self, msg: str, style: str = None):
        if self.tui:
            self.tui.log_scan(msg, style)
            if self.refresh_callback:
                self.refresh_callback()

    def _update_step(self, step: str):
        if self.tui:
            self.tui.update(step=step)
            if self.refresh_callback:
                self.refresh_callback()

    def _update_stats(self, **kwargs):
        if self.tui:
            self.tui.update(**kwargs)
            if self.refresh_callback:
                self.refresh_callback()

    # ═══════════════════════════════════════════════════════════════
    # PARALLEL EXECUTION (TUI-SAFE)
    # ═══════════════════════════════════════════════════════════════

    async def _run_cmd(self, mcp: MCPClientHub, cmd: str, timeout: int, retries: int = 2) -> Optional[str]:
        """Single command with TUI refresh and command counting"""
        if self.tui:
            self.tui.set_running_cmd(cmd)
            self.tui.log_cmd(cmd, "running")
            if self.refresh_callback:
                self.refresh_callback()

        result = None
        for attempt in range(retries + 1):
            try:
                task = asyncio.create_task(
                    mcp.execute("recon", "shell", {"command": cmd, "timeout": timeout})
                )
                while not task.done():
                    if self.refresh_callback:
                        self.refresh_callback()
                    await asyncio.sleep(0.2)

                res = task.result()
                if res.get("success"):
                    result = res["result"].get("output", "")
                    break
            except:
                pass
            if attempt < retries:
                await asyncio.sleep(0.3)

        # ── count this command ──────────────────────────────────
        self.state.commands_run += 1
        self._update_stats(commands=self.state.commands_run)

        if self.tui:
            self.tui.clear_running_cmd()
            self.tui.log_cmd(cmd, "done" if result else "error")
            if self.registry:
                self.registry.set_command_result(cmd, {"success": True, "output": result[:500]} if result else {"success": False})
            if self.refresh_callback:
                self.refresh_callback()

        return result

    async def _run_parallel(self, mcp: MCPClientHub, cmds: List[str], timeout: int) -> List[Optional[str]]:
        """Run commands in parallel — TUI keeps updating"""
        if not cmds:
            return []

        if self.tui:
            self.tui.set_running_cmd(f"[{len(cmds)} parallel]")
            if self.refresh_callback:
                self.refresh_callback()

        tasks = [asyncio.create_task(mcp.execute("recon", "shell", {"command": c, "timeout": timeout})) for c in cmds]

        while not all(t.done() for t in tasks):
            if self.refresh_callback:
                self.refresh_callback()
            await asyncio.sleep(0.2)

        results = []
        for i, task in enumerate(tasks):
            try:
                res = task.result()
                if res.get("success"):
                    output = res["result"].get("output", "")
                    results.append(output)
                    if self.registry:
                        self.registry.set_command_result(cmds[i], {"success": True, "output": output[:500]})
                else:
                    results.append(None)
            except:
                results.append(None)

        # ── count all commands in this batch ────────────────────
        self.state.commands_run += len(cmds)
        self._update_stats(commands=self.state.commands_run)

        if self.tui:
            self.tui.clear_running_cmd()

        return results

    async def _run_batched(self, mcp: MCPClientHub, cmds: List[str], timeout: int) -> List[Optional[str]]:
        """Run in batches respecting parallel_limit"""
        all_results = []
        for i in range(0, len(cmds), self.parallel_limit):
            batch = cmds[i:i + self.parallel_limit]
            results = await self._run_parallel(mcp, batch, timeout)
            all_results.extend(results)
        return all_results

    # ═══════════════════════════════════════════════════════════════
    # MAIN ENTRY
    # ═══════════════════════════════════════════════════════════════

    async def run(self, mcp: MCPClientHub, db: Database) -> int:
        self.mcp = mcp  # store — validator needs it to make HTTP requests
        try:
            await self._run_recon(mcp, db)
            await self._run_vuln_checks(mcp, db)
            return self.vulns_found
        except Exception as e:
            self._log(f"Error: {str(e)}", "red")
            raise

    # ═══════════════════════════════════════════════════════════════
    # RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════

    async def _run_recon(self, mcp: MCPClientHub, db: Database):
        self._log("")
        self._log("Step 1: Reconnaissance", "bold")

        # Tech detection
        self._update_step("Tech detection")
        self._log("  • Technology detection...")

        result = await self._run_cmd(mcp,
            f"whatweb --color=never --no-errors -a 3 {self.target}",
            30, 1)

        if result:
            # Parse text output (more reliable than JSON)
            # Format: [Tech1, Tech2], [Tech3]
            for match in re.findall(r'\[([^\]]+)\]', result):
                if match and not match.isdigit() and 'http' not in match.lower():
                    # Split comma-separated techs
                    for tech in match.split(','):
                        tech = tech.strip()
                        if tech and len(tech) < 50 and tech not in ['200 OK', 'RESERVED', 'ZZ']:
                            self.state.technologies.add(tech)

        tech_str = ', '.join(list(self.state.technologies)[:5]) or 'Unknown'
        self._log(f"    Found: {tech_str}", "green")

        # Content discovery
        self._update_step("Content discovery")
        self._log("  • Content discovery (parallel)...")

        paths = sorted([
            "/", "/index.php", "/index.html", "/admin/", "/admin.php", "/login", "/login.php",
            "/api/", "/api/v1/", "/robots.txt", "/.git/HEAD", "/.env", "/config.php",
            "/phpinfo.php", "/wp-admin/", "/wp-login.php", "/backup/", "/backup.sql",
            "/uploads/", "/upload/", "/files/", "/images/", "/tmp/", "/cache/",
            "/includes/", "/test.php", "/debug.php", "/.htaccess", "/server-status",
            "/sitemap.xml", "/swagger.json", "/graphql", "/rest/", "/web.config",
            "/administrator/", "/phpmyadmin/", "/manager/", "/.svn/entries",
        ])

        cmds = [f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {self.target}{p}" for p in paths]
        results = await self._run_batched(mcp, cmds, 10)

        for path, result in zip(paths, results):
            if result and result.strip() in ['200', '301', '302', '403', '401']:
                self.state.endpoints.add(path)

        self._update_stats(endpoints=len(self.state.endpoints))
        self._log(f"    Found {len(self.state.endpoints)} paths", "green")

        # Gobuster
        self._update_step("Dir bruteforce")
        self._log("  • Gobuster...")

        result = await self._run_cmd(mcp,
            f"gobuster dir -u {self.target} -w /usr/share/wordlists/dirb/common.txt -t 10 -q --no-error 2>/dev/null | head -50",
            90, 1)
        if result:
            count = 0
            for line in result.split('\n'):
                if '(Status:' in line:
                    m = re.search(r'(/\S+)', line)
                    if m:
                        self.state.endpoints.add(m.group(1))
                        count += 1
            self._update_stats(endpoints=len(self.state.endpoints))
            self._log(f"    +{count} paths", "green")

        # Param discovery
        self._update_step("Param discovery")
        self._log("  • Parameter discovery...")

        results = await self._run_parallel(mcp, [
            f"curl -s --max-time 10 {self.target} | grep -oE 'name=\"[^\"]+\"' | head -30",
            f"curl -s --max-time 10 {self.target} | grep -oE 'href=\"[^\"]+\"' | head -50",
        ], 15)

        for r in results:
            if r:
                self.state.parameters.update(re.findall(r'name="([^"]+)"', r))
                for href in re.findall(r'href="([^"]+)"', r):
                    if href.startswith('/'):
                        self.state.endpoints.add(urlparse(href).path)

        self._log(f"    {len(self.state.parameters)} params, {len(self.state.endpoints)} total endpoints", "green")

    # ═══════════════════════════════════════════════════════════════
    # VULNERABILITY CHECKS
    # ═══════════════════════════════════════════════════════════════

    async def _run_vuln_checks(self, mcp: MCPClientHub, db: Database):
        self._log("")
        self._log("Step 2: Vulnerability Checks", "bold")

        endpoints = self._prioritize_endpoints()

        await self._check_info_disclosure(mcp, db)
        await self._check_security_headers(mcp, db)
        await self._check_directory_listing(mcp, db)
        await self._check_sqli(mcp, db, endpoints)
        await self._check_xss(mcp, db, endpoints)
        await self._check_lfi(mcp, db, endpoints)
        await self._check_rce(mcp, db, endpoints)
        await self._check_ssti(mcp, db, endpoints)
        await self._check_ssrf(mcp, db, endpoints)
        await self._check_open_redirect(mcp, db, endpoints)
        await self._check_cors(mcp, db)
        await self._check_error_handling(mcp, db, endpoints)
        self._log(f"Systematic complete: {self.vulns_found} vulnerabilities", "bold green")

    def _prioritize_endpoints(self) -> List[str]:
        """Sort endpoints — high value first"""
        high, low = [], []
        keywords = ['admin', 'login', 'user', 'api', 'search', 'file', 'page', 'id', 'upload', 'download']

        for ep in sorted(self.state.endpoints):
            if any(k in ep.lower() for k in keywords):
                high.append(ep)
            else:
                low.append(ep)

        return (high + low)[:self.config.get('max_endpoints_to_test', 30)]

    # ─────────────────────────────────────────────────────────────
    async def _check_info_disclosure(self, mcp: MCPClientHub, db: Database):
        self._update_step("Info disclosure")
        self._log("  • Information disclosure...")

        checks = [
            ("/.git/HEAD",    "ref:",            "Git exposed",            "critical"),
            ("/.env",         "DB_PASSWORD=",    "Env file exposed",       "critical"),  # stricter pattern
            ("/phpinfo.php",  "phpinfo()",        "PHPInfo exposed",        "high"),
            ("/backup.sql",   "CREATE TABLE",    "SQL backup exposed",     "critical"),
            ("/server-status","Apache",           "Server status exposed",  "medium"),
        ]

        cmds = [f"curl -s --max-time 5 {self.target}{c[0]}" for c in checks]
        results = await self._run_batched(mcp, cmds, 10)

        for (path, check, title, sev), result in zip(checks, results):
            if result and check.lower() in result.lower():
                if await self._store_vuln(db, {"owasp": "A02", "title": title, "severity": sev,
                    "endpoint": path, "evidence": result[:300], "description": title,
                    "remediation": "Restrict access"}):
                    self._log(f"    [{sev.upper()}] {title}", "red" if sev in ["critical", "high"] else "yellow")

    # ─────────────────────────────────────────────────────────────
    async def _check_security_headers(self, mcp: MCPClientHub, db: Database):
        self._update_step("Security headers")
        self._log("  • Security headers...")

        result = await self._run_cmd(mcp, f"curl -s -I --max-time 10 {self.target}", 15)
        if not result:
            return

        for header in ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]:
            if header.lower() not in result.lower():
                if await self._store_vuln(db, {"owasp": "A02", "title": f"Missing {header}", "type": "Missing Header", "severity": "medium",
                    "endpoint": "/", "evidence": "Header not found in response",
                    "description": f"Missing security header: {header}", "remediation": f"Add {header}"}):
                    self._log(f"    [MEDIUM] Missing {header}", "yellow")

    # ─────────────────────────────────────────────────────────────
    async def _check_directory_listing(self, mcp: MCPClientHub, db: Database):
        self._update_step("Directory listing")
        self._log("  • Directory listing...")

        dir_paths = sorted([p for p in self.state.endpoints if p.endswith('/')])[:15]

        if not dir_paths:
            return

        cmds = [f"curl -s --max-time 5 {self.target}{path}" for path in dir_paths]
        results = await self._run_batched(mcp, cmds, 10)

        for path, result in zip(dir_paths, results):
            if result and ("Index of" in result or "Directory listing" in result or "[To Parent Directory]" in result):
                if await self._store_vuln(db, {"owasp": "A02", "title": f"Directory Listing: {path}", "type": "Directory Listing", "severity": "medium",
                    "endpoint": path, "evidence": "Index of / Directory listing found",
                    "description": "Directory listing enabled", "remediation": "Disable directory listing"}):
                    self._log(f"    [MEDIUM] Directory Listing: {path}", "yellow")

    # ─────────────────────────────────────────────────────────────
    async def _check_sqli(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("SQLi tests")
        self._log("  • SQL Injection (parallel)...")

        cmds, info = [], []
        for ep in endpoints:
            for param in SQLI_PARAMS[:10]:
                for payload, indicators in SQLI_PAYLOADS[:self.payload_limit]:
                    test_url = f"{self.target}{ep}?{param}=1{payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 5 '{escaped_url}' 2>/dev/null | head -50")
                    info.append((ep, param, payload, indicators))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, indicators), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            for ind in indicators:
                if ind.lower() in result.lower():
                    if await self._store_vuln(db, {"owasp": "A05", "title": f"SQL Injection: {ep}", "severity": "critical",
                        "endpoint": f"{ep}?{param}=", "evidence": result[:500], "parameter": param, "payload": payload,
                        "description": f"SQLi via {param}", "remediation": "Use prepared statements"}):
                        self._log(f"    [CRITICAL] SQLi: {ep}?{param}", "bold red")
                        found_combos.add(combo)
                    break

    # ─────────────────────────────────────────────────────────────
    async def _check_xss(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("XSS tests")
        self._log("  • XSS (parallel)...")

        cmds, info = [], []
        for ep in endpoints:
            for param in XSS_PARAMS[:8]:
                for payload, check in XSS_PAYLOADS[:self.payload_limit]:
                    # FIXED: no URL encoding — shell-escape with single quotes (was %3C/%3E)
                    test_url = f"{self.target}{ep}?{param}={payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 5 '{escaped_url}' 2>/dev/null")
                    info.append((ep, param, payload, check))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, check), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            if check in result:
                if await self._store_vuln(db, {"owasp": "A05", "title": f"XSS: {ep}", "severity": "high",
                    "endpoint": f"{ep}?{param}=", "evidence": f"Payload reflected: {payload[:50]}",
                    "parameter": param, "payload": payload,
                    "description": f"XSS via {param}", "remediation": "Encode output"}):
                    self._log(f"    [HIGH] XSS: {ep}?{param}", "red")
                    found_combos.add(combo)

    # ─────────────────────────────────────────────────────────────
    async def _check_lfi(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("LFI tests")
        self._log("  • LFI (parallel)...")

        cmds, info = [], []
        for ep in endpoints:
            for param in LFI_PARAMS[:8]:
                for payload, check in LFI_PAYLOADS[:self.payload_limit]:
                    test_url = f"{self.target}{ep}?{param}={payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 5 '{escaped_url}' 2>/dev/null | head -50")
                    info.append((ep, param, payload, check))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, check), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            if check in result:
                if await self._store_vuln(db, {"owasp": "A05", "title": f"LFI: {ep}", "severity": "critical",
                    "endpoint": f"{ep}?{param}=", "evidence": result[:500],
                    "parameter": param, "payload": payload,
                    "description": f"LFI via {param}", "remediation": "Whitelist files"}):
                    self._log(f"    [CRITICAL] LFI: {ep}?{param}", "bold red")
                    found_combos.add(combo)

    # ─────────────────────────────────────────────────────────────
    async def _check_rce(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("RCE tests")
        self._log("  • Command Injection (parallel)...")

        cmds, info = [], []
        for ep in endpoints[:20]:
            for param in RCE_PARAMS[:6]:
                for payload, check in RCE_PAYLOADS[:self.payload_limit]:
                    test_url = f"{self.target}{ep}?{param}=x{payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 5 '{escaped_url}' 2>/dev/null")
                    info.append((ep, param, payload, check))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, check), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            checks = check if isinstance(check, list) else [check]
            for c in checks:
                if c.lower() in result.lower():
                    if await self._store_vuln(db, {"owasp": "A05", "title": f"RCE: {ep}", "severity": "critical",
                        "endpoint": f"{ep}?{param}=", "evidence": result[:500],
                        "parameter": param, "payload": payload,
                        "description": f"Command injection via {param}", "remediation": "Never use shell commands with user input"}):
                        self._log(f"    [CRITICAL] RCE: {ep}?{param}", "bold red")
                        found_combos.add(combo)
                    break

    # ─────────────────────────────────────────────────────────────
    async def _check_ssti(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("SSTI tests")
        self._log("  • Template Injection (parallel)...")

        target_eps = endpoints[:20]

        # ── Phase A: baseline per endpoint (neutral param, no payload) ──
        # Fetch each endpoint once with a harmless value.  If "49" is already
        # in the response, it's ambient — no SSTI payload can "prove" evaluation.
        baseline_cmds = []
        for ep in target_eps:
            escaped = f"{self.target}{ep}?_=1".replace("'", "'\\''")
            baseline_cmds.append(f"curl -s --max-time 5 '{escaped}' 2>/dev/null")
        baseline_results = await self._run_batched(mcp, baseline_cmds, 12)
        # map: endpoint → set of strings that are ambient in its response
        baseline_ambient = {}
        for ep, base_body in zip(target_eps, baseline_results):
            baseline_ambient[ep] = base_body or ""

        # ── Phase B: attack requests (batched, same as before) ──
        cmds, info = [], []
        for ep in target_eps:
            for param in XSS_PARAMS[:8]:
                for payload, check in SSTI_PAYLOADS[:self.payload_limit]:
                    test_url = f"{self.target}{ep}?{param}={payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 5 '{escaped_url}' 2>/dev/null")
                    info.append((ep, param, payload, check))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, check), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue

            # ── baseline gate: skip if expected value is ambient ──
            if check in baseline_ambient.get(ep, ""):
                continue

            if check in result and payload not in result:
                # ── two-probe confirmation (belt + suspenders) ──
                confirm_entry = SSTI_CONFIRM.get(payload)
                if confirm_entry:
                    confirm_payload, confirm_check = confirm_entry
                    # also check confirm value isn't in baseline
                    if confirm_check in baseline_ambient.get(ep, ""):
                        continue
                    confirm_url = f"{self.target}{ep}?{param}={confirm_payload}"
                    confirm_escaped = confirm_url.replace("'", "'\\''")
                    confirm_result = await self._run_cmd(
                        mcp,
                        f"curl -s --max-time 5 '{confirm_escaped}' 2>/dev/null",
                        8
                    )
                    if not confirm_result or confirm_check not in confirm_result:
                        continue   # false positive
                # ── both probes passed (or payload was unique enough) ──
                if await self._store_vuln(db, {"owasp": "A05", "title": f"SSTI: {ep}", "severity": "critical",
                    "endpoint": f"{ep}?{param}=", "evidence": f"Evaluated: {payload}={check}",
                    "parameter": param, "payload": payload,
                    "description": f"SSTI via {param}", "remediation": "Sandbox templates"}):
                    self._log(f"    [CRITICAL] SSTI: {ep}?{param}", "bold red")
                    found_combos.add(combo)

    # ─────────────────────────────────────────────────────────────
    async def _check_ssrf(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("SSRF tests")
        self._log("  • SSRF (parallel)...")

        cmds, info = [], []
        for ep in endpoints[:15]:
            for param in SSRF_PARAMS[:8]:
                for payload, checks in SSRF_PAYLOADS[:self.payload_limit]:
                    # FIXED: no quote() encoding — shell-escape with single quotes
                    test_url = f"{self.target}{ep}?{param}={payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s --max-time 10 '{escaped_url}' 2>/dev/null | head -100")
                    info.append((ep, param, payload, checks))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload, checks), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            for c in checks:
                if c.lower() in result.lower():
                    if await self._store_vuln(db, {"owasp": "A05", "title": f"SSRF: {ep}", "severity": "high",
                        "endpoint": f"{ep}?{param}=", "evidence": result[:500],
                        "parameter": param, "payload": payload,
                        "description": f"SSRF via {param}", "remediation": "Whitelist URLs"}):
                        self._log(f"    [HIGH] SSRF: {ep}?{param}", "red")
                        found_combos.add(combo)
                    break

    # ─────────────────────────────────────────────────────────────
    async def _check_open_redirect(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        self._update_step("Redirect tests")
        self._log("  • Open Redirect (parallel)...")

        cmds, info = [], []
        for ep in endpoints[:15]:
            for param in REDIRECT_PARAMS[:8]:
                for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                    # FIXED: no quote() encoding — shell-escape with single quotes
                    test_url = f"{self.target}{ep}?{param}={payload}"
                    escaped_url = test_url.replace("'", "'\\''")
                    cmds.append(f"curl -s -I --max-time 5 '{escaped_url}' 2>/dev/null | grep -i '^location:'")
                    info.append((ep, param, payload))

        results = await self._run_batched(mcp, cmds, 12)
        found_combos = set()

        for (ep, param, payload), result in zip(info, results):
            if not result:
                continue
            combo = f"{ep}:{param}"
            if combo in found_combos:
                continue
            if "evil.com" in result.lower():
                if await self._store_vuln(db, {"owasp": "A01", "title": f"Open Redirect: {ep}", "severity": "medium",
                    "endpoint": f"{ep}?{param}=", "evidence": result[:200],
                    "parameter": param, "payload": payload,
                    "description": f"Open redirect via {param}", "remediation": "Whitelist destinations"}):
                    self._log(f"    [MEDIUM] Open Redirect: {ep}?{param}", "yellow")
                    found_combos.add(combo)

    # ─────────────────────────────────────────────────────────────
    async def _check_cors(self, mcp: MCPClientHub, db: Database):
        self._update_step("CORS tests")
        self._log("  • CORS...")

        # FIXED: trailing space removed from evil.com (was breaking the header match)
        result = await self._run_cmd(mcp, f"curl -s -I -H 'Origin: https://evil.com' --max-time 8 {self.target}", 12)
        if result and "Access-Control-Allow-Origin: https://evil.com" in result:
            if await self._store_vuln(db, {"owasp": "A01", "title": "CORS Misconfiguration", "severity": "high",
                "endpoint": "/", "evidence": "Reflects arbitrary origin",
                "description": "CORS allows any origin", "remediation": "Whitelist origins"}):
                self._log(f"    [HIGH] CORS Misconfiguration", "red")

    # ─────────────────────────────────────────────────────────────
    async def _check_error_handling(self, mcp: MCPClientHub, db: Database, endpoints: List[str]):
        """
        A10: Mishandling of Exceptional Conditions.
        Sends malformed / edge-case inputs and checks for HTTP 500+
        or stack traces in the response.  Matches what A10 validator's
        _validate_unhandled_exception re-tests.
        """
        self._update_step("Error handling")
        self._log("  • Error handling (A10)...")

        # ── payloads designed to provoke exceptions, NOT injection ──
        # Each tuple: (param_name, value)
        error_params = [
            ("id", "notanumber"),
            ("id", "[]"),
            ("id", "{}"),
            ("id", "null"),
            ("id", "undefined"),
            ("id", "NaN"),
            ("id", "1e999"),
            ("id", "9" * 50),
            ("id", "-" + "9" * 50),
            ("id", ""),
            ("page", "-1"),
            ("page", "0"),
            ("limit", "-1"),
            ("limit", "99999999999"),
            ("q", "'\"<>&;|`$(){}[]\\"),
            ("q", "%00"),
            ("q", "%C0%AE"),
            ("file", ""),
            ("name", "null"),
            ("email", "notanemail"),
        ]

        # ── Phase A: status-code sweep (fast — no body download) ──
        # curl -o /dev/null -w '%{http_code}' only outputs the 3-digit code
        cmds_status, info_status = [], []
        for ep in endpoints[:20]:
            for param, value in error_params:
                escaped = f"{self.target}{ep}?{param}={value}".replace("'", "'\\''")
                cmds_status.append(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 '{escaped}' 2>/dev/null")
                info_status.append((ep, param, value))

        results_status = await self._run_batched(mcp, cmds_status, 10)

        # collect every (ep, param, value) that returned 500 / 502 / 503
        hits_500 = []
        for (ep, param, value), code in zip(info_status, results_status):
            if code and code.strip() in ("500", "502", "503"):
                hits_500.append((ep, param, value, code.strip()))

        # ── Phase B: POST malformed JSON to /api/* endpoints ──
        api_endpoints = [ep for ep in endpoints if "/api" in ep.lower()][:10]
        cmds_post, info_post = [], []
        malformed_bodies = [
            ("not json at all", "plain text as JSON"),
            ("{bad json", "truncated JSON"),
            ('{"key": undefined}', "undefined value"),
            ("null", "null body"),
            ("[]", "array instead of object"),
            ('{"id": "' + "A" * 500 + '"}', "oversized field"),
        ]
        for ep in api_endpoints:
            for body, desc in malformed_bodies:
                escaped_url = f"{self.target}{ep}".replace("'", "'\\''")
                escaped_body = body.replace("'", "'\\''")
                cmds_post.append(
                    f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{escaped_body}' --max-time 5 '{escaped_url}' 2>/dev/null"
                )
                info_post.append((ep, "body", desc))

        results_post = await self._run_batched(mcp, cmds_post, 10)

        for (ep, param, desc), code in zip(info_post, results_post):
            if code and code.strip() in ("500", "502", "503"):
                hits_500.append((ep, param, desc, code.strip()))

        if not hits_500:
            self._log("    No server errors triggered", "dim")
            return

        # ── Phase C: re-fetch bodies for 500-hits to grab evidence ──
        # dedupe by endpoint so we don't store duplicates
        seen_ep = set()
        refetch_cmds, refetch_info = [], []
        for (ep, param, value, code) in hits_500:
            if ep in seen_ep:
                continue
            seen_ep.add(ep)
            if param == "body":
                # was a POST — re-send same way
                escaped_url = f"{self.target}{ep}".replace("'", "'\\''")
                refetch_cmds.append(
                    f"curl -s -X POST -H 'Content-Type: application/json' "
                    f"-d 'not json at all' --max-time 5 '{escaped_url}' 2>/dev/null | head -80"
                )
            else:
                escaped = f"{self.target}{ep}?{param}={value}".replace("'", "'\\''")
                refetch_cmds.append(f"curl -s --max-time 5 '{escaped}' 2>/dev/null | head -80")
            refetch_info.append((ep, param, value, code))

        refetch_results = await self._run_batched(mcp, refetch_cmds, 12)

        # ── Phase D: store confirmed hits ──
        for (ep, param, value, code), body in zip(refetch_info, refetch_results):
            evidence = f"HTTP {code}" + (f"\n{body[:300]}" if body else "")
            # vuln_type must contain "EXCEPTION" so A10 validator routes
            # to _validate_unhandled_exception (not _validate_error_disclosure)
            if await self._store_vuln(db, {
                "owasp": "A10",
                "title": f"Error Handling: {ep}",
                "type": "Unhandled Exception",
                "severity": "medium",
                "endpoint": ep,
                "parameter": param,
                "payload": value,
                "evidence": evidence,
                "description": f"Server error triggered on {ep} with {param}={value}",
                "remediation": "Implement consistent error handling — fail closed, no stack traces in responses"
            }):
                self._log(f"    [MEDIUM] Error Handling: {ep} (HTTP {code})", "yellow")

    # ═══════════════════════════════════════════════════════════════
    # _store_vuln — VALIDATES BEFORE STORING (zero false positives)
    # ═══════════════════════════════════════════════════════════════

    async def _store_vuln(self, db: Database, vuln: Dict) -> bool:
        """Validate → store. Returns True only if confirmed and written to DB."""
        try:
            ep    = urlparse(vuln.get("endpoint", "")).path.split("?")[0].rstrip("/").lower() or "/"
            title = vuln.get("title", "")[:40].lower()

            # ── FIXED: exact match on both columns ─────────────────────
            # Was: LIKE %{ep}% — when ep="/" that matched every single row,
            # silently blocking ALL subsequent vulns after the first one.
            if db.fetch_one(
                "SELECT id FROM vulnerabilities WHERE scan_id=%s AND LOWER(endpoint)=%s AND LOWER(title)=%s LIMIT 1",
                (self.scan_id, ep, title)
            ):
                return False

            sev = vuln.get("severity", "medium").lower()
            if sev not in ["critical", "high", "medium", "low", "info"]:
                sev = "medium"

            # ── VALIDATE before writing ────────────────────────────────
            validation = {}
            if self.validator:
                self._log(f"    🔍 Validating: {vuln.get('title', '?')[:40]}...", "dim")
                try:
                    vuln_report       = create_vuln_report_from_agent(vuln)
                    validation_result = await self.validator.validate(vuln_report, mcp=self.mcp, target=self.target)

                    if not validation_result.is_valid():
                        # REJECTED — never hits the DB
                        self._log(f"    ✗ Rejected: {vuln.get('title', '?')[:40]} — {validation_result.evidence[:60]}", "yellow")
                        return False

                    # CONFIRMED
                    validation = {
                        "result":   validation_result.result.value,
                        "confidence": validation_result.confidence,
                        "evidence": validation_result.evidence,
                        "method":   validation_result.validation_method,
                    }
                    self._log(f"    ✓ Validated ({validation_result.confidence:.0%}): {vuln.get('title', '?')[:40]}", "green")

                except Exception as e:
                    # Validation error — fail closed (don't store)
                    self._log(f"    ✗ Validation error: {str(e)[:60]}", "red")
                    return False
            else:
                # No validator wired in — flag it clearly so the orchestrator fix is obvious
                validation = {
                    "result":     "unvalidated",
                    "confidence": 0.0,
                    "evidence":   "Validator not passed to SystematicScanner",
                    "method":     "none",
                }

            # ── FIXED: schema uses validation_* columns ────────────────
            # Was: standalone 'confidence' column (int 80) that didn't exist in the
            # orchestrator's schema — INSERT silently failed inside bare except.
            db.insert(
                """INSERT INTO vulnerabilities
                   (scan_id, owasp_category, title, description, severity, endpoint,
                    evidence, found_by, remediation,
                    validation_result, validation_confidence, validation_evidence, validation_method)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (self.scan_id,
                 vuln.get("owasp", "A01"),
                 vuln.get("title", "?")[:255],
                 vuln.get("description", "")[:5000],
                 sev,
                 vuln.get("endpoint", "")[:500],
                 vuln.get("evidence", "")[:5000],
                 json.dumps(["systematic"]),
                 vuln.get("remediation", "")[:2000],
                 validation.get("result", "unvalidated"),
                 validation.get("confidence", 0.0),
                 validation.get("evidence", "")[:2000],
                 validation.get("method", "")[:100])
            )

            self.vulns_found += 1
            self._update_stats(vulns=self.vulns_found)
            return True

        except Exception as e:
            self._log(f"    DB error: {str(e)[:60]}", "red")
            return False

    def _log_action(self, db: Database, action_type: str, cmd: str, output: str):
        try:
            db.insert(
                "INSERT INTO action_log (scan_id, agent, action_type, command_executed, result_summary) VALUES (%s,%s,%s,%s,%s)",
                (self.scan_id, "systematic", action_type, cmd[:65000], output[:65000])
            )
        except:
            pass