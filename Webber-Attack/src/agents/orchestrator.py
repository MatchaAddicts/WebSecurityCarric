"""
Orchestrator v8.3 - ULTRA-AGGRESSIVE (COMPACT 64% SMALLER)
- Quick Mode: 60 iter × 4 rounds = 480 attempts/agent
- Normal Mode: 120 iter × 6 rounds = 1440 attempts/agent
- COMPACT PROMPT: 820 tokens (vs 2,283) - saves 87K tokens!
- CONCRETE PAYLOADS: Top 3-5 per vulnerability (not all variants)
- PAYLOAD MULTIPLIER: Test variants before giving up
- FIXED: mark_attempted() strings, better batching
- TARGET: 40+ vulns (Quick), 100+ vulns (Normal)
- OWASP 2025 compliant
"""

import asyncio
import json
import re
import time
import hashlib
import concurrent.futures
import threading
import sys
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.live import Live

from src.agents.openrouter import OpenRouterClient
from src.mcp.client_hub import MCPClientHub
from src.db.database import Database
from src.ui.tui import TriPanelTUI
from .systematic_scanner import SystematicScanner

# ═══════════════════════════════════════════════════════════════════════════
# VALIDATOR IMPORT - validates all vulns before counting
# ═══════════════════════════════════════════════════════════════════════════
from src.validator.hub import (
    VulnerabilityValidator,
    VulnReport,
    ValidationResult,
    create_vuln_report_from_agent
)

console = Console()


OWASP_2025 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration", 
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions"
}

SCAN_MODES = {
    "quick": {
        "systematic_timeout": 150,
        "inner_iterations": 60,        # 30→60: DOUBLED! (240 attempts per agent)
        "outer_iterations": 4,         # 3→4: One more round
        "no_progress_threshold": 5,    # 4→5: Don't stop early
        "command_timeout": 60,         # 45→60: More time per command
        "batch_size": 20,              # 15→20: More batch efficiency
        "max_endpoints_to_test": 60,   # 30→60: Test more endpoints
    },
    "normal": {
        "systematic_timeout": 300,
        "inner_iterations": 120,       # 80→120: MASSIVE increase (720 attempts per agent)
        "outer_iterations": 6,         # 5→6: More rounds
        "no_progress_threshold": 6,    # 5→6: More patience
        "command_timeout": 90,
        "batch_size": 25,              # 15→25: Bigger batches
        "max_endpoints_to_test": 100,  # 50→100: Test way more
    },
    "thorough": {
        "systematic_timeout": 600,
        "inner_iterations": 200,       # 120→200: MAXIMUM coverage
        "outer_iterations": 8,         # 7→8: Maximum rounds
        "no_progress_threshold": 7,    # 6→7: Never give up
        "command_timeout": 120,
        "batch_size": 30,              # 20→30: Maximum batching
        "max_endpoints_to_test": 200,  # 100→200: Test everything
    }
}


class SharedRegistry:
    """Thread-safe shared registry for vulns and commands"""
    
    def __init__(self):
        self._found_vulns: Dict[str, Dict] = {}  # Successfully validated
        self._attempted_vulns: Dict[str, Dict] = {}  # ALL attempts (validated + rejected)
        # SEPARATE command cache per agent - no lock contention!
        self._executed_commands_1: Dict[str, Dict] = {}  # Claude
        self._executed_commands_2: Dict[str, Dict] = {}  # Moonshot
        self._vuln_lock = threading.Lock()  # Only for vulns (less frequent)
    
    def add_vuln(self, vuln_type: str, endpoint: str, agent: str, vuln_data: Dict) -> bool:
        """Add successfully validated vuln"""
        key = f"{vuln_type}|{endpoint}".lower()
        with self._vuln_lock:
            if key not in self._found_vulns:
                self._found_vulns[key] = {"type": vuln_type, "endpoint": endpoint, "agents": [agent], "data": vuln_data}
                return True
            else:
                if agent not in self._found_vulns[key]["agents"]:
                    self._found_vulns[key]["agents"].append(agent)
                return False
    
    def mark_attempted(self, vuln_type: str, endpoint: str, agent: str, validated: bool) -> bool:
        """Mark vuln as attempted (whether validated or rejected). Returns True if NEW attempt."""
        key = f"{vuln_type}|{endpoint}".lower()
        with self._vuln_lock:
            if key not in self._attempted_vulns:
                self._attempted_vulns[key] = {
                    "type": vuln_type, 
                    "endpoint": endpoint, 
                    "attempts": 1,
                    "agents": [agent],
                    "validated": validated
                }
                return True
            else:
                self._attempted_vulns[key]["attempts"] += 1
                if agent not in self._attempted_vulns[key]["agents"]:
                    self._attempted_vulns[key]["agents"].append(agent)
                return False  # Already attempted
    
    def is_vuln_found(self, vuln_type: str, endpoint: str) -> bool:
        """Check if vuln was successfully validated"""
        key = f"{vuln_type}|{endpoint}".lower()
        with self._vuln_lock:
            return key in self._found_vulns
    
    def is_vuln_attempted(self, vuln_type: str, endpoint: str) -> bool:
        """Check if vuln was already attempted (validated OR rejected)"""
        key = f"{vuln_type}|{endpoint}".lower()
        with self._vuln_lock:
            return key in self._attempted_vulns
    
    def get_found_vulns_summary(self) -> str:
        with self._vuln_lock:
            if not self._found_vulns:
                return ""
            lines = [f"- {d['type']} at {d['endpoint']}" for d in list(self._found_vulns.values())[:50]]
            return "\n".join(lines)
    
    def get_command_result(self, command: str, agent_num: int = 1) -> Optional[Dict]:
        """Get cached result - NO LOCK, each agent has own cache"""
        key = hashlib.md5(command.lower().strip().encode()).hexdigest()[:16]
        cache = self._executed_commands_1 if agent_num == 1 else self._executed_commands_2
        return cache.get(key)
    
    def set_command_result(self, command: str, result: Dict, agent_num: int = 1):
        """Set cached result - NO LOCK, each agent has own cache"""
        key = hashlib.md5(command.lower().strip().encode()).hexdigest()[:16]
        cache = self._executed_commands_1 if agent_num == 1 else self._executed_commands_2
        cache[key] = result
    
    def get_vuln_count(self) -> int:
        with self._vuln_lock:
            return len(self._found_vulns)
    
    def get_attempted_count(self) -> int:
        """Get total attempts (validated + rejected)"""
        with self._vuln_lock:
            return len(self._attempted_vulns)
    
    def clear(self):
        with self._vuln_lock:
            self._found_vulns.clear()
            self._attempted_vulns.clear()
        self._executed_commands_1.clear()
        self._executed_commands_2.clear()


@dataclass  
class ScanStateData:
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)
    technologies: List[str] = field(default_factory=set)
    vulns_found: int = 0
    commands_run: int = 0


# ════════════════════════════════════════════════════════════════════
# LIVE STATUS BAR - Background thread updates using \r (NO Rich Live)
# ════════════════════════════════════════════════════════════════════

class LiveStatusBar:
    """Background thread that updates status bar using \\r - works with console.print"""
    
    def __init__(self, start_time: float, state: ScanStateData, get_vuln_count):
        self.start_time = start_time
        self.state = state
        self.get_vuln_count = get_vuln_count
        self.claude_status = "idle"
        self.moonshot_status = "idle"
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._last_line_len = 0
    
    def update(self, agent: str = None, agent_status: str = None, endpoints: int = None, vulns: int = None, commands: int = None):
        with self._lock:
            if agent == "claude" and agent_status:
                self.claude_status = agent_status
            elif agent == "moonshot" and agent_status:
                self.moonshot_status = agent_status
    
    def _build_line(self) -> str:
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        vulns = self.get_vuln_count()
        endpoints = len(self.state.endpoints)
        cmds = self.state.commands_run
        
        with self._lock:
            c_stat, m_stat = self.claude_status, self.moonshot_status
        
        # ANSI colors
        C, G, R, Y, D, B, RST = "\033[96m", "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[1m", "\033[0m"
        
        c_color = G if c_stat == "scanning" else (Y if c_stat == "thinking" else D)
        m_color = G if m_stat == "scanning" else (Y if m_stat == "thinking" else D)
        
        return f"{C}⏱ {B}{mins:02d}:{secs:02d}{RST} {D}│{RST} {D}📍{RST} {G}{endpoints}{RST} {D}│{RST} {D}🔥{RST} {R if vulns else D}{vulns}{RST} {D}│{RST} {D}⚡{RST} {Y}{cmds}{RST} {D}│{RST} {D}Claude:{RST} {c_color}{c_stat}{RST} {D}│{RST} {D}Moonshot:{RST} {m_color}{m_stat}{RST}"
    
    def _update_loop(self):
        while self._running:
            line = self._build_line()
            padding = " " * max(0, self._last_line_len - len(line))
            sys.stdout.write(f"\r{line}{padding}")
            sys.stdout.flush()
            self._last_line_len = len(line)
            time.sleep(0.5)
    
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._update_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write(f"\r{self._build_line()}\n")
        sys.stdout.flush()
    
    def println(self, text: str):
        """Print line below status bar"""
        padding = " " * self._last_line_len
        sys.stdout.write(f"\r{padding}\r{text}\n")
        sys.stdout.flush()


class Orchestrator:
    """
    Orchestrator v8.3 - ULTRA-AGGRESSIVE (COMPACT)
    
    KEY IMPROVEMENTS FROM v8.2:
    - 64% SMALLER PROMPT: 820 tokens vs 2,283
    - SAME PAYLOADS: All concrete attacks kept
    - BETTER CONTEXT: 25% usage vs 68%
    - TOKEN SAVINGS: 87,780 tokens freed
    
    FEATURES:
    - 2X iterations: Quick 60, Normal 120
    - Concrete payloads for OWASP 2025
    - Payload multiplier (3-5 variants)
    - ID enumeration (1-50 ranges)
    - Batch optimization (20-30 requests)
    
    EXPECTED RESULTS:
    - Quick: 40-60 vulns (30-40 min)
    - Normal: 100-150 vulns (60-90 min)
    """
    
    def __init__(self):
        self.agents = {1: "claude_scanner", 2: "moonshot_scanner"}
        self.state = ScanStateData()
        self.registry = SharedRegistry()
        self._lock = threading.Lock()
        self.tui = None
        self.status_bar = None
        self.live = None
        self.global_start_time = None
        self._scan_id = None
        self._vuln_cache = 0
        self._vuln_cache_time = 0
        
        # ═══════════════════════════════════════════════════════════════
        # VALIDATOR - validates all vulns before counting
        # ═══════════════════════════════════════════════════════════════
        self.validator = VulnerabilityValidator(timeout=10, retries=2)
    
    async def initialize(self):
        console.print("[cyan]Initializing Orchestrator v8.3 (Ultra-Aggressive Compact)...[/cyan]")
        
        db = Database()
        db.connect()
        console.print("  • [green]Database:[/green] Connected ✓")
        db.close()
        
        llm = OpenRouterClient()
        console.print("  • [green]OpenRouter:[/green] Configured ✓")
        console.print(f"    - Scanner 1: {llm.models['scanner_1']} (Claude)")
        console.print(f"    - Scanner 2: {llm.models['scanner_2']} (Moonshot)")
        
        mcp = MCPClientHub()
        await mcp.initialize()
        console.print(f"  • [green]MCP Servers:[/green] Ready ✓")
        await mcp.shutdown()
        
        console.print("  • [green]Vulnerability Validator:[/green] Ready ✓")
        console.print("    - Zero false positives mode enabled")
        console.print("  • [green]Multi-Layer Attack:[/green] Enabled ✓")
        console.print("    - Attack chains, depth escalation, payload factory")
        
        console.print("[green]Orchestrator ready.[/green]\n")
    
    def _refresh_tui(self):
        if self.live and self.tui:
            self.live.update(self.tui.render())
    
    def _get_db_vuln_count(self, scan_id: int) -> int:
        db = Database()
        db.connect()
        try:
            result = db.fetch_one("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE scan_id = %s", (scan_id,))
            return result['cnt'] if result else 0
        finally:
            db.close()
    
    def _get_db_vuln_count_cached(self) -> int:
        now = time.time()
        if now - self._vuln_cache_time > 2:
            self._vuln_cache = self._get_db_vuln_count(self._scan_id)
            self._vuln_cache_time = now
        return self._vuln_cache
    
    async def run_scan(self, target: str, scan_id: int, quick: bool = False, thorough: bool = False) -> Dict[str, Any]:
        self.state = ScanStateData()
        self.registry.clear()
        self._scan_id = scan_id
        
        mode = "thorough" if thorough else ("quick" if quick else "normal")
        config = {**SCAN_MODES[mode], 'mode': mode}
        
        self.global_start_time = time.time()
        
        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Mode:[/bold] {mode.upper()}\n"
            f"[bold]Strategy:[/bold] ULTRA-AGGRESSIVE COMPACT (64% smaller prompt)\n"
            f"[bold]Agents:[/bold] Claude + Moonshot (parallel, temp=0.3)\n"
            f"[bold]Iterations:[/bold] {config['inner_iterations']} × {config['outer_iterations']} rounds = {config['inner_iterations'] * config['outer_iterations'] * 2} total attempts\n"
            f"[bold]Prompt Size:[/bold] [green]820 tokens[/green] (saves 87K vs v8.2)\n"
            f"[bold]Payloads:[/bold] [green]TOP 3-5[/green] per vulnerability type\n"
            f"[bold]Expected:[/bold] {40 if mode=='quick' else 100 if mode=='normal' else 150}+ vulnerabilities",
            title="Scan Configuration v8.3 - Compact Aggressive"
        ))
        console.print()
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 1: SYSTEMATIC (TriPanelTUI with Rich Live)
        # ═══════════════════════════════════════════════════════════════
        self.tui = TriPanelTUI(
            target=target, mode=mode, phase_name="Systematic",
            start_time=self.global_start_time,
            initial_vulns=0, initial_endpoints=0, initial_commands=0
        )
        
        with Live(self.tui.render(), console=console, refresh_per_second=4, 
                  screen=False, transient=False) as live:
            self.live = live
            
            self.tui.log_scan("━" * 40, "yellow")
            self.tui.log_scan("PHASE 1: SYSTEMATIC SCAN", "bold yellow")
            self.tui.log_scan("━" * 40, "yellow")
            self._refresh_tui()
            
            await self._systematic_phase(target, scan_id, config)
            
            self.tui.log_scan("")
            self.tui.log_scan(f"Systematic complete: {self.tui.vulns} vulns", "bold green")
            self._refresh_tui()
            await asyncio.sleep(0.5)
            self.live = None
        
        phase1_vulns = self.tui.vulns
        phase1_endpoints = self.tui.endpoints
        phase1_commands = self.tui.commands
        
        console.print("\n" + "═" * 70)
        console.print("[bold magenta]PHASE 2: MULTI-LAYER AGENTIC SCAN[/bold magenta]")
        console.print("[dim]Layer 1: Recon → Layer 2: Shallow → Layer 3: Escalation → Layer 4: Deep[/dim]")
        console.print("═" * 70 + "\n")
        
        # ═══════════════════════════════════════════════════════════════
        # PHASE 2: AGENTIC (LiveStatusBar - background thread, NO Rich Live)
        # ═══════════════════════════════════════════════════════════════
        self.state.vulns_found = phase1_vulns
        self.state.commands_run = phase1_commands
        
        self.status_bar = LiveStatusBar(
            start_time=self.global_start_time,
            state=self.state,
            get_vuln_count=self._get_db_vuln_count_cached
        )
        
        self.status_bar.start()
        try:
            await self._agentic_phase(target, scan_id, config)
        finally:
            self.status_bar.stop()
        
        console.print("\n" + "═" * 70)
        console.print("[bold green]SCAN COMPLETE[/bold green]")
        console.print("═" * 70)
        
        results = self._aggregate_from_db(scan_id)
        results['scan_duration'] = time.time() - self.global_start_time
        return results
    
    async def _systematic_phase(self, target: str, scan_id: int, config: Dict):
        """Phase 1: Systematic baseline scanning"""
        mcp = MCPClientHub()
        await mcp.initialize()
        db = Database()
        db.connect()
        
        try:
            scanner = SystematicScanner(
                target, scan_id, config, self.tui, self.state,
                refresh_callback=self._refresh_tui,
                registry=self.registry,
                validator=self.validator
            )
            await scanner.run(mcp, db)
            
            # Update state with systematic findings
            if hasattr(scanner, 'discovered_endpoints'):
                self.state.endpoints.update(scanner.discovered_endpoints)
        finally:
            await mcp.shutdown()
            db.close()
    
    async def _agentic_phase(self, target: str, scan_id: int, config: Dict):
        """Phase 2: Multi-layer agentic deep scanning with attack chains"""
        
        no_progress_count = 0
        prev_attempt_count = self.registry.get_attempted_count()
        
        for outer_iter in range(config['outer_iterations']):
            self.status_bar.println(f"\n[bold cyan]═══ Round {outer_iter + 1}/{config['outer_iterations']} ═══[/bold cyan]")
            
            # Run both agents in parallel
            results = await self._run_parallel_agents(target, scan_id, config, outer_iter)
            
            # Log results
            for res in results:
                agent_name = res.get("agent", "unknown")
                validated = res.get("validated", 0)
                rejected = res.get("rejected", 0)
                iters = res.get("iterations", 0)
                cmds = res.get("commands_run", 0)
                self.status_bar.println(
                    f"  [dim]{agent_name}: {validated} validated, {rejected} rejected, {iters} iters, {cmds} cmds[/dim]"
                )
            
            # Check progress - count NEW ATTEMPTS (not just validated)
            attempt_count = self.registry.get_attempted_count()
            new_attempts = attempt_count - prev_attempt_count
            prev_attempt_count = attempt_count
            
            # As long as agents are finding NEW vulns (even if rejected), that's progress
            if new_attempts == 0:
                no_progress_count += 1
                self.status_bar.println(f"  [yellow]No new vulns attempted in this round ({no_progress_count}/{config['no_progress_threshold']})[/yellow]")
                if no_progress_count >= config['no_progress_threshold']:
                    self.status_bar.println(f"  \033[33mNo new attempts for {no_progress_count} rounds, stopping\033[0m")
                    break
            else:
                no_progress_count = 0
                self.status_bar.println(f"  [green]Progress: {new_attempts} new vulns attempted this round[/green]")
    
    async def _run_parallel_agents(self, target: str, scan_id: int, config: Dict, outer_iter: int) -> List[Dict]:
        """Run both agents in parallel"""
        
        self.status_bar.update(agent="claude", agent_status="starting")
        self.status_bar.update(agent="moonshot", agent_status="starting")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self._run_agent_sync, agent_num, config, scan_id, target, outer_iter): agent_num
                for agent_num in [1, 2]
            }
            
            for future in concurrent.futures.as_completed(futures):
                agent_num = futures[future]
                agent_short = "claude" if agent_num == 1 else "moonshot"
                
                try:
                    result = future.result()
                    results.append(result)
                    self.status_bar.update(agent=agent_short, agent_status="done")
                except Exception as e:
                    self.status_bar.println(f"\033[31mAgent {agent_num} error: {e}\033[0m")
                    self.status_bar.update(agent=agent_short, agent_status="error")
                    results.append({"agent": self.agents[agent_num], "vulns_found": 0, "iterations": 0, "commands_run": 0, "validated": 0, "rejected": 0})
        
        return results
    
    def _run_agent_sync(self, agent_num: int, config: Dict, scan_id: int, target: str, outer_iter: int) -> Dict:
        """Run agent in thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(
                self._run_agent(agent_num, config, scan_id, target, outer_iter)
            )
        finally:
            loop.close()
    
    async def _run_agent(self, agent_num: int, config: Dict, scan_id: int, target: str, outer_iter: int) -> Dict:
        """Single agent - temp=0.3, multi-layer OWASP prompt, WITH VALIDATION"""
        agent_name = self.agents[agent_num]
        agent_short = "claude" if agent_num == 1 else "moonshot"
        
        # Color codes for clear distinction
        if agent_num == 1:
            C = "\033[96m"  # Cyan for Claude
        else:
            C = "\033[95m"  # Magenta for Moonshot
        RST = "\033[0m"
        
        llm = OpenRouterClient()
        mcp = MCPClientHub()
        await mcp.initialize()
        db = Database()
        db.connect()
        
        self.status_bar.println(f"  {C}[{agent_short}]{RST} Starting multi-layer scan...")
        self.status_bar.update(agent=agent_short, agent_status="scanning")
        
        # Build multi-layer OWASP prompt
        prompt = self._build_multilayer_prompt(target, config, outer_iter, agent_num)
        messages = [{"role": "user", "content": prompt}]
        
        vulns_found = 0
        validated_count = 0
        rejected_count = 0
        commands_run = 0
        iteration = 0
        consecutive_unclear = 0
        consecutive_no_new = 0
        last_http_responses = {}  # Cache for validator evidence
        
        for iteration in range(config['inner_iterations']):
            # Update shared state every 5 iterations
            if iteration > 0 and iteration % 5 == 0:
                found_summary = self.registry.get_found_vulns_summary()
                if found_summary:
                    messages.append({
                        "role": "user",
                        "content": f"PROGRESS - Already found:\n{found_summary}\n\nContinue with remaining OWASP categories and deeper exploitation layers."
                    })
            
            # Very aggressive message trimming - keep first prompt + last 8 messages only
            if len(messages) > 12:
                messages = messages[:2] + messages[-8:]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 📝 Trimmed to {len(messages)} msgs")
            
            self.status_bar.update(agent=agent_short, agent_status="thinking")
            self.status_bar.println(f"    {C}[{agent_short}]{RST} 🧠 Thinking...")
            
            # API call with timeout handling
            try:
                response = llm.chat_scanner(agent_num, messages, temperature=0.3)
            except Exception as e:
                self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[31mAPI timeout/error: {str(e)[:40]}\033[0m")
                await asyncio.sleep(2)
                continue
            
            self.status_bar.update(agent=agent_short, agent_status="scanning")
            
            if not response["success"]:
                self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[31mAPI error: {response.get('error', 'Unknown')[:50]}\033[0m")
                await asyncio.sleep(1)
                continue
            
            reply = response["content"]
            messages.append({"role": "assistant", "content": reply})
            
            action = self._parse_action(reply)
            self.status_bar.update(agent=agent_short, agent_status="scanning")
            
            # ═══════════════════════════════════════════════════════════════
            # SHELL EXECUTION
            # ═══════════════════════════════════════════════════════════════
            if action["type"] == "exec":
                cmd = action["command"]
                
                # Print BEFORE executing so we see what's running
                self.status_bar.println(f"    {C}[{agent_short}]{RST} ▶ {cmd[:65]}{'...' if len(cmd) > 65 else ''}")
                
                result = await self._execute_with_cache(mcp, cmd, config['command_timeout'], agent_name, scan_id, db, target, agent_num)
                commands_run += 1
                
                # Update global counter (GIL makes int increment atomic)
                self.state.commands_run += 1
                
                status = "✓" if result.get("success") else "✗"
                cached = " (cached)" if result.get("cached") else ""
                self.status_bar.println(f"    {C}[{agent_short}]{RST} {status} done{cached}")
                
                if result.get("success"):
                    output = result.get("output", "")
                    self._extract_endpoints(output, target)
                    
                    # Smart summarization - keep it small (2KB max)
                    output_summary = self._summarize_output(output, 2000)
                    feedback = f"Output:\n```\n{output_summary}\n```\nAnalyze for vulns. Continue."
                else:
                    feedback = f"Error: {result.get('error', 'Unknown')[:100]}. Try different approach."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # BATCH SHELL EXECUTION
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "batch":
                cmds = action["commands"][:config['batch_size']]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} ▶ Running {len(cmds)} commands...")
                
                # Print each command we're about to run
                for cmd in cmds:
                    self.status_bar.println(f"      {C}[{agent_short}]{RST} ▶ {cmd[:55]}{'...' if len(cmd) > 55 else ''}")
                
                batch_results = await self._execute_batch_with_cache(mcp, cmds, config['command_timeout'], agent_name, scan_id, db, target, agent_num)
                commands_run += len(cmds)
                
                # Update global counter
                self.state.commands_run += len(cmds)
                
                self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ Batch complete")
                
                feedback_parts = []
                for i, (cmd, res) in enumerate(zip(cmds, batch_results)):
                    status = "✓" if res.get("success") else "✗"
                    cached = " (cached)" if res.get("cached") else ""
                    self.status_bar.println(f"      {C}[{agent_short}]{RST} {status} {cmd[:55]}{'...' if len(cmd) > 55 else ''}{cached}")
                    
                    if res.get("success"):
                        output = res.get("output", "")
                        self._extract_endpoints(output, target)
                        output_summary = self._summarize_output(output, 500)
                        feedback_parts.append(f"[{i+1}] {cmd[:30]}: {output_summary}")
                    else:
                        feedback_parts.append(f"[{i+1}] Error: {res.get('error', '')[:60]}")
                
                feedback = "\n".join(feedback_parts[:10]) + "\nAnalyze results. Continue testing."
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # HTTP ATTACK - Single Request
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "http_attack":
                http_params = action["data"]
                url = http_params.get("url", "?")
                method = http_params.get("method", "GET")
                
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 🌐 {method} {url[:50]}...")
                
                result = await mcp.execute("exploit", "http_attack", http_params, agent=agent_name)
                commands_run += 1
                self.state.commands_run += 1
                
                if result.get("success") and result.get("result", {}).get("success"):
                    http_result = result["result"]
                    code = http_result.get("status_code", "?")
                    body = http_result.get("body", "")
                    
                    # Cache response for validator
                    cache_url = http_result.get("final_url", url)
                    last_http_responses[cache_url] = http_result
                    
                    self._extract_endpoints(body, target)
                    
                    body_summary = self._summarize_output(body, 1500)
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ {code} ({http_result.get('response_time', 0)}s)")
                    
                    feedback = f"HTTP {code}:\n{body_summary}\nAnalyze for vulns. Continue."
                    self._log_action(db, scan_id, agent_name, "http_attack", f"{method} {url}", body[:2000])
                else:
                    error = result.get("error", result.get("result", {}).get("error", "Unknown"))
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✗ HTTP error: {error[:40]}")
                    feedback = f"HTTP error: {error[:150]}. Try different approach."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # HTTP BATCH - Parallel Requests
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "http_batch":
                batch_reqs = action["requests"]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 🌐 Firing {len(batch_reqs)} HTTP requests...")
                
                result = await mcp.execute("exploit", "http_batch", {"requests": batch_reqs}, agent=agent_name)
                commands_run += len(batch_reqs)
                self.state.commands_run += len(batch_reqs)
                
                if result.get("success"):
                    batch_data = result.get("result", {})
                    ok = batch_data.get("successful", 0)
                    fail = batch_data.get("failed", 0)
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ Batch done: {ok} ok, {fail} failed")
                    
                    # Build compact feedback
                    feedback_parts = []
                    for i, res in enumerate(batch_data.get("results", [])):
                        req_url = batch_reqs[i].get("url", "?") if i < len(batch_reqs) else "?"
                        if res.get("success"):
                            code = res.get("status_code", "?")
                            body = res.get("body", "")
                            
                            # Cache response
                            cache_url = res.get("final_url", req_url)
                            last_http_responses[cache_url] = res
                            
                            self._extract_endpoints(body, target)
                            snippet = self._summarize_output(body, 800)
                            feedback_parts.append(f"[{i+1}] {code} {req_url}\n{snippet}")
                            self._log_action(db, scan_id, agent_name, "http_batch", req_url, body[:2000])
                        else:
                            feedback_parts.append(f"[{i+1}] ERR {req_url}: {res.get('error', '')[:80]}")
                    
                    feedback = "\n".join(feedback_parts) + "\nAnalyze for vulns. Continue."
                else:
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✗ Batch error: {result.get('error', '')[:60]}")
                    feedback = f"HTTP batch failed: {result.get('error', 'Unknown')[:150]}. Try individually."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # PYTHON EXECUTION - Payload Factory
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "python_exec":
                code = action["code"]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 🐍 Running Python ({len(code)} chars)...")
                
                result = await mcp.execute("payload_factory", "python_exec", {
                    "code": code,
                    "timeout": 30,
                    "cache": True
                }, agent=agent_name)
                
                if result.get("success") and result.get("result", {}).get("success"):
                    py_result = result["result"]
                    stdout = py_result.get("stdout", "")
                    cached = " (cached)" if py_result.get("cached") else ""
                    
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ Python done{cached}: {stdout[:80]}...")
                    
                    feedback = f"Python output:\n```\n{stdout[:2000]}\n```\nUse this in your next attack. Continue."
                else:
                    stderr = result.get("result", {}).get("stderr", "Unknown error")
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✗ Python error: {stderr[:60]}")
                    feedback = f"Python error:\n{stderr[:500]}\nFix code or try different approach."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # NODE.JS EXECUTION - Payload Factory
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "node_exec":
                code = action["code"]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 📦 Running Node.js ({len(code)} chars)...")
                
                result = await mcp.execute("payload_factory", "node_exec", {
                    "code": code,
                    "timeout": 30,
                    "cache": True
                }, agent=agent_name)
                
                if result.get("success") and result.get("result", {}).get("success"):
                    node_result = result["result"]
                    stdout = node_result.get("stdout", "")
                    cached = " (cached)" if node_result.get("cached") else ""
                    
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ Node done{cached}: {stdout[:80]}...")
                    
                    feedback = f"Node output:\n```\n{stdout[:2000]}\n```\nUse this in your next attack. Continue."
                else:
                    stderr = result.get("result", {}).get("stderr", "Unknown error")
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✗ Node error: {stderr[:60]}")
                    feedback = f"Node error:\n{stderr[:500]}\nFix code or try different approach."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # ENSURE TOOL - Auto-install Missing Tools
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "ensure_tool":
                tool = action["tool"]
                self.status_bar.println(f"    {C}[{agent_short}]{RST} 🔧 Ensuring tool: {tool}")
                
                result = await mcp.execute("exploit", "ensure_tool", {
                    "tool": tool,
                    "package": action.get("package")
                }, agent=agent_name)
                
                if result.get("success") and result.get("result", {}).get("installed"):
                    tool_result = result["result"]
                    action_type = tool_result.get("action", "unknown")
                    
                    if action_type == "already_installed":
                        self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ {tool} already installed")
                        feedback = f"{tool} is ready. Proceed with testing."
                    elif action_type == "installed_now":
                        self.status_bar.println(f"    {C}[{agent_short}]{RST} ✓ {tool} installed successfully")
                        feedback = f"{tool} installed successfully. You can now use it."
                    else:
                        feedback = f"{tool} is available. Continue."
                else:
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} ✗ Failed to install {tool}")
                    feedback = f"Could not install {tool}. Use alternative tools or manual installation."
                
                messages.append({"role": "user", "content": feedback})
                consecutive_unclear = 0
            
            # ═══════════════════════════════════════════════════════════════
            # VULN HANDLING - WITH VALIDATION
            # ═══════════════════════════════════════════════════════════════
            elif action["type"] == "vuln":
                vuln = action["data"]
                vuln_type = self._extract_vuln_type(vuln.get("title", ""), vuln.get("owasp", ""))
                endpoint = self._normalize_endpoint(vuln.get("endpoint", ""))
                owasp_cat = vuln.get("owasp", "A01").upper()
                
                # DEDUP CHECK - Use registry attempted tracking
                if self.registry.is_vuln_attempted(vuln_type, endpoint):
                    messages.append({"role": "user", "content": "Already attempted (validated OR rejected). Try different endpoint/payload."})
                    consecutive_no_new += 1
                else:
                    # NEW VULN ATTEMPT - mark it
                    self.registry.mark_attempted(vuln_type, endpoint, agent_name, "attempted")
                    
                    # VALIDATE THE VULNERABILITY BEFORE STORING
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} 🔍 Validating: {vuln.get('title', 'Unknown')[:40]}...")
                    self.status_bar.update(agent=agent_short, agent_status="validating")
                    
                    try:
                        # Attach cached response matching this endpoint
                        vuln_ep = vuln.get("endpoint", "")
                        for c_url, c_resp in last_http_responses.items():
                            if vuln_ep and vuln_ep.rstrip("/") in c_url:
                                vuln["_original_response"] = c_resp
                                break

                        # Convert agent's report to VulnReport object
                        vuln_report = create_vuln_report_from_agent(vuln)
                        
                        # Validate
                        validation_result = await self.validator.validate(vuln_report, mcp=mcp, target=target)
                        
                        if validation_result.is_valid():
                            # ═══ CONFIRMED ═══
                            # Add validation evidence to vuln data
                            vuln["validation"] = {
                                "result": validation_result.result.value,
                                "confidence": validation_result.confidence,
                                "evidence": validation_result.evidence,
                                "method": validation_result.validation_method
                            }
                            
                            # Store it and mark as validated
                            self.registry.mark_attempted(vuln_type, endpoint, agent_name, "validated")
                            self.registry.add_vuln(vuln_type, endpoint, agent_name, vuln)
                            self._store_vuln(db, scan_id, vuln, agent_name)
                            vulns_found += 1
                            validated_count += 1
                            
                            sev = vuln.get("severity", "medium").upper()
                            title = vuln.get("title", "Unknown")
                            self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[1;32m✓ VALIDATED [{sev}] {title}\033[0m")
                            self.status_bar.println(f"      {C}[{agent_short}]{RST} \033[2m  Evidence: {validation_result.evidence[:60]}...\033[0m")
                            
                            messages.append({
                                "role": "user", 
                                "content": f"CONFIRMED: Vulnerability validated ({validation_result.validation_method}, {validation_result.confidence:.0%} confidence). Continue testing OTHER endpoints or OTHER vuln types."
                            })
                            consecutive_no_new = 0  # Reset counter on success
                        else:
                            # ═══ REJECTED ===
                            rejected_count += 1
                            self.registry.mark_attempted(vuln_type, endpoint, agent_name, "rejected")
                            title = vuln.get("title", "Unknown")
                            self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[33m✗ REJECTED: {title[:40]}\033[0m")
                            self.status_bar.println(f"      {C}[{agent_short}]{RST} \033[2m  Reason: {validation_result.evidence[:60]}...\033[0m")
                            
                            # DON'T count rejection as "no progress" - it's a NEW attempt!
                            # Only tell agent to try something else
                            messages.append({
                                "role": "user",
                                "content": f"Could not confirm. Reason: {validation_result.evidence[:100]}. Try DIFFERENT payload/parameter or test OTHER vulnerabilities."
                            })
                            # Don't increment consecutive_no_new - rejection means they tried something new!
                    
                    except Exception as e:
                        # Validation error - log but don't count as failure
                        self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[31mValidation error: {str(e)[:50]}\033[0m")
                        messages.append({
                            "role": "user",
                            "content": f"Validation failed: {str(e)[:100]}. Continue with other tests."
                        })
                    
                    self.status_bar.update(agent=agent_short, agent_status="scanning")
                
                consecutive_unclear = 0
                
                # Only stop if TRULY stuck (15 consecutive duplicates)
                if consecutive_no_new >= 15:
                    self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[33m15 consecutive duplicates, moving on\033[0m")
                    break
            
            elif action["type"] == "done":
                self.status_bar.println(f"    {C}[{agent_short}]{RST} \033[32mCompleted all checks\033[0m")
                break
            
            else:
                consecutive_unclear += 1
                if consecutive_unclear >= 3:
                    messages.append({"role": "user", "content": self._get_format_reminder()})
                if consecutive_unclear >= 6:
                    break
        
        await mcp.shutdown()
        db.close()
        
        self.status_bar.println(f"  {C}[{agent_short}]{RST} \033[1;32mDone: {vulns_found} vulns ({validated_count} validated, {rejected_count} rejected), {iteration+1} iters, {commands_run} cmds\033[0m")
        
        return {
            "agent": agent_name,
            "vulns_found": vulns_found,
            "validated": validated_count,
            "rejected": rejected_count,
            "iterations": iteration + 1,
            "commands_run": commands_run
        }
    
    def _build_multilayer_prompt(self, target: str, config: Dict, outer_iter: int, agent_num: int) -> str:
        """COMPACT ultra-aggressive prompt - same payloads, 60% smaller"""
        
        found_summary = self.registry.get_found_vulns_summary()
        found_section = f"\n━━ FOUND ━━\n{found_summary}" if found_summary else ""
        
        endpoints = list(self.state.endpoints)[:25]
        endpoints_str = ", ".join(sorted(endpoints)) if endpoints else "(discover first)"
        
        return f"""TARGET: {target} | Round {outer_iter+1} | Endpoints: {endpoints_str}{found_section}

╔══════════════════════════════════════════════════════════════╗
║ OWASP 2025 ULTRA-AGGRESSIVE | TEST MULTIPLE PAYLOADS/ENDPOINT ║
╚══════════════════════════════════════════════════════════════╝

CORE: Try 3-5 payloads per vuln before moving on. Enumerate IDs 1-50.

═══ A01: ACCESS CONTROL (30% of vulns) ═══
IDOR: /api/user/1 → Test 2-20 (batch), /api/order/X → Test X+1 to X+20
Unauth: Try /api/admin, /rest/admin/*, /api/users, /api/feedbacks WITHOUT auth
Privesc: Add ?admin=true, ?role=admin, ?isAdmin=1 to requests

═══ A05: INJECTION (25% of vulns) ═══
SQLi (try ALL on EVERY input): ' OR 1=1--, " OR "1"="1, admin'--, ') OR 1=1--, ' UNION SELECT NULL--
NoSQL: {{"$ne":null}}, {{"$gt":""}}, {{"username":{{"$ne":""}},"password":{{"$ne":""}}}}
XSS: <script>alert(1)</script>, <img src=x onerror=alert(1)>, <svg onload=alert(1)>
Cmd: ; ls, | cat /etc/passwd, `whoami`

═══ A02: MISCONFIG ═══
Files: /.env, /.git/config, /backup.zip, /config.php, /robots.txt
Dirs: Check /uploads/, /files/, /backup/ for listings
Errors: Send malformed JSON/params → Stack traces = vuln

═══ A10: EXCEPTIONAL CONDITIONS ═══
Path: ../../etc/passwd, ..%2F..%2Fetc%2Fpasswd, ....//....//etc/passwd
Null: file.txt%00.pdf, file%2500.md (bypass filters)

═══ A07: AUTHENTICATION ═══
Creds: admin:admin, admin:password, test:test on /login, /rest/user/login
SQLi Bypass: email=' OR 1=1--&password=x
Session: Try without cookies, old tokens

═══ A08: INTEGRITY ═══
JWT: Decode → Change role/admin claim → Re-encode with weak secret (secret, 123456)
Cookies: Change role=user → role=admin

═══ A04: CRYPTO ═══
Hash Leak: MD5 in responses? → Crack: admin, password, 123456
Data Leak: Passwords, tokens, keys in HTML/JS/responses

═══ A06: DESIGN ═══
Logic: Register without verify? Negative prices? Skip payment steps?
CAPTCHA: Remove param, replay old value
Rate: Brute force → Any blocking?

═══ A03: SUPPLY CHAIN ═══
Headers: X-Powered-By, Server → Old versions = CVEs
JS: Check for old jQuery, Angular, React versions

═══ A09: LOGGING ═══
Errors: Paths, stack traces, queries exposed?
Blocking: Try 100 failed logins → No block = vuln

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRATEGY: 
Phase 1 (Iter 1-20): Discover endpoints with http_batch (test 20 paths at once)
Phase 2 (Iter 21-40): Test EACH endpoint with 3-5 payloads
Phase 3 (Iter 41-60): Enumerate IDs, chain attacks, business logic

CRITICAL:
• PAYLOAD MULTIPLIER: 1 fails? Try 3-5 variants
• ID ENUMERATION: /api/user/1? Test 1-20 with http_batch
• BATCH EVERYTHING: 10-20 requests per http_batch
• CONCRETE EVIDENCE: Show exact payload + response

TOOLS:
{{"action":"http_batch","requests":[{{"method":"GET","url":"{target}/api/user/1"}},{{"method":"GET","url":"{target}/api/user/2"}}]}}
{{"action":"http_attack","method":"POST","url":"{target}/login","data":"email=' OR 1=1--&password=x"}}
{{"action":"python_exec","code":"import jwt; print(jwt.encode({{'role':'admin'}},'secret'))"}}
{{"action":"vuln","owasp":"A05","title":"SQL Injection Bypasses Login","severity":"critical","endpoint":"/login","parameter":"email","payload":"' OR 1=1--","evidence":"Got auth token + admin data","description":"SQLi auth bypass"}}

JSON ONLY. START: {{"action":"""
    
    def _get_format_reminder(self) -> str:
        return 'JSON: {"action":"exec/batch/http_attack/http_batch/python_exec/node_exec/ensure_tool/vuln/done",...}'
    
    def _parse_action(self, reply: str) -> Dict[str, Any]:
        """Parse agent's JSON action from reply"""
        try:
            # Find JSON in reply
            start = reply.find("{")
            if start < 0:
                return {"type": "unclear"}
            
            # Handle nested braces
            brace_count = 0
            end = start
            for i, c in enumerate(reply[start:], start):
                if c == '{':
                    brace_count += 1
                elif c == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = i + 1
                        break
            
            if end <= start:
                return {"type": "unclear"}
            
            data = json.loads(reply[start:end])
            action = data.get("action", "")
            
            if action == "exec":
                cmd = data.get("command", "")
                if cmd:
                    return {"type": "exec", "command": cmd}
            
            elif action == "batch":
                cmds = data.get("commands", [])
                if isinstance(cmds, list) and cmds:
                    return {"type": "batch", "commands": cmds}
            
            elif action == "http_attack":
                if data.get("url"):
                    return {"type": "http_attack", "data": data}
            
            elif action == "http_batch":
                reqs = data.get("requests", [])
                if isinstance(reqs, list) and reqs:
                    return {"type": "http_batch", "requests": reqs}
            
            elif action == "python_exec":
                code = data.get("code", "")
                if code:
                    return {"type": "python_exec", "code": code}
            
            elif action == "node_exec":
                code = data.get("code", "")
                if code:
                    return {"type": "node_exec", "code": code}
            
            elif action == "ensure_tool":
                tool = data.get("tool", "")
                if tool:
                    return {"type": "ensure_tool", "tool": tool, "package": data.get("package")}
            
            elif action == "vuln":
                return {"type": "vuln", "data": data}
            
            elif action == "done":
                return {"type": "done"}
        except:
            pass
        return {"type": "unclear"}
    
    def _extract_vuln_type(self, title: str, owasp: str) -> str:
        """Extract normalized vulnerability type for deduplication"""
        vuln_type = f"{owasp}_{title}".lower()
        vuln_type = re.sub(r'[^a-z0-9_]', '', vuln_type)
        return vuln_type[:100]
    
    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for deduplication"""
        if not endpoint or endpoint == "/":
            return "/"
        try:
            path = urlparse(endpoint).path
        except:
            path = endpoint
        return path.split("?")[0].rstrip("/").lower() or "/"
    
    def _store_vuln(self, db, scan_id: int, vuln: Dict, agent: str):
        """Store vulnerability with validation data"""
        try:
            # Get validation data if present
            validation = vuln.get("validation", {})
            
            db.insert(
                """INSERT INTO vulnerabilities 
                   (scan_id, owasp_category, title, description, severity, endpoint, evidence, found_by, remediation,
                    validation_result, validation_confidence, validation_evidence, validation_method)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (scan_id, vuln.get("owasp", "A01").upper(), vuln.get("title", "Unknown")[:255],
                 vuln.get("description", "")[:5000], vuln.get("severity", "medium").lower(),
                 vuln.get("endpoint", "")[:500], vuln.get("evidence", "")[:10000],
                 json.dumps([agent]), vuln.get("remediation", "")[:2000],
                 validation.get("result", "validated"), validation.get("confidence", 1.0),
                 validation.get("evidence", "")[:2000], validation.get("method", "")[:100])
            )
        except Exception as e:
            # Fallback: try without validation columns
            try:
                db.insert(
                    """INSERT INTO vulnerabilities 
                       (scan_id, owasp_category, title, description, severity, endpoint, evidence, found_by, remediation)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (scan_id, vuln.get("owasp", "A01").upper(), vuln.get("title", "Unknown")[:255],
                     vuln.get("description", "")[:5000], vuln.get("severity", "medium").lower(),
                     vuln.get("endpoint", "")[:500], vuln.get("evidence", "")[:10000],
                     json.dumps([agent]), vuln.get("remediation", "")[:2000])
                )
            except Exception as e2:
                self.status_bar.println(f"\033[31mDB error: {e2}\033[0m")
    
    def _log_action(self, db, scan_id: int, agent: str, action_type: str, cmd: str, output: str):
        try:
            db.insert(
                "INSERT INTO action_log (scan_id, agent, action_type, command_executed, result_summary) VALUES (%s,%s,%s,%s,%s)",
                (scan_id, agent[:50], action_type[:50], cmd[:5000], output[:5000])
            )
        except:
            pass
    
    async def _execute_with_cache(self, mcp, cmd: str, timeout: int, agent: str, scan_id: int, db, target: str, agent_num: int = 1) -> Dict:
        """Execute with agent-specific cache - no lock contention"""
        cached = self.registry.get_command_result(cmd, agent_num)
        if cached:
            return {**cached, "cached": True}
        
        result = await mcp.execute("recon", "shell", {"command": cmd, "timeout": timeout}, agent=agent)
        
        # Unwrap the result from MCP hub wrapper
        if result.get("success") and "result" in result:
            inner_result = result["result"]
        else:
            inner_result = result
        
        if inner_result.get("success"):
            # Log to DB (fire and forget)
            self._log_action(db, scan_id, agent, "exec", cmd, inner_result.get("output", "")[:2000])
        
        self.registry.set_command_result(cmd, inner_result, agent_num)
        return inner_result
    
    async def _execute_batch_with_cache(self, mcp, cmds: List[str], timeout: int, agent: str, scan_id: int, db, target: str, agent_num: int = 1) -> List[Dict]:
        """Execute batch with agent-specific cache"""
        results = []
        to_execute = []
        cached_indices = {}
        
        for i, cmd in enumerate(cmds):
            cached = self.registry.get_command_result(cmd, agent_num)
            if cached:
                cached_indices[i] = {**cached, "cached": True}
            else:
                to_execute.append((i, cmd))
        
        # Execute uncached commands
        if to_execute:
            exec_cmds = [cmd for _, cmd in to_execute]
            batch_result = await mcp.execute("recon", "shell_batch", {"commands": exec_cmds, "timeout": timeout}, agent=agent)
            
            # Unwrap result from MCP hub wrapper
            if batch_result.get("success") and "result" in batch_result:
                inner_batch = batch_result["result"]
            else:
                inner_batch = batch_result
            
            if inner_batch.get("success"):
                inner_results = inner_batch.get("results", [])
                for j, (orig_idx, cmd) in enumerate(to_execute):
                    res = inner_results[j] if j < len(inner_results) else {"success": False}
                    self.registry.set_command_result(cmd, res, agent_num)
                    cached_indices[orig_idx] = res
                    
                    if res.get("success"):
                        self._log_action(db, scan_id, agent, "batch", cmd, res.get("output", "")[:1000])
            else:
                for orig_idx, cmd in to_execute:
                    cached_indices[orig_idx] = {"success": False, "error": "Batch failed"}
        
        # Reconstruct results in original order
        for i in range(len(cmds)):
            results.append(cached_indices.get(i, {"success": False, "error": "Missing result"}))
        
        return results
    
    def _extract_endpoints(self, output: str, target: str):
        """Extract endpoints from command output"""
        try:
            parsed = urlparse(target)
            base_domain = parsed.netloc.lower()
        except:
            base_domain = target.lower()
        
        # Patterns to find URLs/paths
        patterns = [
            r'https?://[^\s<>"\']+',
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'/[a-zA-Z0-9_\-./]+(?:\?[^\s<>"\']*)?',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, output, re.I)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                try:
                    # Normalize
                    if match.startswith('http'):
                        parsed_match = urlparse(match)
                        if base_domain in parsed_match.netloc.lower():
                            path = parsed_match.path
                            if path and path != '/':
                                self.state.endpoints.add(path.split('?')[0])
                    elif match.startswith('/'):
                        path = match.split('?')[0]
                        if path and path != '/' and len(path) < 200:
                            self.state.endpoints.add(path)
                except:
                    pass
    
    def _summarize_output(self, output: str, max_len: int = 2000) -> str:
        """Smart summarization - prioritize useful info"""
        if len(output) <= max_len:
            return output
        
        lines = output.split('\n')
        
        # Priority patterns
        priority_patterns = [
            r'error|warning|critical|vulnerable|injection|xss|sql|admin|password|token|secret|key|auth|login|session|cookie|jwt|bearer',
            r'200|301|302|401|403|404|500|nginx|apache|php|mysql|postgresql',
            r'/api/|/admin|/login|/user|/account|\.env|\.git|config|backup',
        ]
        
        priority_lines = []
        other_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if any(re.search(p, line, re.I) for p in priority_patterns):
                priority_lines.append(line)
            else:
                other_lines.append(line)
        
        # Build summary - priority lines first
        summary_parts = []
        char_count = 0
        
        for line in priority_lines:
            if char_count + len(line) + 1 < max_len - 200:
                summary_parts.append(line)
                char_count += len(line) + 1
        
        # Add header from other lines
        header = '\n'.join(other_lines[:10])
        if char_count + len(header) < max_len - 200:
            summary_parts.insert(0, f"[START]\n{header}\n[/START]")
            char_count += len(header)
        
        # Fill remaining space with other lines
        for line in other_lines[10:]:
            if char_count + len(line) + 1 < max_len - 100:
                summary_parts.append(line)
                char_count += len(line) + 1
            else:
                break
        
        result = '\n'.join(summary_parts)
        if len(output) > len(result):
            result += f"\n\n[...truncated {len(output) - len(result)} chars, {len(lines) - len(summary_parts)} lines]"
        
        return result
    
    def _aggregate_from_db(self, scan_id: int) -> Dict[str, Any]:
        console.print("\n[cyan]Aggregating results...[/cyan]")
        
        db = Database()
        db.connect()
        
        try:
            vulns = db.fetch_all(
                """SELECT owasp_category, title, description, severity, endpoint, evidence, found_by, remediation,
                        validation_confidence, validation_result, validation_evidence, validation_method
                FROM vulnerabilities WHERE scan_id = %s
                ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')""",
                (scan_id,)
            )
            
            final_vulns = []
            owasp_coverage = set()
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            
            for row in vulns:
                try:
                    found_by = json.loads(row['found_by']) if row['found_by'] else ["unknown"]
                except:
                    found_by = ["unknown"]
                
                final_vulns.append({
                    "owasp": row['owasp_category'],
                    "title": row['title'],
                    "description": row['description'],
                    "severity": row['severity'],
                    "endpoint": row['endpoint'],
                    "evidence": row['evidence'],
                    "remediation": row['remediation'],
                    "found_by": found_by,
                    "validation": {
                        "confidence": row.get('validation_confidence', 1.0),
                        "result": row.get('validation_result', 'validated'),
                        "evidence": row.get('validation_evidence', ''),
                        "method": row.get('validation_method', '')
                    }
                })
                
                owasp_coverage.add(row['owasp_category'])
                sev = row['severity'].lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            console.print(f"\n[bold]═══ SCAN RESULTS ═══[/bold]")
            console.print(f"  Total vulnerabilities: [bold red]{len(final_vulns)}[/bold red] [green](all validated)[/green]")
            console.print(f"  OWASP categories covered: [bold]{len(owasp_coverage)}/10[/bold] ({', '.join(sorted(owasp_coverage))})")
            console.print(f"  Endpoints discovered: [bold green]{len(self.state.endpoints)}[/bold green]")
            console.print(f"  Commands executed: [bold yellow]{self.state.commands_run}[/bold yellow]")
            console.print(f"\n  [bold]By Severity:[/bold]")
            console.print(f"    Critical: [bold red]{severity_counts['critical']}[/bold red]")
            console.print(f"    High:     [bold orange1]{severity_counts['high']}[/bold orange1]")
            console.print(f"    Medium:   [bold yellow]{severity_counts['medium']}[/bold yellow]")
            console.print(f"    Low:      [bold blue]{severity_counts['low']}[/bold blue]")
            console.print(f"    Info:     [dim]{severity_counts['info']}[/dim]")
            
            # Calculate OWASP coverage
            by_owasp = {}
            for vuln in final_vulns:
                owasp = vuln.get("owasp", "UNKNOWN")
                by_owasp[owasp] = by_owasp.get(owasp, 0) + 1

            by_agent = {}
            raw_count = 0
            for vuln in final_vulns:
                raw_count += 1
                agents = vuln.get("found_by", [])
                for agent in agents:
                    agent_name = agent.replace("_scanner", "")
                    by_agent[agent_name] = by_agent.get(agent_name, 0) + 1

            return {
                "total": len(final_vulns),
                "vulnerabilities": final_vulns,
                "owasp_coverage": list(owasp_coverage),
                "severity_counts": severity_counts,
                "endpoints_discovered": len(self.state.endpoints),
                "commands_executed": self.state.commands_run,
                "by_owasp": by_owasp,
                "by_agent": by_agent,
                "raw_count": raw_count
            }

        finally:
            db.close()
    
    async def shutdown(self):
        pass
    
    async def parallel_recon(self, target: str, scan_id: int, quick: bool = False):
        return await self.run_scan(target, scan_id, quick=quick)