"""
TUI Components for Scanner
- TriPanelTUI: Full 3-panel TUI for Systematic phase
- LiveStatusLine: Simple one-line status for Agentic phase (no lag)
"""
import time
import threading
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text

console = Console()


@dataclass
class TUIState:
    """Shared scan state"""
    endpoints: set = field(default_factory=set)
    parameters: set = field(default_factory=set)
    technologies: List[str] = field(default_factory=list)
    vulns_found: int = 0
    commands_run: int = 0


class TriPanelTUI:
    """
    3-Panel Split TUI for Systematic Phase:
    ┌──────────────┬─────────────────────────┐
    │   Status     │   Scan Log              │
    ├──────────────┴─────────────────────────┤
    │   Command Log                          │
    └─────────────────────────────────────────┘
    """
    
    def __init__(self, target: str, mode: str, phase_name: str = "Scan",
                 start_time: Optional[float] = None,
                 initial_vulns: int = 0,
                 initial_endpoints: int = 0,
                 initial_commands: int = 0,
                 initial_state: Optional[TUIState] = None):
        self.target = target
        self.mode = mode
        self.phase_name = phase_name
        self.start_time = start_time if start_time is not None else time.time()
        
        self.vulns = initial_vulns
        self.endpoints = initial_endpoints
        self.commands = initial_commands
        
        self.state = initial_state if initial_state is not None else TUIState()
        self.state.vulns_found = self.vulns
        self.state.commands_run = self.commands
        
        self.step = ""
        self.agent_status = {"claude": "idle", "moonshot": "idle"}
        
        self.scan_log: List[Dict] = []
        self.cmd_log: List[Dict] = []
        
        self.scan_log_scroll = 0
        self.cmd_log_scroll = 0
        self.scan_visible = 20
        self.cmd_visible = 8
        
        self.current_cmd = ""
        self.current_cmd_start = 0
        
        self._lock = threading.Lock()
        self._spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._spinner_idx = 0
    
    def update(self, step: str = None, vulns: int = None,
               endpoints: int = None, commands: int = None, 
               agent: str = None, agent_status: str = None):
        with self._lock:
            if step is not None:
                self.step = step
            if vulns is not None:
                self.vulns = vulns
            if endpoints is not None:
                self.endpoints = endpoints
            if commands is not None:
                self.commands = commands
            if agent and agent_status:
                self.agent_status[agent] = agent_status
    
    def log_scan(self, message: str, style: str = None):
        with self._lock:
            self.scan_log.append({"text": message, "style": style, "time": time.time()})
    
    def log_cmd(self, cmd: str, status: str = "done"):
        with self._lock:
            display_cmd = cmd[:80] + "..." if len(cmd) > 80 else cmd
            self.cmd_log.append({"cmd": display_cmd, "full_cmd": cmd, "status": status, "time": time.time()})
    
    def set_running_cmd(self, cmd: str):
        with self._lock:
            self.current_cmd = cmd[:80] + "..." if len(cmd) > 80 else cmd
            self.current_cmd_start = time.time()
    
    def clear_running_cmd(self):
        with self._lock:
            self.current_cmd = ""
            self.current_cmd_start = 0
    
    @property
    def elapsed(self) -> str:
        seconds = int(time.time() - self.start_time)
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"
    
    def _spinner(self) -> str:
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
        return self._spinner_frames[self._spinner_idx]
    
    def _cmd_elapsed(self) -> str:
        if not self.current_cmd_start:
            return ""
        return f"{int(time.time() - self.current_cmd_start)}s"
    
    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="top", ratio=3),
            Layout(name="command_log", ratio=1, minimum_size=8),
        )
        layout["top"].split_row(
            Layout(name="status", ratio=1, minimum_size=28),
            Layout(name="scan_log", ratio=2),
        )
        
        layout["status"].update(self._render_status())
        layout["scan_log"].update(self._render_scan_log())
        layout["command_log"].update(self._render_cmd_log())
        
        return layout
    
    def _render_status(self) -> Panel:
        lines = []
        
        timer_line = Text()
        timer_line.append("⏱  ", style="cyan")
        timer_line.append(f"{self.elapsed}", style="bold cyan")
        lines.append(timer_line)
        lines.append(Text())
        
        phase_line = Text()
        phase_line.append("Phase: ", style="dim")
        phase_line.append(f"{self.phase_name}", style="bold blue")
        lines.append(phase_line)
        
        if self.step:
            step_line = Text()
            step_line.append("Step: ", style="dim")
            step_line.append(f"{self.step}", style="white")
            lines.append(step_line)
        
        lines.append(Text("─" * 20, style="dim"))
        
        stats1 = Text()
        stats1.append("📍 ", style="dim")
        stats1.append(f"{self.endpoints}", style="bold green")
        stats1.append(" endpoints", style="dim")
        lines.append(stats1)
        
        stats2 = Text()
        stats2.append("🔥 ", style="dim")
        stats2.append(f"{self.vulns}", style="bold red" if self.vulns > 0 else "dim")
        stats2.append(" vulns", style="dim")
        lines.append(stats2)
        
        stats3 = Text()
        stats3.append("⚡ ", style="dim")
        stats3.append(f"{self.commands}", style="bold yellow")
        stats3.append(" cmds", style="dim")
        lines.append(stats3)
        
        if self.agent_status.get("claude") != "idle" or self.agent_status.get("moonshot") != "idle":
            lines.append(Text("─" * 20, style="dim"))
            
            claude_stat = self.agent_status.get("claude", "idle")
            claude_style = "green" if claude_stat == "scanning" else ("yellow" if claude_stat == "thinking" else "dim")
            c_line = Text()
            c_line.append("Claude:   ", style="dim")
            c_line.append(f"{claude_stat}", style=claude_style)
            lines.append(c_line)
            
            moon_stat = self.agent_status.get("moonshot", "idle")
            moon_style = "green" if moon_stat == "scanning" else ("yellow" if moon_stat == "thinking" else "dim")
            m_line = Text()
            m_line.append("Moonshot: ", style="dim")
            m_line.append(f"{moon_stat}", style=moon_style)
            lines.append(m_line)
        
        if self.current_cmd:
            lines.append(Text("─" * 20, style="dim"))
            running = Text()
            running.append(f"{self._spinner()} ", style="cyan")
            running.append("Running...", style="dim italic")
            lines.append(running)
            
            elapsed = Text()
            elapsed.append(f"   {self._cmd_elapsed()}", style="yellow")
            lines.append(elapsed)
        
        return Panel(Group(*lines), title="[bold blue]Status[/bold blue]", border_style="blue", padding=(0, 1))
    
    def _render_scan_log(self) -> Panel:
        lines = []
        
        with self._lock:
            total_entries = len(self.scan_log)
            start_idx = max(0, total_entries - self.scan_visible - self.scan_log_scroll)
            end_idx = total_entries - self.scan_log_scroll
            
            visible_entries = self.scan_log[start_idx:end_idx]
            for entry in visible_entries:
                text = Text(entry["text"])
                if entry.get("style"):
                    text.stylize(entry["style"])
                lines.append(text)
        
        if not lines:
            lines.append(Text("Waiting for scan output...", style="dim italic"))
        
        return Panel(Group(*lines), title=f"[bold yellow]Scan Log[/bold yellow] [dim]({total_entries} entries)[/dim]", border_style="yellow", padding=(0, 1))
    
    def _render_cmd_log(self) -> Panel:
        lines = []
        
        with self._lock:
            total_entries = len(self.cmd_log)
            start_idx = max(0, total_entries - self.cmd_visible - self.cmd_log_scroll)
            end_idx = total_entries - self.cmd_log_scroll
            
            visible_entries = self.cmd_log[start_idx:end_idx]
            for entry in visible_entries:
                cmd_text = Text()
                if entry["status"] == "running":
                    cmd_text.append(f"{self._spinner()} ", style="cyan")
                elif entry["status"] == "done":
                    cmd_text.append("✓ ", style="green")
                elif entry["status"] == "error":
                    cmd_text.append("✗ ", style="red")
                else:
                    cmd_text.append("$ ", style="dim")
                cmd_text.append(entry["cmd"], style="dim")
                lines.append(cmd_text)
            
            if self.current_cmd:
                running = Text()
                running.append(f"{self._spinner()} ", style="cyan bold")
                running.append(self.current_cmd, style="cyan")
                running.append(f" ({self._cmd_elapsed()})", style="yellow")
                lines.append(running)
        
        if not lines:
            lines.append(Text("No commands executed yet...", style="dim italic"))
        
        return Panel(Group(*lines), title=f"[bold magenta]Command Log[/bold magenta] [dim]({total_entries} entries)[/dim]", border_style="magenta", padding=(0, 1))


class LiveStatusLine:
    """
    Simple one-line live status for Agentic Phase (no lag):
    ⏱ 05:32 | 📍 67 endpoints | 🔥 16 vulns | ⚡ 234 cmds | Claude: scanning | Moonshot: thinking
    """
    
    def __init__(self, start_time: float, initial_vulns: int = 0, 
                 initial_endpoints: int = 0, initial_commands: int = 0):
        self.start_time = start_time
        self.vulns = initial_vulns
        self.endpoints = initial_endpoints
        self.commands = initial_commands
        self.claude_status = "idle"
        self.moonshot_status = "idle"
        self._lock = threading.Lock()
    
    def update(self, vulns: int = None, endpoints: int = None, commands: int = None,
               agent: str = None, agent_status: str = None):
        with self._lock:
            if vulns is not None:
                self.vulns = vulns
            if endpoints is not None:
                self.endpoints = endpoints
            if commands is not None:
                self.commands = commands
            if agent == "claude" and agent_status:
                self.claude_status = agent_status
            elif agent == "moonshot" and agent_status:
                self.moonshot_status = agent_status
    
    @property
    def elapsed(self) -> str:
        seconds = int(time.time() - self.start_time)
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"
    
    def _status_color(self, status: str) -> str:
        return {
            "idle": "dim",
            "starting": "yellow",
            "thinking": "cyan",
            "scanning": "green",
            "done": "bold green",
            "error": "bold red"
        }.get(status, "white")
    
    def render(self) -> Text:
        with self._lock:
            line = Text()
            line.append("⏱ ", style="cyan")
            line.append(f"{self.elapsed}", style="bold cyan")
            line.append(" │ ", style="dim")
            line.append("📍 ", style="dim")
            line.append(f"{self.endpoints}", style="bold green")
            line.append(" │ ", style="dim")
            line.append("🔥 ", style="dim")
            line.append(f"{self.vulns}", style="bold red" if self.vulns > 0 else "dim")
            line.append(" │ ", style="dim")
            line.append("⚡ ", style="dim")
            line.append(f"{self.commands}", style="bold yellow")
            line.append(" │ ", style="dim")
            line.append("Claude: ", style="dim")
            line.append(f"{self.claude_status}", style=self._status_color(self.claude_status))
            line.append(" │ ", style="dim")
            line.append("Moonshot: ", style="dim")
            line.append(f"{self.moonshot_status}", style=self._status_color(self.moonshot_status))
            return line