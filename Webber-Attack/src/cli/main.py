"""
Webber-Attack CLI
Main entry point
"""

import click
import asyncio
import json
import time
from datetime import timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from dotenv import load_dotenv

load_dotenv()

console = Console()

# OWASP Top 10 2025
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

BANNER = """
██╗    ██╗███████╗██████╗ ██████╗ ███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝██████╔╝███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
        ███████╗████████╗████████╗ █████╗  ██████╗██╗  ██╗
        ██╔══██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
        ███████║   ██║      ██║   ███████║██║     █████╔╝ 
        ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
        ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
        ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                    [ Autonomous Web Security Scanner ]
                              [ v1.0.0 ]
"""


def run_async(coro):
    """Helper to run async functions"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def format_duration(seconds: float) -> str:
    """Format seconds into human readable duration"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {mins}m {secs}s"


def format_duration_verbose(seconds: float) -> str:
    """Format seconds into verbose duration string"""
    td = timedelta(seconds=int(seconds))
    parts = []
    
    hours, remainder = divmod(td.seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    
    if td.days > 0:
        parts.append(f"{td.days} day{'s' if td.days > 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours > 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes > 1 else ''}")
    if secs > 0 or not parts:
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")
    
    return ", ".join(parts)


class ScanTimer:
    """Timer class to track scan duration"""
    
    def __init__(self):
        self.start_time: float = 0
        self.end_time: float = 0
        self.phase_times: dict = {}
        self._current_phase: str = ""
        self._phase_start: float = 0
    
    def start(self):
        """Start the timer"""
        self.start_time = time.time()
        self.phase_times = {}
    
    def stop(self):
        """Stop the timer"""
        self.end_time = time.time()
        if self._current_phase:
            self.end_phase()
    
    def start_phase(self, phase_name: str):
        """Start timing a phase"""
        if self._current_phase:
            self.end_phase()
        self._current_phase = phase_name
        self._phase_start = time.time()
    
    def end_phase(self):
        """End timing current phase"""
        if self._current_phase:
            elapsed = time.time() - self._phase_start
            self.phase_times[self._current_phase] = elapsed
            self._current_phase = ""
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def elapsed_str(self) -> str:
        """Get formatted elapsed time"""
        return format_duration(self.elapsed)
    
    def get_phase_time(self, phase: str) -> float:
        """Get time for a specific phase"""
        return self.phase_times.get(phase, 0)
    
    def get_phase_str(self, phase: str) -> str:
        """Get formatted time for a specific phase"""
        return format_duration(self.get_phase_time(phase))


@click.group()
@click.version_option(version="1.0.0", prog_name="webber-attack")
def cli():
    """Webber-Attack: Autonomous Web Security Scanner"""
    pass


@cli.command()
@click.argument("target")
@click.option("--stealth", is_flag=True, help="Enable stealth mode")
@click.option("--scope", type=click.Path(exists=True), help="Scope file")
@click.option("--cookie", type=str, help="Session cookie")
@click.option("--auth", type=str, help="Basic auth (user:pass)")
@click.option("--resume", is_flag=True, help="Resume scan")
@click.option("--repo", type=str, help="GitHub repo URL")
@click.option("--quick", is_flag=True, help="Quick scan")
@click.option("--thorough", is_flag=True, help="Thorough deep scan")
def scan(target, stealth, scope, cookie, auth, resume, repo, quick, thorough):
    """
    Scan target for vulnerabilities.
    
    Examples:
      webber-attack scan http://target.com
      webber-attack scan http://target.com --quick
      webber-attack scan http://target.com --thorough
    """
    console.print(BANNER, style="bold red")
    console.print(Panel(f"[bold green]Target:[/bold green] {target}", title="Scan Configuration"))
    
    # Display options
    options = []
    if stealth:
        options.append("[yellow]Stealth Mode[/yellow]: Enabled")
    if scope:
        options.append(f"[yellow]Scope File[/yellow]: {scope}")
    if cookie:
        options.append("[yellow]Cookie Auth[/yellow]: Provided")
    if auth:
        options.append("[yellow]Basic Auth[/yellow]: Provided")
    if resume:
        options.append("[yellow]Resume[/yellow]: Enabled")
    if repo:
        options.append(f"[yellow]GitHub Repo[/yellow]: {repo}")
    if quick:
        options.append("[yellow]Mode[/yellow]: Quick")
    elif thorough:
        options.append("[yellow]Mode[/yellow]: Thorough (Deep Scan)")
    else:
        options.append("[yellow]Mode[/yellow]: Normal")
    
    for opt in options:
        console.print(f"  • {opt}")
    
    console.print()
    
    try:
        run_async(_run_scan(target, stealth, scope, cookie, auth, resume, repo, quick, thorough))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        import traceback
        traceback.print_exc()


async def _run_scan(target, stealth, scope, cookie, auth, resume, repo, quick, thorough):
    """Async scan implementation"""
    from src.agents.orchestrator import Orchestrator
    from src.db.database import Database
    
    # Initialize timer
    timer = ScanTimer()
    timer.start()
    
    orch = Orchestrator()
    await orch.initialize()
    
    db = Database()
    db.connect()
    
    # Store config
    flags = json.dumps({
        "stealth": stealth,
        "scope": scope,
        "cookie": cookie is not None,
        "auth": auth is not None,
        "resume": resume,
        "repo": repo,
        "quick": quick,
        "thorough": thorough
    })
    
    # Create scan record
    scan_id = db.insert(
        "INSERT INTO scans (target, status, flags) VALUES (%s, %s, %s)",
        (target, "running", flags)
    )
    console.print(f"[green]Scan ID:[/green] {scan_id}\n")
    
    # Load scope
    if scope:
        with open(scope, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    db.insert(
                        "INSERT INTO scope_config (scan_id, domain) VALUES (%s, %s)",
                        (scan_id, domain)
                    )
        console.print(f"[green]Scope loaded from {scope}[/green]\n")
    
    try:
        # Run scan with timer tracking
        console.print(f"[dim]Timer started at {time.strftime('%H:%M:%S')}[/dim]\n")
        
        results = await orch.run_scan(target, scan_id, quick=quick, thorough=thorough)
        
        # Stop timer
        timer.stop()
        
        # Add timing info to results
        results['scan_duration'] = timer.elapsed
        results['scan_duration_str'] = timer.elapsed_str
        
        # Display results
        display_scan_results(results, scan_id)
        
        # Update status with duration
        db.update(
            "UPDATE scans SET status = %s, end_time = NOW() WHERE id = %s",
            ("completed", scan_id)
        )
        
        # Summary with timing
        mode_str = "Quick" if quick else ("Thorough" if thorough else "Normal")
        console.print(Panel(
            f"[bold green]Scan complete![/bold green]\n\n"
            f"Scan ID: {scan_id}\n"
            f"Target: {target}\n"
            f"Mode: {mode_str}\n"
            f"Raw findings: {results.get('raw_count', 0)}\n"
            f"Unique vulnerabilities: {results.get('total', 0)}\n"
            f"Endpoints discovered: {results.get('endpoints_discovered', 0)}\n\n"
            f"[bold cyan]⏱  Duration: {timer.elapsed_str}[/bold cyan]\n"
            f"[dim]   ({format_duration_verbose(timer.elapsed)})[/dim]\n\n"
            f"Next steps:\n"
            f"  • [cyan]webber-attack show {scan_id}[/cyan] - View details\n"
            f"  • [cyan]webber-attack exploit --scan-id {scan_id}[/cyan] - Deep exploitation\n"
            f"  • [cyan]webber-attack patch --scan-id {scan_id}[/cyan] - Generate patches\n"
            f"  • [cyan]webber-attack export --scan-id {scan_id} --format pdf[/cyan] - Export report",
            title="Summary"
        ))
        
    except Exception as e:
        timer.stop()
        db.update(
            "UPDATE scans SET status = %s, end_time = NOW() WHERE id = %s",
            ("failed", scan_id)
        )
        console.print(f"\n[red]Scan failed after {timer.elapsed_str}[/red]")
        raise e
    finally:
        db.close()
        await orch.shutdown()


def display_scan_results(aggregated: dict, scan_id: int):
    """Display results"""
    
    vulns = aggregated.get("vulnerabilities", [])
    duration_str = aggregated.get('scan_duration_str', 'N/A')
    
    if not vulns:
        console.print(f"[yellow]No vulnerabilities found.[/yellow] [dim](scan took {duration_str})[/dim]")
        return
    
    # Vulnerability table
    table = Table(
        title=f"Vulnerabilities Found (Scan #{scan_id}) [dim]• {duration_str}[/dim]", 
        show_header=True, 
        header_style="bold magenta"
    )
    table.add_column("OWASP", style="cyan", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=35)
    table.add_column("Endpoint", width=22)
    table.add_column("Confidence", width=12)
    table.add_column("Found By", width=12)
    
    for vuln in vulns:
        severity = vuln.get("severity", "unknown").lower()
        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }
        severity_style = severity_colors.get(severity, "white")
        
        # FIXED:
        validation = vuln.get("validation", {})
        confidence = validation.get("confidence", 0)

        # Convert float to percentage
        conf_pct = int(confidence * 100) if isinstance(confidence, float) else int(confidence)

        if conf_pct >= 95:
            conf_style = f"[bold green]{conf_pct}%[/bold green]"
        elif conf_pct >= 80:
            conf_style = f"[green]{conf_pct}%[/green]"
        elif conf_pct >= 60:
            conf_style = f"[yellow]{conf_pct}%[/yellow]"
        else:
            conf_style = f"[dim]{conf_pct}%[/dim]"
        
        agents = vuln.get("found_by", [])
        if len(agents) == 2:
            agent_str = "Both"
        elif isinstance(agents, list) and agents:
            agent_str = agents[0].replace("_scanner", "")
        else:
            agent_str = str(agents)
        
        table.add_row(
            vuln.get("owasp", "-"),
            f"[{severity_style}]{severity.upper()}[/{severity_style}]",
            vuln.get("title", "Unknown")[:33],
            vuln.get("endpoint", "-")[:20],
            conf_style,
            agent_str[:10]
        )
    
    console.print(table)
    
    # OWASP coverage
    console.print()
    owasp_table = Table(title="OWASP Top 10 2025 Coverage", show_header=True, header_style="bold blue")
    owasp_table.add_column("Category", width=6)
    owasp_table.add_column("Name", width=40)
    owasp_table.add_column("Vulns", width=8)
    
    owasp_counts = aggregated.get("by_owasp", {})
    
    for cat_id, cat_name in OWASP_2025.items():
        count = owasp_counts.get(cat_id, 0)
        count_str = f"[green]{count}[/green]" if count > 0 else "[dim]0[/dim]"
        owasp_table.add_row(cat_id, cat_name, count_str)
    
    console.print(owasp_table)
    
    # Agent contributions
    console.print()
    agent_table = Table(title="Agent Contributions", show_header=True, header_style="bold cyan")
    agent_table.add_column("Agent", width=20)
    agent_table.add_column("Raw Findings", width=15)
    
    for agent, count in aggregated.get("by_agent", {}).items():
        agent_table.add_row(agent, str(count))
    
    agent_table.add_row("[bold]Total (raw)[/bold]", f"[bold]{aggregated.get('raw_count', 0)}[/bold]")
    agent_table.add_row("[bold]Unique (deduped)[/bold]", f"[bold]{aggregated.get('total', 0)}[/bold]")
    
    console.print(agent_table)
    
    # Timing summary
    console.print()
    console.print(f"[dim]Total scan time: {duration_str}[/dim]")


@cli.command()
@click.option("--scan-id", type=int, help="Scan ID to exploit")
def exploit(scan_id):
    """Deep exploitation of found vulnerabilities."""
    console.print(BANNER, style="bold red")
    console.print(f"[cyan]Exploit phase for scan ID: {scan_id or 'latest'}[/cyan]")
    console.print("\n[yellow]Exploit phase not yet implemented.[/yellow]")


@cli.command()
@click.option("--scan-id", type=int, help="Scan ID to patch")
def patch(scan_id):
    """Generate patches for vulnerabilities."""
    console.print(BANNER, style="bold red")
    console.print(f"[cyan]Generating patches for scan ID: {scan_id or 'latest'}[/cyan]")
    console.print("\n[yellow]Patch generation not yet implemented.[/yellow]")


@cli.command()
@click.option("--approve", is_flag=True, required=True, help="Confirm deployment")
@click.option("--scan-id", type=int, help="Scan ID to deploy")
def deploy(approve, scan_id):
    """Deploy patches."""
    console.print(BANNER, style="bold red")
    console.print(f"[cyan]Deploying patches for scan ID: {scan_id or 'latest'}[/cyan]")
    console.print("\n[yellow]Deployment not yet implemented.[/yellow]")


@cli.command(name="export")
@click.option("--format", "fmt", type=click.Choice(["pdf", "json", "csv", "html"]), default="pdf")
@click.option("--scan-id", type=int, help="Scan ID to export")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def export_report(fmt, scan_id, output):
    """Export scan report."""
    console.print(BANNER, style="bold red")
    console.print(f"[cyan]Exporting {fmt.upper()} report for scan ID: {scan_id or 'latest'}[/cyan]")
    console.print("\n[yellow]Export not yet implemented.[/yellow]")


@cli.command()
def status():
    """Check system status."""
    console.print(BANNER, style="bold red")
    console.print(Panel("[bold]System Status[/bold]", title="Webber-Attack"))
    
    # MySQL
    try:
        from src.db.database import Database
        db = Database()
        db.connect()
        result = db.fetch_one("SELECT COUNT(*) as count FROM scans")
        console.print(f"  • [green]MySQL:[/green] Connected ✓ ({result['count']} scans)")
        db.close()
    except Exception as e:
        console.print(f"  • [red]MySQL:[/red] Failed ✗ ({e})")
    
    # OpenRouter
    try:
        from src.agents.openrouter import OpenRouterClient
        client = OpenRouterClient()
        console.print("  • [green]OpenRouter:[/green] Configured ✓")
        console.print(f"    - Scanner 1: {client.models['scanner_1']}")
        console.print(f"    - Scanner 2: {client.models['scanner_2']}")
    except Exception as e:
        console.print(f"  • [red]OpenRouter:[/red] Failed ✗ ({e})")
    
    # MCP
    try:
        from src.mcp.servers.recon import ReconServer
        server = ReconServer()
        run_async(server.initialize())
        tools = server.get_available_tools()
        console.print(f"  • [green]Recon Tools:[/green] {len(tools)} available")
    except Exception as e:
        console.print(f"  • [red]Recon Tools:[/red] Failed ✗ ({e})")


@cli.command()
def scans():
    """List all scans."""
    console.print(BANNER, style="bold red")
    
    try:
        from src.db.database import Database
        db = Database()
        db.connect()
        
        results = db.fetch_all(
            """SELECT s.id, s.target, s.status, s.start_time, s.end_time,
                      (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = s.id) as vuln_count,
                      TIMESTAMPDIFF(SECOND, s.start_time, COALESCE(s.end_time, NOW())) as duration
               FROM scans s ORDER BY s.id DESC LIMIT 15"""
        )
        
        if not results:
            console.print("[yellow]No scans found.[/yellow]")
            return
        
        table = Table(title="Recent Scans", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=6)
        table.add_column("Target", width=30)
        table.add_column("Status", width=12)
        table.add_column("Vulns", width=8)
        table.add_column("Duration", width=10)
        table.add_column("Started", width=18)
        
        for row in results:
            status_style = {
                "running": "[yellow]running[/yellow]",
                "completed": "[green]completed[/green]",
                "failed": "[red]failed[/red]"
            }.get(row['status'], row['status'])
            
            # Format duration
            duration = row.get('duration', 0) or 0
            duration_str = format_duration(duration) if duration else "-"
            
            table.add_row(
                str(row['id']),
                row['target'][:28],
                status_style,
                str(row['vuln_count']),
                duration_str,
                str(row['start_time'])[:16] if row['start_time'] else "-"
            )
        
        console.print(table)
        db.close()
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@cli.command()
@click.argument("scan_id", type=int)
def show(scan_id):
    """Show scan details."""
    console.print(BANNER, style="bold red")
    
    try:
        from src.db.database import Database
        db = Database()
        db.connect()
        
        scan = db.fetch_one(
            """SELECT *, 
                      TIMESTAMPDIFF(SECOND, start_time, COALESCE(end_time, NOW())) as duration
               FROM scans WHERE id = %s""", 
            (scan_id,)
        )
        if not scan:
            console.print(f"[red]Scan #{scan_id} not found.[/red]")
            return
        
        duration = scan.get('duration', 0) or 0
        duration_str = format_duration(duration) if duration else "N/A"
        
        console.print(Panel(
            f"[bold]Target:[/bold] {scan['target']}\n"
            f"[bold]Status:[/bold] {scan['status']}\n"
            f"[bold]Started:[/bold] {scan['start_time']}\n"
            f"[bold]Ended:[/bold] {scan['end_time'] or 'N/A'}\n"
            f"[bold]Duration:[/bold] {duration_str}",
            title=f"Scan #{scan_id}"
        ))
        
        vulns = db.fetch_all(
            """SELECT * FROM vulnerabilities WHERE scan_id = %s 
               ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low', 'info')""",
            (scan_id,)
        )
        
        if vulns:
            table = Table(title="Vulnerabilities", show_header=True, header_style="bold magenta")
            table.add_column("OWASP", width=6)
            table.add_column("Severity", width=10)
            table.add_column("Title", width=40)
            table.add_column("Endpoint", width=30)
            
            for vuln in vulns:
                severity = vuln.get("severity", "unknown").lower()
                severity_colors = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim"
                }
                severity_style = severity_colors.get(severity, "white")
                
                table.add_row(
                    vuln['owasp_category'],
                    f"[{severity_style}]{severity.upper()}[/{severity_style}]",
                    vuln['title'][:38],
                    vuln['endpoint'][:28] if vuln['endpoint'] else "-"
                )
            
            console.print(table)
            console.print(f"\n[bold]Total: {len(vulns)} vulnerabilities[/bold] [dim]• Scan duration: {duration_str}[/dim]")
        else:
            console.print("[yellow]No vulnerabilities found.[/yellow]")
        
        db.close()
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


def main():
    cli()


if __name__ == "__main__":
    main()