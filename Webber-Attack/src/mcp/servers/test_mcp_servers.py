#!/usr/bin/env python3
"""
MCP Servers Test Suite
Tests MCP Server 2 (Exploit - Enhanced) and MCP Server 3 (Payload Factory)

Usage:
    python3 test_mcp_servers.py [--payload-factory] [--exploit] [--all]
    
    --payload-factory  : Test only Payload Factory server
    --exploit          : Test only Exploit server
    --all              : Test both servers (default)
"""

import asyncio
import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Add project root to path so we can import the servers
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add(self, name: str, success: bool, details: str = ""):
        self.tests.append({
            "name": name,
            "success": success,
            "details": details
        })
        if success:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        table = Table(title="Test Results Summary")
        table.add_column("Test", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details", style="dim")
        
        for test in self.tests:
            status = "[green]✓ PASS[/green]" if test["success"] else "[red]✗ FAIL[/red]"
            table.add_row(test["name"], status, test["details"][:80])
        
        console.print("\n")
        console.print(table)
        console.print(f"\n[bold]Total: {self.passed + self.failed} tests[/bold]")
        console.print(f"[green]Passed: {self.passed}[/green]")
        console.print(f"[red]Failed: {self.failed}[/red]")
        
        if self.failed == 0:
            console.print("\n[bold green]🎉 All tests passed![/bold green]")
        else:
            console.print(f"\n[bold red]⚠️  {self.failed} test(s) failed[/bold red]")


async def test_payload_factory():
    """Test MCP Server 3: Payload Factory"""
    results = TestResults()
    
    console.print(Panel("[bold cyan]Testing MCP Server 3: Payload Factory[/bold cyan]"))
    
    try:
        # Import the server
        try:
            from payload_factory import PayloadFactoryServer
            results.add("Import PayloadFactoryServer", True, "Module imported successfully")
        except ImportError as e:
            console.print(f"[red]✗ Failed to import PayloadFactoryServer: {e}[/red]")
            console.print("[yellow]Make sure payload_factory.py is in the current directory or src/mcp/servers/[/yellow]")
            results.add("Import PayloadFactoryServer", False, str(e))
            return results
        
        # Initialize server
        console.print("\n[yellow]Initializing server...[/yellow]")
        server = PayloadFactoryServer()
        await server.initialize()
        results.add("Server initialization", True, f"Workspace: {server.workspace}")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 1: Simple Python Execution
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 1: Simple Python execution[/cyan]")
        result = await server.execute_tool("python_exec", {
            "code": "print('Hello from Payload Factory')\nprint(2 + 2)"
        })
        
        if result.get("success") and "Hello from Payload Factory" in result.get("stdout", ""):
            console.print("[green]✓ Python execution works[/green]")
            console.print(f"  Output: {result['stdout'].strip()}")
            results.add("Python execution", True, "Basic Python code executed")
        else:
            console.print(f"[red]✗ Python execution failed: {result.get('stderr', 'Unknown error')}[/red]")
            results.add("Python execution", False, result.get("stderr", "Unknown error"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 2: JWT Generation
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 2: JWT token generation[/cyan]")
        jwt_code = """
try:
    import jwt
    payload = {'user': 'admin', 'role': 'superadmin', 'admin': True}
    token = jwt.encode(payload, 'weak_secret', algorithm='HS256')
    print(f"Generated JWT: {token}")
except ImportError:
    print("JWT library not available - installing...")
    import subprocess
    subprocess.run(['pip3', 'install', '--break-system-packages', 'pyjwt'], capture_output=True)
    import jwt
    payload = {'user': 'admin', 'role': 'superadmin', 'admin': True}
    token = jwt.encode(payload, 'weak_secret', algorithm='HS256')
    print(f"Generated JWT: {token}")
"""
        result = await server.execute_tool("python_exec", {"code": jwt_code, "timeout": 60})
        
        if result.get("success") and "Generated JWT:" in result.get("stdout", ""):
            console.print("[green]✓ JWT generation works[/green]")
            console.print(f"  {result['stdout'].strip()}")
            results.add("JWT generation", True, "JWT token created successfully")
        else:
            console.print(f"[yellow]⚠ JWT generation failed (PyJWT may not be installed)[/yellow]")
            console.print(f"  Error: {result.get('stderr', 'Unknown')[:100]}")
            results.add("JWT generation", False, "PyJWT not available or error")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 3: Hash Cracking
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 3: Hash cracking (MD5)[/cyan]")
        hash_code = """
import hashlib

target_hash = '5f4dcc3b5aa765d61d8327deb882cf99'  # MD5 of "password"
wordlist = ['admin', 'password', '12345', 'letmein', 'qwerty']

for word in wordlist:
    if hashlib.md5(word.encode()).hexdigest() == target_hash:
        print(f'CRACKED: {word}')
        break
else:
    print('Hash not cracked')
"""
        result = await server.execute_tool("python_exec", {"code": hash_code})
        
        if result.get("success") and "CRACKED: password" in result.get("stdout", ""):
            console.print("[green]✓ Hash cracking works[/green]")
            console.print(f"  {result['stdout'].strip()}")
            results.add("Hash cracking", True, "MD5 hash cracked successfully")
        else:
            console.print(f"[red]✗ Hash cracking failed[/red]")
            results.add("Hash cracking", False, result.get("stderr", "Unknown error"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 4: JSON Parsing
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 4: Complex JSON parsing[/cyan]")
        json_code = """
import json
import base64

response = '{"status":"ok","data":{"session":{"tokens":{"access":"YWRtaW46cGFzc3dvcmQ=","refresh":"xyz"}}}}'
data = json.loads(response)
token = data['data']['session']['tokens']['access']
decoded = base64.b64decode(token).decode()
print(f'Extracted and decoded: {decoded}')
"""
        result = await server.execute_tool("python_exec", {"code": json_code})
        
        if result.get("success") and "admin:password" in result.get("stdout", ""):
            console.print("[green]✓ JSON parsing works[/green]")
            console.print(f"  {result['stdout'].strip()}")
            results.add("JSON parsing", True, "Extracted nested token from JSON")
        else:
            console.print(f"[red]✗ JSON parsing failed[/red]")
            results.add("JSON parsing", False, result.get("stderr", "Unknown error"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 5: File Creation
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 5: File creation in workspace[/cyan]")
        file_code = """
with open('test_payload.txt', 'w') as f:
    f.write('This is a test payload')
print('File created: test_payload.txt')

import os
print(f'File exists: {os.path.exists("test_payload.txt")}')
"""
        result = await server.execute_tool("python_exec", {"code": file_code})
        
        if result.get("success") and "test_payload.txt" in result.get("files_created", []):
            console.print("[green]✓ File creation works[/green]")
            console.print(f"  Files created: {result['files_created']}")
            results.add("File creation", True, f"Created: {result['files_created']}")
        else:
            console.print(f"[yellow]⚠ File creation check failed[/yellow]")
            results.add("File creation", False, "File not tracked or error")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 6: Script Save/Load
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 6: Script persistence (save/load)[/cyan]")
        
        # Save a script
        save_result = await server.execute_tool("script_save", {
            "name": "test_script",
            "code": "print('This is a persisted script')\nprint('ID:', 12345)",
            "language": "python"
        })
        
        if save_result.get("success"):
            console.print(f"[green]✓ Script saved: {save_result['message']}[/green]")
            
            # Load it back
            load_result = await server.execute_tool("script_load", {"name": "test_script"})
            
            if load_result.get("success") and "12345" in load_result.get("code", ""):
                console.print(f"[green]✓ Script loaded: {len(load_result['code'])} chars[/green]")
                results.add("Script save/load", True, "Saved and loaded successfully")
            else:
                console.print("[red]✗ Script load failed[/red]")
                results.add("Script save/load", False, "Load failed")
        else:
            console.print(f"[red]✗ Script save failed: {save_result.get('error')}[/red]")
            results.add("Script save/load", False, save_result.get("error", "Unknown"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 7: Script List
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 7: List saved scripts[/cyan]")
        list_result = await server.execute_tool("script_list", {})
        
        if list_result.get("success"):
            console.print(f"[green]✓ Script listing works: {list_result['count']} scripts[/green]")
            for script in list_result.get("scripts", []):
                console.print(f"  - {script['name']} ({script['language']}, {script['size']} bytes)")
            results.add("Script listing", True, f"Found {list_result['count']} scripts")
        else:
            console.print(f"[red]✗ Script listing failed[/red]")
            results.add("Script listing", False, list_result.get("error", "Unknown"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 8: Execution Caching
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[cyan]Test 8: Execution caching[/cyan]")
        code = "import time; print(f'Timestamp: {time.time()}')"
        
        result1 = await server.execute_tool("python_exec", {"code": code, "cache": True})
        result2 = await server.execute_tool("python_exec", {"code": code, "cache": True})
        
        if result1.get("success") and result2.get("cached"):
            console.print("[green]✓ Caching works (second call was cached)[/green]")
            console.print(f"  First: {result1['execution_time']}s")
            console.print(f"  Second: cached (same output)")
            results.add("Execution caching", True, "Cache hit on second call")
        else:
            console.print("[yellow]⚠ Caching may not be working[/yellow]")
            results.add("Execution caching", False, "No cache hit detected")
        
        # Cleanup
        await server.shutdown()
        console.print("\n[dim]Server shutdown complete[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        results.add("Unexpected error", False, str(e))
    
    return results


async def test_exploit_server():
    """Test MCP Server 2: Exploit (Enhanced)"""
    results = TestResults()
    
    console.print(Panel("[bold magenta]Testing MCP Server 2: Exploit (Enhanced)[/bold magenta]"))
    
    try:
        # Import the server
        try:
            from exploit_enhanced import ExploitServer
            results.add("Import ExploitServer", True, "Module imported successfully")
        except ImportError:
            try:
                # Try alternate path
                sys.path.insert(0, str(Path(__file__).parent / "src" / "mcp" / "servers"))
                from exploit import ExploitServer
                results.add("Import ExploitServer", True, "Module imported from src/mcp/servers")
            except ImportError as e:
                console.print(f"[red]✗ Failed to import ExploitServer: {e}[/red]")
                console.print("[yellow]Make sure exploit_enhanced.py is in the current directory or src/mcp/servers/[/yellow]")
                results.add("Import ExploitServer", False, str(e))
                return results
        
        # Initialize server
        console.print("\n[yellow]Initializing server...[/yellow]")
        server = ExploitServer()
        await server.initialize()
        results.add("Server initialization", True, f"Tools available: {len(server.tools)}")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 1: Check Existing Tool
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 1: Check existing tool (curl)[/magenta]")
        result = await server.execute_tool("ensure_tool", {"tool": "curl"})
        
        if result.get("installed") and result.get("action") == "already_installed":
            console.print(f"[green]✓ Tool check works: curl is installed[/green]")
            console.print(f"  Path: {result.get('path')}")
            results.add("Check existing tool", True, f"curl found at {result.get('path')}")
        else:
            console.print(f"[red]✗ Tool check failed: {result.get('message')}[/red]")
            results.add("Check existing tool", False, result.get("message", "Unknown"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 2: Install Missing Tool
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 2: Install missing tool (ffuf)[/magenta]")
        console.print("[dim]Note: This will attempt to install ffuf if not present (requires sudo/root)[/dim]")
        
        result = await server.execute_tool("ensure_tool", {"tool": "ffuf"})
        
        if result.get("installed"):
            action = result.get("action")
            if action == "already_installed":
                console.print(f"[green]✓ ffuf already installed[/green]")
                console.print(f"  Path: {result.get('path')}")
                results.add("Install missing tool", True, "ffuf already present")
            elif action == "installed_now":
                console.print(f"[green]✓ ffuf installed successfully[/green]")
                console.print(f"  Path: {result.get('path')}")
                results.add("Install missing tool", True, "ffuf installed dynamically")
        else:
            console.print(f"[yellow]⚠ Could not install ffuf (may need sudo)[/yellow]")
            console.print(f"  Message: {result.get('message')}")
            results.add("Install missing tool", False, "Installation requires privileges")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 3: Shell Execution
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 3: Shell command execution[/magenta]")
        result = await server.execute_tool("shell", {"command": "echo 'Shell test successful'"})
        
        if result.get("return_code") == 0 and "Shell test successful" in result.get("output", ""):
            console.print("[green]✓ Shell execution works[/green]")
            console.print(f"  Output: {result['output'].strip()}")
            results.add("Shell execution", True, "Command executed successfully")
        else:
            console.print(f"[red]✗ Shell execution failed[/red]")
            results.add("Shell execution", False, result.get("errors", "Unknown error"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 4: HTTP Attack (GET)
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 4: HTTP attack (GET request)[/magenta]")
        result = await server.execute_tool("http_attack", {
            "method": "GET",
            "url": "https://httpbin.org/get"
        })
        
        if result.get("success") and result.get("status_code") == 200:
            console.print(f"[green]✓ HTTP GET works[/green]")
            console.print(f"  Status: {result['status_code']}, Time: {result['response_time']}s")
            results.add("HTTP GET attack", True, f"Status 200, {result['response_time']}s")
        else:
            console.print(f"[yellow]⚠ HTTP GET failed (network issue?)[/yellow]")
            results.add("HTTP GET attack", False, result.get("error", "Unknown"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 5: HTTP Attack (POST with data)
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 5: HTTP attack (POST with data)[/magenta]")
        result = await server.execute_tool("http_attack", {
            "method": "POST",
            "url": "https://httpbin.org/post",
            "data": "test=payload&injection=' OR 1=1--"
        })
        
        if result.get("success") and result.get("status_code") == 200:
            console.print(f"[green]✓ HTTP POST works (payload sent unencoded)[/green]")
            console.print(f"  Status: {result['status_code']}")
            # Verify payload was sent as-is
            body = result.get("body", "")
            if "' OR 1=1--" in body:
                console.print("  [green]✓ Payload preserved (no encoding)[/green]")
                results.add("HTTP POST attack", True, "Payload sent unencoded")
            else:
                console.print("  [yellow]⚠ Payload may have been encoded[/yellow]")
                results.add("HTTP POST attack", False, "Payload encoding detected")
        else:
            console.print(f"[yellow]⚠ HTTP POST failed (network issue?)[/yellow]")
            results.add("HTTP POST attack", False, result.get("error", "Unknown"))
        
        # ═══════════════════════════════════════════════════════════════
        # Test 6: Session Persistence
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 6: Session persistence[/magenta]")
        
        # First request - get cookies
        result1 = await server.execute_tool("http_attack", {
            "method": "GET",
            "url": "https://httpbin.org/cookies/set?session=test123",
            "session_id": "test_session"
        })
        
        # Second request - verify cookies persisted
        result2 = await server.execute_tool("http_attack", {
            "method": "GET",
            "url": "https://httpbin.org/cookies",
            "session_id": "test_session"
        })
        
        if result2.get("success") and "test123" in result2.get("body", ""):
            console.print("[green]✓ Session persistence works[/green]")
            console.print("  Cookies from first request were reused")
            results.add("Session persistence", True, "Cookies persisted across requests")
        else:
            console.print("[yellow]⚠ Session persistence unclear[/yellow]")
            results.add("Session persistence", False, "Cookie not found in second request")
        
        # ═══════════════════════════════════════════════════════════════
        # Test 7: HTTP Batch
        # ═══════════════════════════════════════════════════════════════
        console.print("\n[magenta]Test 7: HTTP batch (parallel requests)[/magenta]")
        result = await server.execute_tool("http_batch", {
            "requests": [
                {"method": "GET", "url": "https://httpbin.org/delay/1"},
                {"method": "GET", "url": "https://httpbin.org/delay/1"},
                {"method": "GET", "url": "https://httpbin.org/delay/1"}
            ]
        })
        
        if result.get("success") and result.get("successful", 0) == 3:
            console.print(f"[green]✓ HTTP batch works[/green]")
            console.print(f"  Sent 3 requests in parallel, all succeeded")
            results.add("HTTP batch attack", True, "3/3 parallel requests succeeded")
        else:
            console.print(f"[yellow]⚠ HTTP batch partial success[/yellow]")
            console.print(f"  Success: {result.get('successful', 0)}/{result.get('total', 0)}")
            results.add("HTTP batch attack", False, f"{result.get('successful', 0)}/{result.get('total', 0)} succeeded")
        
        # Cleanup
        await server.shutdown()
        console.print("\n[dim]Server shutdown complete[/dim]")
        
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())
        results.add("Unexpected error", False, str(e))
    
    return results


async def main():
    parser = argparse.ArgumentParser(description="Test MCP Servers")
    parser.add_argument("--payload-factory", action="store_true", help="Test only Payload Factory")
    parser.add_argument("--exploit", action="store_true", help="Test only Exploit server")
    parser.add_argument("--all", action="store_true", help="Test both servers (default)")
    
    args = parser.parse_args()
    
    # Default to testing all if no specific flag
    if not (args.payload_factory or args.exploit or args.all):
        args.all = True
    
    all_results = TestResults()
    
    console.print(Panel.fit(
        "[bold]MCP Servers Test Suite[/bold]\n"
        "Testing Payload Factory (MCP Server 3) and Enhanced Exploit (MCP Server 2)",
        border_style="cyan"
    ))
    
    # Test Payload Factory
    if args.payload_factory or args.all:
        pf_results = await test_payload_factory()
        for test in pf_results.tests:
            all_results.add(f"[PF] {test['name']}", test['success'], test['details'])
    
    # Test Exploit Server
    if args.exploit or args.all:
        exploit_results = await test_exploit_server()
        for test in exploit_results.tests:
            all_results.add(f"[EX] {test['name']}", test['success'], test['details'])
    
    # Print summary
    all_results.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if all_results.failed == 0 else 1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
        sys.exit(1)