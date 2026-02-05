"""
MCP Client Hub
Routes tool calls to appropriate MCP servers
"""

import asyncio
from typing import Dict, Any, Optional
from rich.console import Console

from src.mcp.servers.recon  import ReconServer
from src.mcp.servers.exploit import ExploitServer
# Future imports:
# from src.mcp.servers.package import PackageServer
from src.mcp.servers.payload_factory import PayloadFactoryServer
# from src.mcp.servers.docker_mgr import DockerServer
# from src.mcp.servers.github_mcp import GitHubServer
# from src.mcp.servers.ansible_mcp import AnsibleServer

console = Console()


class MCPClientHub:
    """
    Central hub that manages connections to all MCP servers.
    Routes tool calls based on agent decisions.
    """
    
    def __init__(self):
        self.servers: Dict[str, Any] = {}
        self._initialized = False
    
    async def initialize(self):
        """Initialize all MCP servers"""
        if self._initialized:
            return
        
        console.print("[cyan]Initializing MCP Client Hub...[/cyan]")
        
        # ── Server 1: Reconnaissance ────────────────────────────────────
        self.servers["recon"] = ReconServer()
        await self.servers["recon"].initialize()
        console.print("  • [green]Server 1 (Recon):[/green] Ready ✓")
        
        # ── Server 2: Exploitation ──────────────────────────────────────
        self.servers["exploit"] = ExploitServer()
        await self.servers["exploit"].initialize()
        console.print("  • [green]Server 2 (Exploit):[/green] Ready ✓")
        
        # Future servers (uncomment as implemented):
        # self.servers["package"] = PackageServer()
        # await self.servers["package"].initialize()
        # console.print("  • [green]Server 3 (Package):[/green] Ready ✓")
        
        self.servers["payload_factory"] = PayloadFactoryServer()
        await self.servers["payload_factory"].initialize()
        console.print("  • [green]Server 3 (Payload Factory):[/green] Ready ✓")
        
        # self.servers["docker"] = DockerServer()
        # await self.servers["docker"].initialize()
        # console.print("  • [green]Server 5 (Docker):[/green] Ready ✓")
        
        # self.servers["github"] = GitHubServer()
        # await self.servers["github"].initialize()
        # console.print("  • [green]Server 6 (GitHub):[/green] Ready ✓")
        
        # self.servers["ansible"] = AnsibleServer()
        # await self.servers["ansible"].initialize()
        # console.print("  • [green]Server 7 (Ansible):[/green] Ready ✓")
        
        self._initialized = True
        console.print("[green]MCP Client Hub initialized.[/green]\n")
    
    async def execute(self, server_name: str, tool_name: str, params: Dict[str, Any], agent: str = "unknown") -> Dict[str, Any]:
        """
        Execute a tool on a specific server.
        
        Args:
            server_name: "recon", "exploit", etc.
            tool_name: The specific tool to run
            params: Parameters for the tool
            agent: Which agent is making this request
            
        Returns:
            Dict with success status and result/error
        """
        if not self._initialized:
            await self.initialize()
        
        server = self.servers.get(server_name)
        if not server:
            return {
                "success": False,
                "error": f"Unknown server: {server_name}",
                "agent": agent
            }
        
        try:
            result = await server.execute_tool(tool_name, params)
            return {
                "success": True,
                "server": server_name,
                "tool": tool_name,
                "agent": agent,
                "result": result
            }
        except Exception as e:
            return {
                "success": False,
                "server": server_name,
                "tool": tool_name,
                "agent": agent,
                "error": str(e)
            }
        
    async def get_available_tools(self, server_name: Optional[str] = None) -> Dict[str, list]:
        """
        Get list of available tools from servers.
        
        Args:
            server_name: Optional, specific server to query. If None, returns all.
            
        Returns:
            Dict mapping server names to their available tools
        """
        if not self._initialized:
            await self.initialize()
        
        if server_name:
            server = self.servers.get(server_name)
            if server:
                return {server_name: server.get_tools()}
            return {}
        
        # Return all tools from all servers
        all_tools = {}
        for name, server in self.servers.items():
            all_tools[name] = server.get_tools()
        return all_tools
    
    async def shutdown(self):
        """Shutdown all servers"""
        for name, server in self.servers.items():
            try:
                await server.shutdown()
                console.print(f"  • [yellow]{name}:[/yellow] Shutdown ✓")
            except Exception as e:
                console.print(f"  • [red]{name}:[/red] Shutdown failed: {e}")
        
        self._initialized = False


# Quick test
if __name__ == "__main__":
    async def test():
        hub = MCPClientHub()
        await hub.initialize()
        
        # Get available tools
        tools = await hub.get_available_tools()
        print("\nAvailable tools:")
        for server, tool_list in tools.items():
            print(f"  {server}: {tool_list}")
        
        # Test recon shell
        print("\nTesting nmap on localhost...")
        result = await hub.execute("recon", "shell", {
            "command": "nmap -sV -p 22,80,443 127.0.0.1"
        })
        if result["success"]:
            print(f"✓ Nmap:\n{result['result']['output'][:500]}...")
        else:
            print(f"✗ Error: {result['error']}")
        
        # Test exploit http_attack
        print("\nTesting http_attack on httpbin...")
        result = await hub.execute("exploit", "http_attack", {
            "method": "GET",
            "url": "http://httpbin.org/get",
            "session_id": "test_session"
        })
        if result["success"]:
            print(f"✓ HTTP {result['result']['status_code']} — {result['result']['response_time']}s")
        else:
            print(f"✗ Error: {result['error']}")
        
        await hub.shutdown()
    
    asyncio.run(test())