"""
MCP Server 1: Reconnaissance
Raw shell execution with output normalization for MariaDB backend
"""

import asyncio
import subprocess
import shutil
import re
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console

console = Console()


class ReconServer:
    """
    Recon MCP Server - Raw shell with normalization and MariaDB compatibility
    """
    
    def __init__(self):
        self.name = "recon"
        self._initialized = False
        self.command_cache = {}  # In-memory cache for session
        # All -o / > output files land here instead of polluting project root
        self.cache_dir = Path(__file__).resolve().parents[3] / "cache"
        
    async def initialize(self):
        if self._initialized:
            return
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(exist_ok=True)
        self.available_tools = {}
        tools = ["nmap", "masscan", "subfinder", "assetfinder", "amass", "dig", 
                "gobuster", "ffuf", "dirb", "whatweb", "wafw00f", "curl", "wget", 
                "host", "nslookup", "nikto", "sqlmap", "python3", "bash", "nc", "wget"]
        
        for tool in tools:
            if shutil.which(tool):
                self.available_tools[tool] = True
                
        self._initialized = True
        console.print(f"[green]Recon Server ready with {len(self.available_tools)} tools[/green]")
    
    def get_available_tools(self) -> List[str]:
        return list(self.available_tools.keys())
    
    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command with caching and normalization"""
        if not self._initialized:
            await self.initialize()
        
        if tool_name != "shell":
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}. Use 'shell'.",
                "output": ""
            }
        
        command = params.get("command")
        timeout = params.get("timeout", 300)
        use_cache = params.get("cache", True)
        normalize = params.get("normalize", True)
        
        if not command:
            return {
                "success": False,
                "error": "No command provided",
                "output": "",
                "normalized": False
            }
        
        # Check cache
        if use_cache:
            cmd_hash = hashlib.md5(f"{command}{normalize}".encode()).hexdigest()
            if cmd_hash in self.command_cache:
                return self.command_cache[cmd_hash]
        
        # Execute
        result = await self._execute_raw(command, timeout)
        
        # Normalize output for consistency
        if normalize and result["success"]:
            result["output"] = self._normalize_output(result["output"])
            result["normalized"] = True
        
        # Cache result
        if use_cache and result["success"]:
            self.command_cache[cmd_hash] = result.copy()
        
        return result
    
    async def _execute_raw(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute raw shell command"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cache_dir,
                limit=5*1024*1024  # 5MB limit
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode("utf-8", errors="replace"),
                "errors": stderr.decode("utf-8", errors="replace"),
                "return_code": process.returncode,
                "command": command,
                "timestamp": time.time()
            }
            
        except asyncio.TimeoutError:
            try:
                process.kill()
                await process.wait()
            except:
                pass
            return {
                "success": False,
                "output": "",
                "errors": f"Timeout after {timeout}s",
                "return_code": -1,
                "command": command,
                "timestamp": time.time()
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "errors": str(e),
                "return_code": -1,
                "command": command,
                "timestamp": time.time()
            }
    
    def _normalize_output(self, output: str) -> str:
        """Normalize output to ensure consistency across runs"""
        if not output:
            return output
            
        output = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?', '[TIMESTAMP]', output)
        output = re.sub(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', output)
        output = re.sub(r'PHPSESSID=[a-zA-Z0-9]+', 'PHPSESSID=[SESSION]', output, flags=re.IGNORECASE)
        output = re.sub(r'JSESSIONID=[a-zA-Z0-9]+', 'JSESSIONID=[SESSION]', output, flags=re.IGNORECASE)
        output = re.sub(r'\d+\.\d+\s*seconds', '[TIME]s', output)
        output = re.sub(r'time=\d+\.?\d*', 'time=[TIME]', output)
        output = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP]', output)
        output = re.sub(r'ETag:\s*"[^"]*"', 'ETag: "[TAG]"', output, flags=re.IGNORECASE)
        output = output.replace('\r\n', '\n')
        
        return output
    
    def clear_cache(self):
        """Clear command cache"""
        self.command_cache.clear()
    
    async def shutdown(self):
        self._initialized = False
        self.command_cache.clear()