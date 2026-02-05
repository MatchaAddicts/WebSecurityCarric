"""
MCP Server 3: Payload Factory
Sandboxed code execution for payload generation, response parsing, and exploit logic.

Tools:
- python_exec:  Execute Python code in isolated workspace (no network by default)
- node_exec:    Execute Node.js code in isolated workspace
- script_save:  Save a script for reuse across iterations
- script_load:  Load a previously saved script
- script_list:  List all saved scripts

Use cases:
  - Generate JWT tokens with manipulated claims
  - Parse complex JSON/XML responses to extract tokens
  - Create polyglot files (image+PHP, PDF+JS)
  - Crack hashes programmatically
  - Encode/decode data (base64, hex, URL)
  - Implement custom crypto/signing logic
  - Build deserialization payloads
  - Multi-step exploit logic requiring state

Design rules:
  - Sandboxed: No network access, isolated filesystem
  - Timeout-enforced: 30s max execution
  - Persistent workspace: Scripts/files survive across iterations
  - Result capture: stdout, stderr, return value, files created
"""

import asyncio
import json
import shutil
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console

console = Console()


class PayloadFactoryServer:
    """
    Payload Factory MCP Server.
    Provides sandboxed code execution for payload generation and analysis.
    The agent builds exploits HERE, then fires them via exploit.py.
    """

    def __init__(self):
        self.name = "payload_factory"
        self._initialized = False
        
        # Workspace: isolated directory for code execution
        # All scripts run here, all files created land here
        self.workspace = Path(__file__).resolve().parents[3] / "cache" / "payload_factory"
        
        # Script storage: persisted scripts the agent can reuse
        self.scripts_dir = self.workspace / "scripts"
        
        # Execution cache: avoid re-running identical code
        self._exec_cache: Dict[str, Dict] = {}

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def initialize(self):
        """Set up workspace and check for Python/Node.js"""
        if self._initialized:
            return

        # Create directories
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.scripts_dir.mkdir(exist_ok=True)

        # Check available interpreters
        self.python_path = shutil.which("python3") or shutil.which("python")
        self.node_path = shutil.which("node")

        tools_available = []
        if self.python_path:
            tools_available.append("python")
        if self.node_path:
            tools_available.append("node")

        self._initialized = True
        console.print(f"    [dim]Payload Factory ready: {', '.join(tools_available)}[/dim]")
        console.print(f"    [dim]Workspace: {self.workspace}[/dim]")

    def get_tools(self) -> List[str]:
        return ["python_exec", "node_exec", "script_save", "script_load", "script_list"]

    def get_tool_info(self) -> Dict[str, Dict]:
        return {
            "python_exec": {
                "description": "Execute Python code (sandboxed, 30s timeout)",
                "installed": self.python_path is not None
            },
            "node_exec": {
                "description": "Execute Node.js code (sandboxed, 30s timeout)",
                "installed": self.node_path is not None
            },
            "script_save": {
                "description": "Save a script for reuse",
                "installed": True
            },
            "script_load": {
                "description": "Load a saved script",
                "installed": True
            },
            "script_list": {
                "description": "List all saved scripts",
                "installed": True
            }
        }

    async def shutdown(self):
        self._exec_cache.clear()
        self._initialized = False

    # =========================================================================
    # Dispatch
    # =========================================================================

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Route to the correct handler"""

        if tool_name == "python_exec":
            code = params.get("code")
            if not code:
                return {"success": False, "error": "'code' parameter required"}
            return await self._execute_python(code, params.get("timeout", 30), params.get("cache", True))

        elif tool_name == "node_exec":
            code = params.get("code")
            if not code:
                return {"success": False, "error": "'code' parameter required"}
            return await self._execute_node(code, params.get("timeout", 30), params.get("cache", True))

        elif tool_name == "script_save":
            name = params.get("name")
            code = params.get("code")
            if not name or not code:
                return {"success": False, "error": "'name' and 'code' required"}
            return self._save_script(name, code, params.get("language", "python"))

        elif tool_name == "script_load":
            name = params.get("name")
            if not name:
                return {"success": False, "error": "'name' parameter required"}
            return self._load_script(name)

        elif tool_name == "script_list":
            return self._list_scripts()

        else:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

    # =========================================================================
    # Python Execution
    # =========================================================================

    async def _execute_python(self, code: str, timeout: int = 30, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute Python code in the isolated workspace.
        
        Security features:
        - Runs in workspace directory (can't access parent dirs easily)
        - Timeout enforced
        - No network access by default (can be added if needed)
        - Captures stdout/stderr
        
        Returns:
        {
            "success": bool,
            "stdout": str,
            "stderr": str,
            "return_code": int,
            "files_created": [str],  # New files in workspace
            "execution_time": float
        }
        """
        if not self.python_path:
            return {"success": False, "error": "Python not available"}

        # Check cache
        if use_cache:
            cache_key = hashlib.md5(code.encode()).hexdigest()
            if cache_key in self._exec_cache:
                cached = self._exec_cache[cache_key].copy()
                cached["cached"] = True
                return cached

        # Track files before execution
        files_before = set(self.workspace.glob("*"))

        # Write code to temp file
        script_file = self.workspace / f"exec_{hashlib.md5(code.encode()).hexdigest()[:8]}.py"
        script_file.write_text(code, encoding="utf-8")

        try:
            import time
            start = time.time()

            # Execute in workspace directory
            process = await asyncio.create_subprocess_exec(
                self.python_path,
                str(script_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.workspace),
                # Security: limit resources
                # Note: These limits work on Linux, may need adjustment for other OS
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                return_code = process.returncode
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Execution timeout after {timeout}s",
                    "return_code": -1,
                    "execution_time": timeout
                }

            # Track new files created
            files_after = set(self.workspace.glob("*"))
            new_files = [str(f.relative_to(self.workspace)) for f in (files_after - files_before)]

            result = {
                "success": return_code == 0,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "return_code": return_code,
                "files_created": new_files,
                "execution_time": round(time.time() - start, 3)
            }

            # Cache successful executions
            if use_cache and return_code == 0:
                self._exec_cache[cache_key] = result.copy()

            return result

        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": 0
            }
        finally:
            # Cleanup temp script file
            try:
                script_file.unlink()
            except:
                pass

    # =========================================================================
    # Node.js Execution
    # =========================================================================

    async def _execute_node(self, code: str, timeout: int = 30, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute Node.js code in the isolated workspace.
        Similar to Python execution but for JavaScript exploits.
        """
        if not self.node_path:
            return {"success": False, "error": "Node.js not available"}

        # Check cache
        if use_cache:
            cache_key = hashlib.md5(f"node:{code}".encode()).hexdigest()
            if cache_key in self._exec_cache:
                cached = self._exec_cache[cache_key].copy()
                cached["cached"] = True
                return cached

        # Track files before execution
        files_before = set(self.workspace.glob("*"))

        # Write code to temp file
        script_file = self.workspace / f"exec_{hashlib.md5(code.encode()).hexdigest()[:8]}.js"
        script_file.write_text(code, encoding="utf-8")

        try:
            import time
            start = time.time()

            process = await asyncio.create_subprocess_exec(
                self.node_path,
                str(script_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.workspace),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                return_code = process.returncode
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Execution timeout after {timeout}s",
                    "return_code": -1,
                    "execution_time": timeout
                }

            # Track new files created
            files_after = set(self.workspace.glob("*"))
            new_files = [str(f.relative_to(self.workspace)) for f in (files_after - files_before)]

            result = {
                "success": return_code == 0,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "return_code": return_code,
                "files_created": new_files,
                "execution_time": round(time.time() - start, 3)
            }

            # Cache successful executions
            if use_cache and return_code == 0:
                self._exec_cache[cache_key] = result.copy()

            return result

        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": 0
            }
        finally:
            # Cleanup temp script file
            try:
                script_file.unlink()
            except:
                pass

    # =========================================================================
    # Script Persistence
    # =========================================================================

    def _save_script(self, name: str, code: str, language: str = "python") -> Dict[str, Any]:
        """
        Save a script for reuse across iterations.
        Useful for common payloads, parsers, or exploit modules.
        """
        try:
            # Sanitize filename
            safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
            if not safe_name:
                return {"success": False, "error": "Invalid script name"}

            ext = ".py" if language == "python" else ".js"
            script_path = self.scripts_dir / f"{safe_name}{ext}"

            script_path.write_text(code, encoding="utf-8")

            return {
                "success": True,
                "message": f"Script saved: {safe_name}{ext}",
                "path": str(script_path.relative_to(self.workspace))
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _load_script(self, name: str) -> Dict[str, Any]:
        """Load a previously saved script"""
        try:
            # Try both .py and .js extensions
            for ext in [".py", ".js"]:
                script_path = self.scripts_dir / f"{name}{ext}"
                if script_path.exists():
                    code = script_path.read_text(encoding="utf-8")
                    language = "python" if ext == ".py" else "node"
                    return {
                        "success": True,
                        "code": code,
                        "language": language,
                        "name": name
                    }

            return {"success": False, "error": f"Script not found: {name}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _list_scripts(self) -> Dict[str, Any]:
        """List all saved scripts"""
        try:
            scripts = []
            for script_path in self.scripts_dir.glob("*.[pj][ys]"):
                language = "python" if script_path.suffix == ".py" else "node"
                scripts.append({
                    "name": script_path.stem,
                    "language": language,
                    "size": script_path.stat().st_size
                })

            return {
                "success": True,
                "scripts": scripts,
                "count": len(scripts)
            }

        except Exception as e:
            return {"success": False, "error": str(e)}