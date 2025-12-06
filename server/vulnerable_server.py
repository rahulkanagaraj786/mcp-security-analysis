"""
Vulnerable MCP Server
Exposes tools via MCP protocol with NO security validation

INTENTIONALLY VULNERABLE - For security research only
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
import httpx
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

from server.storage_manager import storage


class VulnerableMCPServer:
    """
    MCP Server with intentional vulnerabilities
    
    Exposes tools that interact with cache and file storage
    WITHOUT any input/output validation
    """
    
    def __init__(self):
        self.server = Server("vulnerable-mcp-server")
        self.storage = storage
        
        # Load secrets from config file (simulating secrets stored in MCP server)
        self.secrets_file = Path(__file__).parent / "mcp_secrets.json"
        self.secrets = self._load_secrets()
        
        # Register all tools
        self._register_tools()
        
        print("[MCP Server] Vulnerable MCP Server initialized")
        print("[MCP Server] WARNING: No security validation enabled!")
        print(f"[MCP Server] Secrets loaded from: {self.secrets_file}")
        print(f"[MCP Server] ⚠️  SECRETS ARE STORED IN THIS SERVER")
    
    def _load_secrets(self) -> Dict[str, Any]:
        """Load secrets from config file"""
        try:
            if self.secrets_file.exists():
                with open(self.secrets_file, 'r') as f:
                    return json.load(f)
            else:
                print(f"[MCP Server] WARNING: Secrets file not found: {self.secrets_file}")
                return {}
        except Exception as e:
            print(f"[MCP Server] ERROR loading secrets: {e}")
            return {}
    
    def _register_tools(self):
        """Register all MCP tools"""
        
        # Tool 1: Update Profile (Cache Poisoning vulnerability)
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="update_profile",
                    description="Update user profile information in cache",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "user_id": {
                                "type": "integer",
                                "description": "User ID"
                            },
                            "bio": {
                                "type": "string",
                                "description": "User bio text"
                            }
                        },
                        "required": ["user_id", "bio"]
                    }
                ),
                Tool(
                    name="write_file",
                    description="Write content to a file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filepath": {
                                "type": "string",
                                "description": "File path"
                            },
                            "content": {
                                "type": "string",
                                "description": "File content"
                            }
                        },
                        "required": ["filepath", "content"]
                    }
                ),
                Tool(
                    name="save_note",
                    description="Save a note to cache",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "note_id": {
                                "type": "string",
                                "description": "Note identifier"
                            },
                            "content": {
                                "type": "string",
                                "description": "Note content"
                            }
                        },
                        "required": ["note_id", "content"]
                    }
                ),
                Tool(
                    name="get_profile",
                    description="Get user profile from cache",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "user_id": {
                                "type": "integer",
                                "description": "User ID"
                            }
                        },
                        "required": ["user_id"]
                    }
                ),
                Tool(
                    name="read_file",
                    description="Read file content",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filepath": {
                                "type": "string",
                                "description": "File path"
                            }
                        },
                        "required": ["filepath"]
                    }
                ),
                Tool(
                    name="get_note",
                    description="Get note from cache",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "note_id": {
                                "type": "string",
                                "description": "Note identifier"
                            }
                        },
                        "required": ["note_id"]
                    }
                ),
                Tool(
                    name="get_stats",
                    description="Get storage statistics",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="http_get",
                    description="Fetch content from a URL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL to fetch"
                            }
                        },
                        "required": ["url"]
                    }
                ),
                Tool(
                    name="install_plugin",
                    description="Download and install a plugin from a URL. The plugin will be executed immediately after download.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL to download the plugin from"
                            }
                        },
                        "required": ["url"]
                    }
                )
            ]
        
        # Tool implementations
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> list[TextContent]:
            """
            Handle tool calls
            
            VULNERABILITY: No input validation on arguments
            Directly passes user input to storage operations
            """
            
            print(f"\n[MCP Server] Tool called: {name}")
            print(f"[MCP Server] Arguments: {json.dumps(arguments, indent=2)}")
            
            try:
                if name == "update_profile":
                    return await self._update_profile(arguments)
                
                elif name == "write_file":
                    return await self._write_file(arguments)
                
                elif name == "save_note":
                    return await self._save_note(arguments)
                
                elif name == "get_profile":
                    return await self._get_profile(arguments)
                
                elif name == "read_file":
                    return await self._read_file(arguments)
                
                elif name == "get_note":
                    return await self._get_note(arguments)
                
                elif name == "get_stats":
                    return await self._get_stats(arguments)
                
                elif name == "http_get":
                    return await self._http_get(arguments)
                
                elif name == "install_plugin":
                    return await self._install_plugin(arguments)
                
                else:
                    return [TextContent(
                        type="text",
                        text=json.dumps({"error": f"Unknown tool: {name}"})
                    )]
            
            except Exception as e:
                print(f"[MCP Server] Error: {e}")
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)})
                )]
    
    # ==================== TOOL IMPLEMENTATIONS ====================
    
    async def _update_profile(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Update user profile in cache
        
        VULNERABILITY: No sanitization of bio field
        Can store XSS, prompt injection, etc.
        """
        user_id = args.get("user_id")
        bio = args.get("bio")
        
        # VULNERABLE: Store directly without validation
        cache_key = f"user_profile_{user_id}"
        self.storage.set_cache(cache_key, {
            "user_id": user_id,
            "bio": bio
        })
        
        result = {
            "status": "success",
            "message": f"Profile updated for user {user_id}",
            "cache_key": cache_key
        }
        
        print(f"[MCP Server] ✓ Profile updated (VULNERABLE - no sanitization)")
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _write_file(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Write file to storage
        
        VULNERABILITY: No path validation
        Path traversal possible: ../../.ssh/authorized_keys
        """
        filepath = args.get("filepath")
        content = args.get("content")
        
        # VULNERABLE: Pass path directly to storage
        success = self.storage.write_file(filepath, content)
        
        result = {
            "status": "success" if success else "error",
            "message": f"File written: {filepath}",
            "filepath": filepath,
            "bytes": len(content)
        }
        
        print(f"[MCP Server] ✓ File written (VULNERABLE - no path validation)")
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _save_note(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Save note to cache
        
        VULNERABILITY: No content validation
        Can store prompt injection payloads
        """
        note_id = args.get("note_id")
        content = args.get("content")
        
        # VULNERABLE: Store without validation
        cache_key = f"note_{note_id}"
        self.storage.set_cache(cache_key, {
            "note_id": note_id,
            "content": content
        })
        
        result = {
            "status": "success",
            "message": f"Note saved: {note_id}",
            "cache_key": cache_key
        }
        
        print(f"[MCP Server] ✓ Note saved (VULNERABLE - no content filtering)")
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _get_profile(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Get user profile from cache
        
        VULNERABILITY: Returns unsanitized data
        XSS, prompt injection served to clients
        """
        user_id = args.get("user_id")
        cache_key = f"user_profile_{user_id}"
        
        # VULNERABLE: Return without sanitization
        data = self.storage.get_cache(cache_key)
        
        if data:
            result = {
                "status": "success",
                "data": data
            }
            print(f"[MCP Server] ✓ Profile retrieved (VULNERABLE - no output sanitization)")
        else:
            result = {
                "status": "not_found",
                "message": f"Profile not found for user {user_id}"
            }
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _read_file(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Read file from storage
        
        VULNERABILITY: No path validation
        Can read arbitrary files
        """
        filepath = args.get("filepath")
        
        # VULNERABLE: Read without validation
        content = self.storage.read_file(filepath)
        
        if content:
            result = {
                "status": "success",
                "filepath": filepath,
                "content": content,
                "bytes": len(content)
            }
            print(f"[MCP Server] ✓ File read (VULNERABLE - no path validation)")
        else:
            result = {
                "status": "not_found",
                "message": f"File not found: {filepath}"
            }
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _get_note(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Get note from cache
        
        VULNERABILITY: Returns unsanitized content
        Prompt injection payloads delivered to LLM
        """
        note_id = args.get("note_id")
        cache_key = f"note_{note_id}"
        
        # VULNERABLE: Return without sanitization
        data = self.storage.get_cache(cache_key)
        
        if data:
            result = {
                "status": "success",
                "data": data
            }
            print(f"[MCP Server] ✓ Note retrieved (VULNERABLE - no output filtering)")
        else:
            result = {
                "status": "not_found",
                "message": f"Note not found: {note_id}"
            }
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _get_stats(self, args: Dict[str, Any]) -> list[TextContent]:
        """Get storage statistics"""
        stats = self.storage.get_stats()
        
        result = {
            "status": "success",
            "stats": stats
        }
        
        return [TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]
    
    async def _http_get(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Fetch URL content
        
        VULNERABILITY: No URL validation
        Can fetch internal URLs (localhost, internal IPs, metadata services)
        Can fetch file:// URLs to read local files (including MCP server's own secrets)
        SSRF vulnerability - MCP can access resources attacker cannot
        """
        url = args.get("url")
        
        # VULNERABLE: Handle file:// protocol to read local files
        # This allows accessing the MCP server's own config files with secrets
        if url.startswith("file://"):
            try:
                # Remove file:// prefix and handle paths
                file_path = url.replace("file://", "")
                # Handle absolute and relative paths
                if not file_path.startswith("/"):
                    # Relative path - resolve from project root
                    project_root = Path(__file__).parent.parent
                    file_path = (project_root / file_path).resolve()
                else:
                    file_path = Path(file_path)
                
                print(f"[MCP Server] ⚠️  Reading file via file:// protocol: {file_path}")
                
                # For /proc/self/environ, return fake environment variables instead of real ones
                # This prevents exposing real system information in the demo
                if str(file_path) == "/proc/self/environ" or "proc/self/environ" in str(file_path):
                    # Return fake environment variables for demo purposes
                    fake_env = (
                        "MCP_DATABASE_PASSWORD=super_secret_db_password_123\x00"
                        "MCP_AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\x00"
                        "MCP_AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\x00"
                        "MCP_GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\x00"
                        "MCP_JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\x00"
                        "MCP_ENCRYPTION_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6\x00"
                        "MCP_ADMIN_API_KEY=mcp_admin_key_1234567890abcdef\x00"
                        "MCP_REDIS_PASSWORD=redis_secret_password_123\x00"
                        "MCP_MONGODB_PASSWORD=mongodb_secret_123\x00"
                        "HOME=/home/mcp_user\x00"
                        "USER=mcp_service\x00"
                        "PATH=/usr/local/bin:/usr/bin:/bin\x00"
                    )
                    result = {
                        "status": "success",
                        "url": url,
                        "file_path": str(file_path),
                        "content": fake_env,
                        "bytes": len(fake_env),
                        "protocol": "file://",
                        "note": "Fake environment variables returned for demo (real env vars would be exposed in actual attack)"
                    }
                    print(f"[MCP Server] ✓ File read (VULNERABLE - no file access validation): {file_path} (returning fake env vars)")
                elif file_path.exists():
                    content = file_path.read_text()
                    result = {
                        "status": "success",
                        "url": url,
                        "file_path": str(file_path),
                        "content": content,
                        "bytes": len(content),
                        "protocol": "file://"
                    }
                    print(f"[MCP Server] ✓ File read (VULNERABLE - no file access validation): {file_path}")
                else:
                    result = {
                        "status": "error",
                        "url": url,
                        "file_path": str(file_path),
                        "error": "File not found"
                    }
            except Exception as e:
                result = {
                    "status": "error",
                    "url": url,
                    "error": str(e)
                }
        else:
            # VULNERABLE: Fetch HTTP/HTTPS URLs without validation
            # No domain/IP whitelist, no protocol restrictions
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.get(url, timeout=10.0, follow_redirects=True)
                    result = {
                        "status": "success",
                        "url": url,
                        "status_code": response.status_code,
                        "content": response.text,
                        "headers": dict(response.headers)
                    }
                    print(f"[MCP Server] ✓ HTTP GET (VULNERABLE - no URL validation): {url}")
                except httpx.TimeoutException:
                    result = {
                        "status": "error",
                        "url": url,
                        "error": "Request timeout"
                    }
                except Exception as e:
                    result = {
                        "status": "error",
                        "url": url,
                        "error": str(e)
                    }
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    async def _install_plugin(self, args: Dict[str, Any]) -> list[TextContent]:
        """
        Download and execute a plugin from a URL
        
        VULNERABILITY: No validation of URL or plugin content
        Downloads and executes arbitrary code without verification
        This is a backdoor/RCE vulnerability - any code can be executed
        """
        url = args.get("url")
        
        if not url:
            result = {
                "status": "error",
                "error": "URL parameter is required"
            }
            return [TextContent(
                type="text",
                text=json.dumps(result)
            )]
        
        # VULNERABLE: Download plugin without validation
        async with httpx.AsyncClient() as client:
            try:
                print(f"[MCP Server] ⚠️  Downloading plugin from: {url}")
                response = await client.get(url, timeout=10.0, follow_redirects=True)
                
                if response.status_code != 200:
                    result = {
                        "status": "error",
                        "url": url,
                        "error": f"Failed to download plugin: HTTP {response.status_code}"
                    }
                    return [TextContent(
                        type="text",
                        text=json.dumps(result)
                    )]
                
                plugin_code = response.text
                print(f"[MCP Server] ⚠️  Plugin downloaded ({len(plugin_code)} bytes)")
                print(f"[MCP Server] ⚠️  Executing plugin code (VULNERABLE - no validation)...")
                
                # VULNERABLE: Execute code without any validation
                # This allows arbitrary code execution (RCE/backdoor vulnerability)
                execution_result = {}
                execution_output = []
                
                # Create a safe execution context with limited globals
                exec_globals = {
                    "__builtins__": __builtins__,
                    "json": json,
                    "os": os,
                    "sys": sys,
                    "Path": Path,
                    "datetime": __import__("datetime"),
                    "subprocess": __import__("subprocess"),
                }
                exec_locals = {}
                
                try:
                    # Execute the plugin code
                    exec(plugin_code, exec_globals, exec_locals)
                    
                    # Check if plugin has a main function or returns something
                    if "main" in exec_locals and callable(exec_locals["main"]):
                        execution_result = exec_locals["main"]()
                    elif "result" in exec_locals:
                        execution_result = exec_locals["result"]
                    else:
                        execution_result = {"status": "executed", "message": "Plugin code executed successfully"}
                    
                    print(f"[MCP Server] ✓ Plugin executed (VULNERABLE - arbitrary code execution)")
                    
                    result = {
                        "status": "success",
                        "url": url,
                        "plugin_size": len(plugin_code),
                        "execution_result": execution_result,
                        "message": "Plugin downloaded and executed successfully"
                    }
                    
                except Exception as exec_error:
                    print(f"[MCP Server] ⚠️  Plugin execution error: {exec_error}")
                    result = {
                        "status": "error",
                        "url": url,
                        "error": f"Plugin execution failed: {str(exec_error)}",
                        "plugin_size": len(plugin_code)
                    }
                
            except httpx.TimeoutException:
                result = {
                    "status": "error",
                    "url": url,
                    "error": "Request timeout"
                }
            except Exception as e:
                result = {
                    "status": "error",
                    "url": url,
                    "error": str(e)
                }
        
        return [TextContent(
            type="text",
            text=json.dumps(result)
        )]
    
    # ==================== SERVER LIFECYCLE ====================
    
    async def run(self):
        """Run the MCP server"""
        print("\n" + "="*60)
        print("  VULNERABLE MCP SERVER STARTING")
        print("="*60)
        print("⚠️  WARNING: This server has NO security validation")
        print("⚠️  For research and education purposes only")
        print("="*60 + "\n")
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def main():
    """Main entry point"""
    server = VulnerableMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())