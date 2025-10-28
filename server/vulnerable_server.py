"""
Vulnerable MCP Server
Exposes tools via MCP protocol with NO security validation

INTENTIONALLY VULNERABLE - For security research only
"""

import asyncio
import json
from typing import Any, Dict, Optional
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
        
        # Register all tools
        self._register_tools()
        
        print("[MCP Server] Vulnerable MCP Server initialized")
        print("[MCP Server] WARNING: No security validation enabled!")
    
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