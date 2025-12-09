#!/usr/bin/env python3
"""
Cache Poisoning - Where Does The Attack Happen?

This script clearly demonstrates the TWO PHASES of cache poisoning:
1. Phase 1: THE ATTACK - Where malicious content is stored (poisoning the cache)
2. Phase 2: THE IMPACT - Where the poisoned content affects victims

Run this to see exactly where the attack happens!
"""

import asyncio
import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from llm.ollama_client import OllamaLLM
from llm.tool_definitions import get_tools_for_ollama
import requests


class MCPClientWrapper:
    """Wrapper to make MCP client work with Ollama client"""
    
    def __init__(self):
        self.session = None
        self.server_params = None
        
    async def initialize(self):
        """Initialize connection to MCP server"""
        project_root = Path(__file__).parent.parent
        
        self.server_params = StdioServerParameters(
            command="python",
            args=["-m", "server.vulnerable_server"],
            env=None,
            cwd=str(project_root)
        )
        
        self.stdio_context = stdio_client(self.server_params)
        self.stdio_transport = await self.stdio_context.__aenter__()
        read, write = self.stdio_transport
        
        self.session_context = ClientSession(read, write)
        self.session = await self.session_context.__aenter__()
        await self.session.initialize()
        
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool on the MCP server"""
        if not self.session:
            raise RuntimeError("MCP client not initialized")
            
        try:
            result = await self.session.call_tool(tool_name, arguments)
            if result.content:
                content_text = result.content[0].text if result.content else ""
                try:
                    return json.loads(content_text)
                except json.JSONDecodeError:
                    return {"raw": content_text}
            return {"status": "success"}
        except Exception as e:
            return {"error": str(e)}
    
    async def cleanup(self):
        """Clean up connections"""
        if hasattr(self, 'session_context') and self.session_context:
            await self.session_context.__aexit__(None, None, None)
        if hasattr(self, 'stdio_context') and self.stdio_context:
            await self.stdio_context.__aexit__(None, None, None)


async def create_mcp_client():
    """Create and initialize MCP client"""
    client = MCPClientWrapper()
    await client.initialize()
    return client


async def demonstrate_cache_poisoning():
    """Demonstrate where cache poisoning happens"""
    
    print("\n" + "="*80)
    print("  CACHE POISONING: WHERE DOES THE ATTACK HAPPEN?")
    print("="*80)
    print("\nThis demo shows the TWO PHASES of cache poisoning attacks.\n")
    
    # Check Ollama
    print("[CHECK] Checking Ollama...")
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code != 200:
            raise Exception("Ollama not responding")
    except Exception as e:
        print(f"[ERROR] Ollama is not running! ({e})")
        print("\nPlease start Ollama first:")
        print("  ollama serve")
        return
    
    print("[OK] Ollama is running\n")
    
    # Initialize MCP client
    print("[CONNECT] Connecting to MCP server...")
    try:
        mcp_client = await create_mcp_client()
        print("[OK] Connected to MCP server\n")
    except Exception as e:
        print(f"[ERROR] Failed to connect to MCP server: {e}")
        return
    
    # Create Ollama LLM client
    try:
        ollama_llm = OllamaLLM(mcp_client, model="llama3.1")
        tools = get_tools_for_ollama()
        print(f"[OK] Ollama client ready\n")
    except Exception as e:
        print(f"[ERROR] Failed to create Ollama client: {e}")
        await mcp_client.cleanup()
        return
    
    # ========================================================================
    # PHASE 1: THE ATTACK (Storage Phase)
    # ========================================================================
    print("\n" + "="*80)
    print("  PHASE 1: THE ATTACK - WHERE POISONING HAPPENS")
    print("="*80)
    print("\n📍 Location: update_profile() or save_note() tool calls")
    print("📍 File: server/vulnerable_server.py (lines 262-296, 325-353)")
    print("\nIn this phase, the attacker stores malicious content in the cache.")
    print("The server stores it WITHOUT VALIDATION - this is where the attack happens!\n")
    
    malicious_bio = "Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"
    
    print(f"[ATTACKER] Sending malicious content to store...")
    print(f"  Content: {malicious_bio}\n")
    
    attack_query = f"Update my profile with user_id 1 and bio: {malicious_bio}"
    
    print(f"[QUERY] {attack_query}\n")
    print("[PROCESSING] LLM processing query and calling update_profile()...\n")
    
    result = await ollama_llm.process_query(attack_query, tools)
    
    if result.get("type") == "tool_use":
        for tool_call in result['tool_calls']:
            if tool_call.get('tool') == 'update_profile' and tool_call.get('success'):
                print("✅ [PHASE 1 COMPLETE] Attack successful!")
                print(f"   Tool: {tool_call['tool']}")
                print(f"   Status: {tool_call.get('result', {}).get('status', 'unknown')}")
                print(f"   Cache Key: {tool_call.get('result', {}).get('cache_key', 'unknown')}")
                print("\n   ⚠️  THE CACHE IS NOW POISONED!")
                print("   The malicious content is stored in the server's cache.")
                print("   This content will be served to ANY user who retrieves it.\n")
    
    await asyncio.sleep(1)
    
    # Show what's in the cache
    print("[CACHE STATE] Checking what's stored in cache...")
    cache_file = project_root / "cache" / "cache_contents.json"
    if cache_file.exists():
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        print(f"\n📁 Cache file: {cache_file}")
        print(f"📄 Contents:\n{json.dumps(cache_data, indent=2)}\n")
        print("⚠️  Notice: The malicious content is stored as-is, without any sanitization!")
    
    # ========================================================================
    # PHASE 2: THE IMPACT (Retrieval Phase)
    # ========================================================================
    print("\n" + "="*80)
    print("  PHASE 2: THE IMPACT - WHERE VICTIMS ARE AFFECTED")
    print("="*80)
    print("\n📍 Location: get_profile() or get_note() tool calls")
    print("📍 File: server/vulnerable_server.py (lines 355-389, 422-450)")
    print("\nIn this phase, a victim retrieves the poisoned content.")
    print("The server returns it WITHOUT SANITIZATION - this is where the impact happens!\n")
    
    print("[VICTIM] Retrieving profile (simulating a victim user)...")
    print("  Query: Get my profile for user_id 1\n")
    
    retrieval_query = "Get my profile for user_id 1"
    print(f"[QUERY] {retrieval_query}\n")
    print("[PROCESSING] LLM processing query and calling get_profile()...\n")
    
    result = await ollama_llm.process_query(retrieval_query, tools)
    
    if result.get("type") == "tool_use":
        for tool_call in result['tool_calls']:
            if tool_call.get('tool') == 'get_profile' and tool_call.get('success'):
                result_data = tool_call.get('result', {})
                if 'data' in result_data:
                    retrieved_bio = result_data['data'].get('bio', '')
                    print("✅ [PHASE 2 COMPLETE] Victim retrieved poisoned content!")
                    print(f"   Tool: {tool_call['tool']}")
                    print(f"   Status: {result_data.get('status', 'unknown')}")
                    print(f"\n   📨 Retrieved Content:")
                    print(f"   {retrieved_bio}\n")
                    print("   ⚠️  THE POISONED CONTENT WAS SERVED UNSANITIZED!")
                    print("   This malicious content could now:")
                    print("   - Trick the user into revealing their password")
                    print("   - Steal session tokens")
                    print("   - Execute XSS if rendered in a browser")
                    print("   - Inject prompts into an LLM\n")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    print("\n" + "="*80)
    print("  SUMMARY: WHERE THE ATTACK HAPPENS")
    print("="*80)
    print("""
The cache poisoning attack happens in TWO PHASES:

┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: THE ATTACK (Storage)                               │
│ ─────────────────────────────────────────────────────────── │
│ Location: update_profile() / save_note()                    │
│ File: server/vulnerable_server.py:262-296, 325-353         │
│                                                              │
│ What happens:                                                │
│ 1. Attacker sends malicious content                         │
│ 2. Server stores it in cache WITHOUT VALIDATION            │
│ 3. Cache is now POISONED                                    │
│                                                              │
│ ⚠️  THIS IS WHERE THE ATTACK HAPPENS                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ PHASE 2: THE IMPACT (Retrieval)                             │
│ ─────────────────────────────────────────────────────────── │
│ Location: get_profile() / get_note()                        │
│ File: server/vulnerable_server.py:355-389, 422-450         │
│                                                              │
│ What happens:                                                │
│ 1. Victim retrieves cached content                          │
│ 2. Server returns it WITHOUT SANITIZATION                  │
│ 3. Victim processes the malicious content                   │
│                                                              │
│ 💥 THIS IS WHERE THE IMPACT HAPPENS                         │
└─────────────────────────────────────────────────────────────┘

Key Points:
• The attack happens in Phase 1 (storage)
• The impact happens in Phase 2 (retrieval)
• The cache is a SHARED resource - one poisoned entry affects many users
• The vulnerability: No validation on storage OR retrieval
""")
    
    print("="*80 + "\n")
    
    # Cleanup
    print("[CLEANUP] Cleaning up...")
    await mcp_client.cleanup()
    print("[OK] Done\n")


if __name__ == "__main__":
    try:
        asyncio.run(demonstrate_cache_poisoning())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...\n")
