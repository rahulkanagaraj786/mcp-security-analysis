#!/usr/bin/env python3
"""
Cache Poisoning Attack & Defense Demonstration

This demonstrates cache poisoning attacks focused on:
- Session Hijacking: Attacker stores malicious content that tricks users into revealing session tokens
- Data Theft: Attacker stores content that harvests credentials or exfiltrates sensitive data

Attack Flow:
1. User 1 (Attacker) stores malicious content in cache via update_profile or save_note
2. User 2 (Victim) retrieves the poisoned content via get_profile or get_note
3. User 2 sees malicious content and may reveal session tokens, credentials, or send data to attacker

The vulnerable system stores content without validation, allowing cache poisoning.
The protected system validates content before storage and blocks malicious patterns.
"""

import asyncio
import sys
import json
import re
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from llm.ollama_client import OllamaLLM
from llm.tool_definitions import get_tools_for_ollama
from defenses.cache_poisoning_protection_wrapper import create_cache_poisoning_protection_wrapper
from server.storage_manager import storage
import requests


class MCPClientWrapper:
    """Wrapper to make MCP client work with Ollama client"""
    
    def __init__(self, show_cache_ops=False):
        self.session = None
        self.server_params = None
        self.show_cache_ops = show_cache_ops
        
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
                    parsed_result = json.loads(content_text)
                    return parsed_result
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


class ProtectedMCPClientWrapper:
    """Wrapper that shows protection in action"""
    
    def __init__(self, base_client):
        self.base_client = base_client
        from defenses.input_validation.content_sanitizer import create_content_sanitizer
        self.sanitizer = create_content_sanitizer(strict_mode=True, sanitize_output=True)
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call tool with protection"""
        if tool_name in ['update_profile', 'save_note']:
            content = arguments.get('bio', '') or arguments.get('content', '')
            
            if content:
                # Check for session hijacking patterns
                session_patterns = [
                    r'session[_\s]?token', r'session[_\s]?id', r'session[_\s]?key',
                    r'auth[_\s]?token', r'access[_\s]?token'
                ]
                session_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in session_patterns)
                
                # Check for data theft patterns
                data_theft_patterns = [
                    r'password[:\s]+', r'credential[:\s]+', r'api[_\s]?key',
                    r'http[s]?://[^\s]+attacker', r'http[s]?://[^\s]+collect',
                    r'verify@[^\s]+', r'security@[^\s]+', r'send[_\s]?(?:your|the)[_\s]?(?:password|credential)'
                ]
                data_theft_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in data_theft_patterns)
                
                # Check for phishing patterns
                phishing_patterns = [
                    r'security[_\s]?alert', r'account[_\s]?(?:suspension|verification)',
                    r'immediate[_\s]?(?:action|verification)', r'urgent[_\s]?(?:verification|action)'
                ]
                phishing_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in phishing_patterns)
                
                threats = []
                if session_detected:
                    threats.append("Session Hijacking")
                if data_theft_detected:
                    threats.append("Data Theft")
                if phishing_detected:
                    threats.append("Phishing")
                
                if threats:
                    return {
                        "error": "CACHE_POISONING_PROTECTION",
                        "message": f"Blocked: Cache poisoning detected. Threats: {', '.join(threats)}",
                        "tool": tool_name,
                        "blocked": True,
                        "status": "blocked"
                    }
        
        elif tool_name in ['get_profile', 'get_note']:
            result = await self.base_client.call_tool(tool_name, arguments)
            
            if result.get('status') == 'success':
                data = result.get('data', {})
                content = data.get('bio', '') or data.get('content', '')
                
                if content:
                    sanitized = content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    sanitized = sanitized.replace('"', '&quot;').replace("'", '&#x27;')
                    
                    if 'bio' in data:
                        data['bio'] = sanitized
                    if 'content' in data:
                        data['content'] = sanitized
                    result['data'] = data
            
            return result
        
        return await self.base_client.call_tool(tool_name, arguments)
    
    async def cleanup(self):
        """Clean up"""
        await self.base_client.cleanup()


async def create_mcp_client(show_cache_ops=False):
    """Create and initialize MCP client"""
    client = MCPClientWrapper(show_cache_ops=show_cache_ops)
    await client.initialize()
    return client


async def demonstrate_vulnerable_attack():
    """Demonstrate cache poisoning with two users"""
    print("\n" + "="*70)
    print("VULNERABLE SYSTEM - Cache Poisoning Attack")
    print("="*70)
    
    storage.clear_cache()
    
    # User 1 (Attacker) stores malicious content
    print("\n[User 1 - Attacker]")
    print("Query: Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com")
    
    mcp_client1 = await create_mcp_client(show_cache_ops=False)
    ollama_llm1 = OllamaLLM(mcp_client1, model="llama3.1")
    tools = get_tools_for_ollama()
    
    attack_query = "Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"
    result1 = await ollama_llm1.process_query(attack_query, tools)
    
    if result1.get("type") == "tool_use":
        for tool_call in result1['tool_calls']:
            if tool_call.get('success'):
                cache_key = tool_call.get('result', {}).get('cache_key', '')
                if cache_key:
                    cached_data = storage.get_cache(cache_key)
                    if cached_data:
                        print(f"\nCache stored: {cache_key}")
                        print(f"Content: {cached_data.get('bio', '')}")
                        print("Status: Content stored without validation")
    
    await mcp_client1.cleanup()
    
    # User 2 (Victim) retrieves the poisoned content
    print("\n" + "-"*70)
    print("[User 2 - Victim]")
    print("Query: Get my profile for user_id 1")
    
    mcp_client2 = await create_mcp_client(show_cache_ops=False)
    ollama_llm2 = OllamaLLM(mcp_client2, model="llama3.1")
    
    retrieve_query = "Get my profile for user_id 1"
    result2 = await ollama_llm2.process_query(retrieve_query, tools)
    
    if result2.get("type") == "tool_use":
        for tool_call in result2['tool_calls']:
            if tool_call.get('success'):
                retrieved_data = tool_call.get('result', {}).get('data', {})
                retrieved_content = retrieved_data.get('bio', '')
                if retrieved_content:
                    print(f"\nRetrieved from cache:")
                    print(f"Content: {retrieved_content}")
                    print("Status: Content returned without sanitization")
                    print("\nImpact: User 2 sees malicious content and may:")
                    print("  - Reveal their session token")
                    print("  - Send password to attacker")
                    print("  - Fall victim to phishing")
    
    await mcp_client2.cleanup()


async def demonstrate_protected_attack():
    """Demonstrate protection against cache poisoning"""
    print("\n" + "="*70)
    print("PROTECTED SYSTEM - Cache Poisoning Defense")
    print("="*70)
    
    storage.clear_cache()
    
    # User 1 (Attacker) tries to store malicious content
    print("\n[User 1 - Attacker]")
    print("Query: Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com")
    
    base_client1 = await create_mcp_client(show_cache_ops=False)
    protected_client1 = ProtectedMCPClientWrapper(base_client1)
    ollama_llm1 = OllamaLLM(protected_client1, model="llama3.1")
    tools = get_tools_for_ollama()
    
    attack_query = "Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"
    result1 = await ollama_llm1.process_query(attack_query, tools)
    
    if result1.get("type") == "tool_use":
        for tool_call in result1['tool_calls']:
            result_data = tool_call.get('result', {})
            if result_data.get('error') == 'CACHE_POISONING_PROTECTION':
                print(f"\nValidation: Malicious patterns detected")
                print(f"Action: Content blocked, not stored in cache")
                
                # Verify cache is not poisoned
                cache_key = f"user_profile_1"
                cached_data = storage.get_cache(cache_key)
                if cached_data is None:
                    print(f"Cache status: Key '{cache_key}' does not exist")
    
    await protected_client1.cleanup()
    
    # User 2 (Victim) tries to retrieve - nothing in cache
    print("\n" + "-"*70)
    print("[User 2 - Victim]")
    print("Query: Get my profile for user_id 1")
    
    base_client2 = await create_mcp_client(show_cache_ops=False)
    protected_client2 = ProtectedMCPClientWrapper(base_client2)
    ollama_llm2 = OllamaLLM(protected_client2, model="llama3.1")
    
    retrieve_query = "Get my profile for user_id 1"
    result2 = await ollama_llm2.process_query(retrieve_query, tools)
    
    if result2.get("type") == "tool_use":
        for tool_call in result2['tool_calls']:
            result_data = tool_call.get('result', {})
            if result_data.get('status') == 'not_found':
                print(f"\nRetrieved from cache: Not found")
                print("Status: No malicious content in cache")
                print("\nResult: User 2 protected - cache was not poisoned")
    
    await protected_client2.cleanup()


async def main():
    """Main demonstration function"""
    print("\nCache Poisoning Attack & Defense Demonstration")
    print("="*70)
    
    # Check Ollama
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code != 200:
            raise Exception("Ollama not responding")
    except Exception as e:
        print(f"Error: Ollama is not running ({e})")
        print("Please start Ollama first: ollama serve")
        return
    
    # Run demonstrations
    await demonstrate_vulnerable_attack()
    await demonstrate_protected_attack()
    
    print("\n" + "="*70)
    print("Demonstration complete")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...\n")
