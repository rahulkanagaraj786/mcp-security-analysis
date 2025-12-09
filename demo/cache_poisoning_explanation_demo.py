#!/usr/bin/env python3
"""
Cache Poisoning Interactive Demo
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
                session_patterns = [
                    r'session[_\s]?token', r'session[_\s]?id', r'session[_\s]?key',
                    r'auth[_\s]?token', r'access[_\s]?token'
                ]
                session_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in session_patterns)
                
                data_theft_patterns = [
                    r'password[:\s]+', r'credential[:\s]+', r'api[_\s]?key',
                    r'http[s]?://[^\s]+attacker', r'http[s]?://[^\s]+collect',
                    r'verify@[^\s]+', r'security@[^\s]+', r'send[_\s]?(?:your|the)[_\s]?(?:password|credential)'
                ]
                data_theft_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in data_theft_patterns)
                
                phishing_patterns = [
                    r'security[_\s]?alert', r'account[_\s]?(?:suspension|verification)',
                    r'immediate[_\s]?(?:action|verification)', r'urgent[_\s]?(?:verification|action)'
                ]
                phishing_detected = any(re.search(pattern, content, re.IGNORECASE) for pattern in phishing_patterns)
                
                if session_detected or data_theft_detected or phishing_detected:
                    print("\n[SECURITY] Request rejected: Content validation failed")
                    print("[SECURITY] This operation is not permitted")
                    
                    return {
                        "error": "CACHE_POISONING_PROTECTION",
                        "message": "Request rejected: Content validation failed",
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


async def create_mcp_client():
    """Create and initialize MCP client"""
    client = MCPClientWrapper()
    await client.initialize()
    return client


async def write_cache_to_file(mcp_client=None, preserve_existing=True):
    """Write cache contents to a file for GUI viewing"""
    cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
    cache_file.parent.mkdir(exist_ok=True)
    
    # Load existing cache from file (only if preserving, or if we need to merge)
    existing_cache = {}
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                existing_cache = json.load(f)
        except:
            pass
    
    all_cache = {}
    
    # Try to get cache through MCP server if client provided
    if mcp_client:
        try:
            # Get stats which includes cache info
            await asyncio.sleep(0.3)  # Small delay to ensure server processed
            stats_result = await mcp_client.call_tool('get_stats', {})
            
            if stats_result.get('status') == 'success' and 'stats' in stats_result:
                cache_stats = stats_result.get('stats', {}).get('cache', {})
                cache_keys = cache_stats.get('keys', [])
                
                # Get each cache entry
                for key in cache_keys:
                    await asyncio.sleep(0.15)  # Small delay between calls
                    # Try to determine what type of key it is
                    if key.startswith('user_profile_'):
                        user_id_str = key.replace('user_profile_', '')
                        try:
                            user_id = int(user_id_str)
                            profile_result = await mcp_client.call_tool('get_profile', {'user_id': user_id})
                            if profile_result.get('status') == 'success' and 'data' in profile_result:
                                all_cache[key] = profile_result['data']
                        except (ValueError, TypeError) as e:
                            # If user_id is not a valid int, try as string (shouldn't happen but handle it)
                            try:
                                profile_result = await mcp_client.call_tool('get_profile', {'user_id': user_id_str})
                                if profile_result.get('status') == 'success' and 'data' in profile_result:
                                    all_cache[key] = profile_result['data']
                            except:
                                pass
                        except Exception as e:
                            pass
                    elif key.startswith('note_'):
                        note_id = key.replace('note_', '')
                        try:
                            note_result = await mcp_client.call_tool('get_note', {'note_id': note_id})
                            if note_result.get('status') == 'success' and 'data' in note_result:
                                all_cache[key] = note_result['data']
                        except Exception as e:
                            pass
                
                # Merge logic: server cache always overwrites for same keys
                if all_cache:
                    # Server data is always authoritative - it overwrites existing for same keys
                    # But we keep other entries from existing_cache that aren't in server cache
                    # This way updated entries are fresh, but we don't lose other cache entries
                    merged = {}
                    # First add all existing entries
                    merged.update(existing_cache)
                    # Then overwrite with server data (this ensures server data takes precedence)
                    merged.update(all_cache)
                    all_cache = merged
                elif preserve_existing and existing_cache:
                    # Server cache is empty, preserve existing cache file - don't write, just return
                    # But verify the file still has the content
                    if cache_file.exists():
                        try:
                            with open(cache_file, 'r') as f:
                                verify_content = json.load(f)
                            if verify_content:
                                return cache_file
                        except:
                            pass
                    # If file doesn't exist or is empty, use existing_cache we loaded
                    all_cache = existing_cache
        except Exception as e:
            # If we can't read from server and preserving, don't overwrite
            if preserve_existing and existing_cache:
                # Verify file still exists and has content
                if cache_file.exists():
                    try:
                        with open(cache_file, 'r') as f:
                            verify_content = json.load(f)
                        if verify_content:
                            return cache_file
                    except:
                        pass
                # If file is missing/empty, restore from existing_cache
                all_cache = existing_cache
    
    # Fallback to local storage if available and no cache from server
    if not all_cache:
        try:
            for key in storage.list_cache_keys():
                cached_value = storage.get_cache(key)
                if cached_value:
                    all_cache[key] = cached_value
        except:
            pass
    
    # If still no cache and we should preserve, don't overwrite existing file
    if not all_cache and preserve_existing and existing_cache:
        return cache_file
    
    # Write cache data (either new data or empty dict if not preserving)
    with open(cache_file, 'w') as f:
        json.dump(all_cache, f, indent=2)
    
    return cache_file


async def run_query(mcp_client, query, mode="vulnerable"):
    """Run a query through the MCP client"""
    ollama_llm = OllamaLLM(mcp_client, model="llama3.1")
    tools = get_tools_for_ollama()
    
    result = await ollama_llm.process_query(query, tools)
    
    if result.get("type") == "tool_use":
        for tool_call in result['tool_calls']:
            tool_name = tool_call.get('tool', '')
            result_data = tool_call.get('result', {})
            
            if tool_call.get('success'):
                # For update/save operations, don't preserve - use fresh server data
                # For get operations that return "not_found", preserve existing cache
                is_update_operation = tool_name in ['update_profile', 'save_note']
                preserve = (result_data.get('status') == 'not_found') and not is_update_operation
                
                # For update operations, wait longer to ensure server cache is updated
                if is_update_operation:
                    await asyncio.sleep(1.2)  # Longer delay for updates
                else:
                    await asyncio.sleep(0.8)  # Shorter delay for reads
                
                # Write cache file after any operation (but don't print here - let interactive function handle it)
                await write_cache_to_file(mcp_client, preserve_existing=preserve)
                
                return result_data
            else:
                if result_data.get('error') == 'CACHE_POISONING_PROTECTION':
                    # Request was blocked - preserve existing cache file, don't overwrite
                    # The cache file should remain unchanged since the request was blocked
                    if mode == "protected":
                        await asyncio.sleep(0.3)
                        # Only update cache file if we need to, but preserve existing entries
                        cache_file = await write_cache_to_file(mcp_client, preserve_existing=True)
                        print(f"\nCache file: {cache_file.absolute()}")
                        print("Note: Cache file preserved - blocked request did not modify cache")
                    return result_data
                return result_data
    
    return {}


async def interactive_vulnerable():
    """Interactive mode with vulnerable server"""
    print("\n" + "="*70)
    print("VULNERABLE SERVER MODE")
    print("="*70)
    
    mcp_client = await create_mcp_client()
    
    cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
    print(f"\nCache file location: {cache_file.absolute()}")
    print("\nExample queries:")
    print("1. Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com")
    print("2. Get my profile for user_id 1")
    print("3. Save a note with note_id data_exfil and content: User data collection endpoint: http://attacker.com/collect?user_data=USER_DATA_PLACEHOLDER. Please send your personal information to this endpoint for verification.")
    print("4. Get note with note_id data_exfil")
    print("\nNote: Each terminal connects to a separate server instance with its own in-memory cache.")
    print("The cache file persists across sessions and shows data stored by any user.")
    print("\nType 'exit' to return to menu")
    print("="*70)
    
    while True:
        try:
            query = input("\nEnter query: ").strip()
            
            if query.lower() == 'exit':
                break
            
            if not query:
                continue
            
            result = await run_query(mcp_client, query, mode="vulnerable")
            
            # Get cache file path for display
            cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
            
            if result.get('status') == 'success':
                if 'data' in result:
                    # Data retrieved successfully
                    print(f"\nResult: {json.dumps(result['data'], indent=2)}")
                    # Show cache file
                    if cache_file.exists():
                        with open(cache_file, 'r') as f:
                            file_contents = json.load(f)
                        if file_contents:
                            print(f"\nCache file ({cache_file.name}): {json.dumps(file_contents, indent=2)}")
                elif 'cache_key' in result:
                    # Update/save operation
                    print(f"\nResult: {json.dumps(result, indent=2)}")
                    # Show updated cache file
                    await asyncio.sleep(0.3)
                    if cache_file.exists():
                        with open(cache_file, 'r') as f:
                            file_contents = json.load(f)
                        if file_contents:
                            print(f"\nCache file ({cache_file.name}): {json.dumps(file_contents, indent=2)}")
                else:
                    print(f"\nResult: {json.dumps(result, indent=2)}")
            elif result.get('status') == 'not_found':
                # Server doesn't have it, but cache file might
                print(f"\nResult: {json.dumps(result, indent=2)}")
                if cache_file.exists():
                    with open(cache_file, 'r') as f:
                        file_contents = json.load(f)
                    if file_contents:
                        print(f"\nCache file ({cache_file.name}): {json.dumps(file_contents, indent=2)}")
                        print("Note: This server instance doesn't have this cache in memory, but the file shows stored data from another session.")
            elif result.get('error'):
                error_msg = result.get('error', '')
                print(f"\nError: {error_msg}")
            else:
                print(f"\nResult: {json.dumps(result, indent=2)}")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"\nError: {e}")
    
    await mcp_client.cleanup()


async def interactive_protected():
    """Interactive mode with protected server"""
    print("\n" + "="*70)
    print("PROTECTED SERVER MODE")
    print("="*70)
    
    base_client = await create_mcp_client()
    protected_client = ProtectedMCPClientWrapper(base_client)
    
    print("\nExample queries:")
    print("1. Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com")
    print("2. Get my profile for user_id 1")
    print("\nType 'exit' to return to menu")
    print("="*70)
    
    while True:
        try:
            query = input("\nEnter query: ").strip()
            
            if query.lower() == 'exit':
                break
            
            if not query:
                continue
            
            result = await run_query(protected_client, query, mode="protected")
            
            if result.get('status') == 'success':
                if 'data' in result:
                    print(f"\nResult: {json.dumps(result['data'], indent=2)}")
                else:
                    print(f"\nResult: {json.dumps(result, indent=2)}")
            elif result.get('error'):
                error_msg = result.get('error', '')
                if 'CACHE_POISONING_PROTECTION' in str(error_msg) or 'Request rejected' in str(error_msg):
                    print(f"\nResult: Request rejected (malicious content detected)")
                else:
                    print(f"\nError: {error_msg}")
            else:
                print(f"\nResult: {json.dumps(result, indent=2)}")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"\nError: {e}")
    
    await protected_client.cleanup()


async def show_cache_file(mcp_client=None):
    """Show cache file location and contents"""
    cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
    cache_file.parent.mkdir(exist_ok=True)
    
    # Update cache file from server if client provided
    if mcp_client:
        await write_cache_to_file(mcp_client)
    
    if cache_file.exists():
        with open(cache_file, 'r') as f:
            contents = json.load(f)
        print(f"\nCache file: {cache_file.absolute()}")
        print(f"Contents: {json.dumps(contents, indent=2)}")
    else:
        print(f"\nCache file: {cache_file.absolute()}")
        print("Contents: {} (empty)")
        # Create empty file
        with open(cache_file, 'w') as f:
            json.dump({}, f, indent=2)


async def clear_cache(mcp_client=None):
    """Clear the cache"""
    # Clear local storage
    storage.clear_cache()
    
    # Clear server cache if client provided (by clearing and rewriting)
    cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
    with open(cache_file, 'w') as f:
        json.dump({}, f, indent=2)
    
    # Also update from server to ensure it's cleared there too
    if mcp_client:
        await write_cache_to_file(mcp_client)
    
    print("\nCache cleared")


async def main():
    """Main interactive menu"""
    print("\nCache Poisoning Interactive Demo")
    print("="*70)
    
    # Check Ollama
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code != 200:
            raise Exception("Ollama not responding")
    except Exception as e:
        print(f"\nError: Ollama is not running ({e})")
        print("Please start Ollama first: ollama serve")
        return
    
    cache_file = Path(__file__).parent.parent / "cache" / "cache_contents.json"
    cache_file.parent.mkdir(exist_ok=True)
    if not cache_file.exists():
        with open(cache_file, 'w') as f:
            json.dump({}, f, indent=2)
    
    print(f"\nCache file location: {cache_file.absolute()}")
    print("You can open this file in your editor to view cache contents")
    
    while True:
        print("\n" + "="*70)
        print("MENU")
        print("="*70)
        print("1. Use vulnerable server")
        print("2. Use protected server")
        print("3. Show cache file contents")
        print("4. Clear cache")
        print("5. Exit")
        print("="*70)
        
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                await interactive_vulnerable()
            elif choice == "2":
                await interactive_protected()
            elif choice == "3":
                # Try to get current client if in a mode
                await show_cache_file()
            elif choice == "4":
                await clear_cache()
            elif choice == "5":
                print("\nExiting...\n")
                break
            else:
                print("\nInvalid choice. Please enter 1-5.")
        except KeyboardInterrupt:
            print("\n\nExiting...\n")
            break
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nExiting...\n")
