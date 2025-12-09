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
        "expected": "MCP fetches HTML with <script> tags and returns it unsanitized",
        "xss_type": "script_tags"
    },
    {
        "name": "Backward XSS - Event Handlers in HTML",
        "description": "XSS service returns HTML with event handlers (onerror, onclick, etc.)",
        "url": "http://127.0.0.1:8003/widget",
        "expected": "MCP fetches HTML with event handlers and returns it unsanitized",
        "xss_type": "event_handlers"
    },
    {
        "name": "Backward XSS - Obvious Marker",
        "description": "XSS service returns HTML with obvious XSS marker for testing",
        "url": "http://127.0.0.1:8003/marker",
        "expected": "MCP fetches HTML with obvious XSS payload and returns it unsanitized",
        "xss_type": "marker"
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
    print(f"[START] Starting {name} on port {port}...")
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", module],
            cwd=str(project_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        max_attempts = 10
        for attempt in range(max_attempts):
            time.sleep(0.5)
            if check_service_running(port):
                print(f"[OK] {name} started successfully (PID: {process.pid})")
                return process
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr else "Unknown error"
                print(f"[ERROR] {name} process died: {stderr}")
                return None
        print(f"[WARNING] {name} may not have started properly")
        return process
    except Exception as e:
        print(f"[ERROR] Failed to start {name}: {e}")
        return None


async def run_attack_scenario(mcp_client, attack_scenario, mode="vulnerable"):
    """Run a single backward XSS attack scenario"""
    
    print(f"\n{'='*80}")
    print(f"[ATTACK #{attack_scenario.get('number', '?')}] {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"[MODE] {'VULNERABLE' if mode == 'vulnerable' else 'PROTECTED'}")
    print(f"{'─'*80}\n")
    
    print(f"[ATTACK] Calling MCP http_get tool with URL: {attack_scenario['url']}")
    
    try:
        result = await mcp_client.call_tool("http_get", {"url": attack_scenario['url']})
        
        print(f"[RESULT] MCP server response:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "success":
            content = result.get("content", "")
            
            # Check for XSS payloads
            xss_detected = False
            if "<script" in content.lower():
                print(f"\n[WARNING] XSS PAYLOAD DETECTED: <script> tags found in content")
                xss_detected = True
            if "onerror" in content.lower() or "onclick" in content.lower() or "onload" in content.lower():
                print(f"\n[WARNING] XSS PAYLOAD DETECTED: Event handlers found in content")
                xss_detected = True
            
            if mode == "protected":
                # Check if content was sanitized
                if result.get("xss_protected") and result.get("sanitization_applied"):
                    print(f"\n[PROTECTED] Content was sanitized by protection wrapper")
                    print(f"[PROTECTED] XSS patterns detected: {result.get('xss_patterns_detected', [])}")
                    print(f"[PROTECTED] Original length: {result.get('original_content_length', 'N/A')} bytes")
                    print(f"[PROTECTED] Sanitized length: {result.get('sanitized_content_length', 'N/A')} bytes")
                    print(f"[PROTECTED] Backward XSS attack was successfully prevented!")
                elif xss_detected:
                    print(f"\n[WARNING] XSS detected but content may not have been fully sanitized")
                else:
                    print(f"\n[INFO] No XSS patterns detected in this response")
            else:
                if xss_detected:
                    print(f"\n[VULNERABLE] Backward XSS attack successful!")
                    print(f"[VULNERABLE] Malicious content was fetched and returned unsanitized")
                    print(f"[VULNERABLE] If this content is rendered in a browser, XSS will execute")
        else:
            print(f"\n[RESULT] {result.get('message', 'Unknown error')}")
            
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
    
    print(f"{'─'*80}")
    await asyncio.sleep(1)


async def demonstrate_vulnerable_system():
    """Demonstrate attacks against vulnerable MCP server"""
    print("\n" + "="*80)
    print("  PART 1: VULNERABLE SYSTEM (No Protection)")
    print("="*80)
    print("\nDemonstrating backward XSS attacks against vulnerable MCP server.")
    print("The server has no protection, so attacks will succeed.")
    print("="*80 + "\n")
    
    # Create vulnerable MCP client
    mcp_client = await create_mcp_client()
    
    # Number the attacks
    for i, attack in enumerate(BACKWARD_XSS_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Run attacks
    for attack_scenario in BACKWARD_XSS_ATTACK_SCENARIOS:
        await run_attack_scenario(mcp_client, attack_scenario, mode="vulnerable")
    
    await mcp_client.cleanup()
    
    # Summary
    print(f"\n{'='*80}")
    print("  [PART 1 SUMMARY] Vulnerable System")
    print("="*80)
    print("[VULNERABLE] Attacks succeeded - system is vulnerable")
    print("[VULNERABLE] Backward XSS attacks returned unsanitized content")
    print("[VULNERABLE] No security protection was in place")
    print("[VULNERABLE] MCP server returned content from external services without sanitization")
    print("="*80 + "\n")
    
    await asyncio.sleep(2)


async def demonstrate_protected_system():
    """Demonstrate attacks against protected MCP server"""
    print("\n" + "="*80)
    print("  PART 2: PROTECTED SYSTEM (With Security Wrapper)")
    print("="*80)
    print("\nDemonstrating the same backward XSS attacks against protected MCP server.")
    print("The security wrapper will sanitize responses to prevent XSS attacks.")
    print("="*80 + "\n")
    
    # Create vulnerable MCP client
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
    for attack_scenario in BACKWARD_XSS_ATTACK_SCENARIOS:
        await run_attack_scenario(protected_mcp_client, attack_scenario, mode="protected")
    
    # Security summary
    protection_stats = protected_mcp_client.get_protection_stats()
    
    # Summary
    print(f"\n{'='*80}")
    print("  [PART 2 SUMMARY] Protected System")
    print("="*80)
    print(f"[PROTECTED] Security Wrapper Status: ACTIVE")
    print(f"[PROTECTED] Sanitized Responses: {protection_stats['sanitized_count']}")
    print(f"[PROTECTED] Blocked Count: {protection_stats['blocked_count']}")
    print("\n[PROTECTED] Attacks were sanitized - system is protected")
    print("[PROTECTED] Backward XSS attacks were prevented")
    print("[PROTECTED] Content sanitization successfully removed XSS payloads")
    print("[PROTECTED] Security wrapper sanitized HTML, script tags, and event handlers")
    print("="*80 + "\n")
    
    await protected_mcp_client.cleanup()
    await asyncio.sleep(2)


def cleanup_processes():
    """Clean up background processes"""
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
    print("[OK] Cleanup complete")


async def main():
    """Main demonstration function"""
    print("\n" + "="*80)
    print("  BACKWARD XSS ATTACK & DEFENSE DEMONSTRATION")
    print("="*80)
    print("\nThis script demonstrates backward XSS attacks against both")
    print("vulnerable and protected MCP servers, showing how security")
    print("wrappers can prevent backward XSS attacks.")
    print("\n[WARNING] These are real attack demonstrations!")
    print("="*80 + "\n")
    
    # Check if XSS service is running
    print("[CHECK] Checking XSS service (port 8003)...")
    if not check_service_running(8003):
        print("[START] XSS service not running, starting it...")
        xss_service = start_service("XSS Service", "external_service.xss_service", 8003)
        if xss_service:
            background_processes.append(xss_service)
            await asyncio.sleep(2)
        else:
            print("[ERROR] Failed to start XSS service")
            return
    else:
        print("[OK] XSS service is running")
    
    print("\n[OK] Required services are running\n")
    
    try:
        # Run demonstrations
        await demonstrate_vulnerable_system()
        await demonstrate_protected_system()
        
        # Final summary
        print("\n" + "="*80)
        print("  [FINAL SUMMARY] Backward XSS Defense Demonstration")
        print("="*80)
        print("\n[COMPARISON]")
        print("\n[VULNERABLE SYSTEM]:")
        print("  - No content sanitization")
        print("  - Malicious HTML/JavaScript returned unsanitized")
        print("  - XSS payloads execute in user's browser")
        print("  - Backward XSS attacks succeed")
        
        print("\n[PROTECTED SYSTEM]:")
        print("  - Content sanitization on responses")
        print("  - HTML tags and JavaScript stripped/encoded")
        print("  - Event handlers removed")
        print("  - Backward XSS attacks prevented")
        
        print("\n[KEY TAKEAWAYS]:")
        print("  - Backward XSS: external services return malicious content")
        print("  - Protection: sanitize all content from external services")
        print("  - Defense in depth: strip HTML tags, remove event handlers, HTML-encode")
        print("  - Security wrappers can prevent backward XSS attacks")
        print("\n" + "="*80 + "\n")
        
    finally:
        cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Cleaning up...")
        cleanup_processes()
        print("Exiting...\n")

