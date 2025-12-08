#!/usr/bin/env python3
"""
Backdoor Protection Demonstration

This script demonstrates how the backdoor protection wrapper blocks backdoor/RCE attacks
by validating plugin URLs before allowing the MCP server to download and execute them.

It shows the same attack scenarios as attack5_backdoor.py, but using a protected
client that has backdoor protection enabled.
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
from defenses.backdoor_protection_wrapper import create_backdoor_protection_wrapper

# Track background processes for cleanup
background_processes = []

# Same attack scenarios as the vulnerable version
BACKDOOR_ATTACK_SCENARIOS = [
    {
        "name": "Backdoor - Cache Optimizer Plugin (Should be blocked)",
        "url": "http://127.0.0.1:8002/plugin/optimizer.py",
        "should_be_blocked": True,
        "reason": "Internal/localhost URL"
    },
    {
        "name": "Backdoor - Cache Helper Plugin (Should be blocked)",
        "url": "http://127.0.0.1:8002/plugin/cache_helper.py",
        "should_be_blocked": True,
        "reason": "Internal/localhost URL"
    },
    {
        "name": "Backdoor - Secrets Exfiltration Plugin (Should be blocked)",
        "url": "http://127.0.0.1:8002/plugin/secrets_exfil.py",
        "should_be_blocked": True,
        "reason": "Internal/localhost URL"
    },
    {
        "name": "Backdoor - Safe External Plugin (Should be allowed if domain whitelisted)",
        "url": "https://trusted-plugin-server.com/plugin/safe_plugin.py",
        "should_be_blocked": True,  # Blocked because not in whitelist
        "reason": "Domain not in whitelist"
    }
]


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
                print(f"[OK] {name} started successfully on port {port}")
                return process
        print(f"[WARNING] {name} may not have started properly")
        return process
    except Exception as e:
        print(f"[ERROR] Failed to start {name}: {e}")
        return None


def cleanup_processes():
    """Clean up all background processes"""
    print("\n[CLEANUP] Stopping background services...")
    for process in background_processes:
        try:
            process.terminate()
            process.wait(timeout=5)
            print(f"[CLEANUP] Stopped process {process.pid}")
        except:
            try:
                process.kill()
            except:
                pass
    background_processes.clear()


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    cleanup_processes()
    sys.exit(0)


async def test_protected_client(attack_scenario, protected_client):
    """Test a backdoor attack against protected client"""
    
    print(f"\n{'='*80}")
    print(f"  Test #{attack_scenario.get('number', '?')}: {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"URL: {attack_scenario['url']}")
    print(f"Expected: {'BLOCKED' if attack_scenario['should_be_blocked'] else 'ALLOWED'}")
    if attack_scenario.get('reason'):
        print(f"Reason: {attack_scenario['reason']}")
    print(f"{'─'*80}\n")
    
    print(f"[TEST] Attempting to install plugin from: {attack_scenario['url']}")
    
    try:
        result = await protected_client.call_tool("install_plugin", {"url": attack_scenario['url']})
        
        # Check if blocked
        if result.get("blocked") or result.get("error") == "BACKDOOR_PROTECTION":
            print(f"\n[RESULT] PROTECTION WORKED - Attack was BLOCKED")
            print(f"[RESULT] {result.get('message', 'Plugin installation blocked by protection')}")
            
            if attack_scenario['should_be_blocked']:
                print("[SUCCESS] Correctly blocked malicious plugin URL")
            else:
                print("[WARNING] Blocked a URL that should have been allowed")
        else:
            print(f"\n[RESULT] PROTECTION FAILED - Attack was ALLOWED")
            print(f"[RESULT] Plugin installation was allowed (should have been blocked)")
            print(json.dumps(result, indent=2))
            
            if attack_scenario['should_be_blocked']:
                print("[ERROR] Failed to block malicious plugin URL")
            else:
                print("[SUCCESS] Correctly allowed safe plugin URL")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()


async def run_protection_demo():
    """Run backdoor protection demonstration"""
    
    # Register signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*80)
    print("  BACKDOOR PROTECTION DEMONSTRATION")
    print("="*80)
    print("\nThis script demonstrates how the backdoor protection wrapper blocks")
    print("backdoor/RCE attacks by validating plugin URLs before allowing the")
    print("MCP server to download and execute them.")
    print("\n[AUTO-START] Checking and starting required services...")
    print("="*80 + "\n")
    
    # Check and start RCE service (port 8002)
    rce_service_started = False
    if not check_service_running(8002):
        print("[INFO] RCE service (port 8002) not running, starting it...")
        process = start_service("RCE Service", "external_service.rce_service", 8002)
        if process:
            background_processes.append(process)
            rce_service_started = True
    else:
        print("[OK] RCE service (port 8002) is already running (will reuse existing)")
    
    # Wait a bit for services to be ready
    if rce_service_started:
        print("[WAIT] Waiting for services to be ready...")
        time.sleep(2)
    
    print("\n[WARNING] Testing backdoor protection - attacks should be BLOCKED!")
    print("="*80 + "\n")
    
    # Number the attacks
    for i, attack in enumerate(BACKDOOR_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Create a single protected client that will be reused for all tests
    # This allows statistics to accumulate across all tests
    print("[INIT] Creating protected MCP client...")
    base_client = MCPClientWrapper()
    await base_client.initialize()
    
    # Wrap with backdoor protection
    # Block internal URLs, require domain whitelist (empty = block all)
    protected_client = create_backdoor_protection_wrapper(
        base_mcp_client=base_client,
        allowed_domains=[],  # Empty whitelist = block all (for strict security)
        blocked_domains=None,
        allow_internal=False,  # Block localhost/internal IPs
        allowed_extensions=['.py'],
        strict_mode=True
    )
    print("[OK] Protected client created\n")
    
    # Run all tests using the same protected client
    print(f"[RUN] Running {len(BACKDOOR_ATTACK_SCENARIOS)} backdoor protection tests...\n")
    
    for attack_scenario in BACKDOOR_ATTACK_SCENARIOS:
        await test_protected_client(attack_scenario, protected_client)
        time.sleep(1)  # Small delay between tests
    
    # Get protection stats from the same client that processed all requests
    stats = protected_client.get_protection_stats()
    blocked_count = stats.get("blocked_count", 0)
    allowed_count = stats.get("allowed_count", 0)
    
    # Cleanup
    await base_client.cleanup()
    
    print("\n" + "="*80)
    print("  BACKDOOR PROTECTION DEMONSTRATION COMPLETE")
    print("="*80)
    print("\nSummary:")
    print("  Protection: Backdoor protection wrapper validates plugin URLs before MCP server downloads them")
    print("  Blocked URLs: Internal/localhost URLs, untrusted domains, suspicious extensions")
    print("  Allowed URLs: Only URLs from whitelisted domains (if whitelist is configured)")
    print(f"\n  Protection Statistics:")
    print(f"    - Plugin installations blocked: {blocked_count}")
    print(f"    - Plugin installations allowed: {allowed_count}")
    print(f"    - Total requests: {blocked_count + allowed_count}")
    print("\n  The wrapper successfully prevents backdoor attacks by blocking:")
    print("    - localhost/127.0.0.1 addresses")
    print("    - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)")
    print("    - Untrusted domains (unless whitelisted)")
    print("    - Suspicious file extensions")
    print("    - Optional: Malicious code patterns in plugin content")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_protection_demo())
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Protection demonstration interrupted by user")
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Protection demonstration failed: {e}")
        import traceback
        traceback.print_exc()
        cleanup_processes()
        sys.exit(1)

