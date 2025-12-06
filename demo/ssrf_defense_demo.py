#!/usr/bin/env python3
"""
SSRF Protection Demonstration

This script demonstrates how the SSRF protection wrapper blocks SSRF attacks
by validating URLs before allowing the MCP server to fetch them.

It shows the same attack scenarios as attack4_ssrf.py, but using the
protected relay service that has SSRF protection enabled.
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

# Track background processes for cleanup
background_processes = []

# Same attack scenarios as the vulnerable version
SSRF_ATTACK_SCENARIOS = [
    {
        "name": "SSRF - Internal Admin Config (Scenario 1)",
        "url": "http://127.0.0.1:8080/admin/config",
        "scenario": 1,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - Internal API Keys (Scenario 1)",
        "url": "http://127.0.0.1:8080/internal/keys",
        "scenario": 1,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - Instance Metadata (Scenario 1)",
        "url": "http://127.0.0.1:8080/metadata/instance",
        "scenario": 1,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - MCP Server Secrets File (Scenario 2)",
        "url": "file:///cis_project/mcp_security_project/server/mcp_secrets.json",
        "scenario": 2,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - MCP Server Secrets (Relative Path) (Scenario 2)",
        "url": "file://./server/mcp_secrets.json",
        "scenario": 2,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - Environment Variables (Scenario 2)",
        "url": "file:///proc/self/environ",
        "scenario": 2,
        "should_be_blocked": True
    },
    {
        "name": "SSRF - Safe External URL (Should be allowed)",
        "url": "https://www.example.com",
        "scenario": 0,
        "should_be_blocked": False
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


async def test_protected_relay(attack_scenario):
    """Test SSRF attack against protected relay service"""
    
    scenario_num = attack_scenario.get('scenario', '?')
    should_block = attack_scenario.get('should_be_blocked', True)
    
    print(f"\n{'='*80}")
    print(f"  Test: {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"Scenario: {scenario_num} - {'Secrets in separate internal service' if scenario_num == 1 else 'Secrets in MCP server itself' if scenario_num == 2 else 'Safe external URL'}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {'BLOCKED by SSRF protection' if should_block else 'ALLOWED (safe external URL)'}")
    print(f"{'─'*80}\n")
    
    relay_url = f"http://127.0.0.1:8005/fetch?url={attack_scenario['url']}"
    print(f"[TEST] Sending request to protected relay service: {relay_url}")
    
    try:
        response = requests.get(relay_url, timeout=30)
        result = response.json()
        
        print(f"[RESULT] Protected relay service response:")
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "blocked":
            print(f"\n[SUCCESS] ✅ SSRF protection WORKED! URL was blocked.")
            print(f"[PROTECTION] Blocked reasons: {result.get('blocked_reasons', [])}")
            if should_block:
                print(f"[VERIFY] ✓ Correctly blocked malicious URL")
            else:
                print(f"[WARNING] ⚠️  Safe URL was incorrectly blocked!")
        elif result.get("status") == "success":
            print(f"\n[RESULT] URL was allowed and fetched.")
            if should_block:
                print(f"[WARNING] ⚠️  SSRF protection FAILED! Malicious URL was allowed!")
            else:
                print(f"[VERIFY] ✓ Correctly allowed safe external URL")
        else:
            print(f"\n[RESULT] {result.get('message', 'Unknown status')}")
            
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Cannot connect to protected relay service at http://127.0.0.1:8005")
        print(f"[INFO] Make sure the protected relay service is running:")
        print(f"  python -m external_service.secure_ssrf_relay_service")
    except Exception as e:
        print(f"[ERROR] Test failed: {e}")
    
    print(f"{'─'*80}")
    await asyncio.sleep(1)


async def run_protection_demo():
    """Run SSRF protection demonstration"""
    
    # Register signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*80)
    print("  SSRF PROTECTION DEMONSTRATION")
    print("="*80)
    print("\nThis script demonstrates how the SSRF protection wrapper blocks SSRF attacks.")
    print("\nThe protection wrapper sits between the relay service and MCP server,")
    print("validating URLs before allowing the MCP server to fetch them.")
    print("\n[AUTO-START] Checking and starting required services...")
    print("="*80 + "\n")
    
    # Check and start internal target service (for Scenario 1)
    internal_service_started = False
    if not check_service_running(8080):
        print("[INFO] Internal target service (port 8080) not running, starting it...")
        process = start_service("Internal Target Service", "external_service.internal_target_service", 8080)
        if process:
            background_processes.append(process)
            internal_service_started = True
    else:
        print("[OK] Internal target service (port 8080) is already running (will reuse existing)")
    
    # Check and start protected relay service
    protected_relay_started = False
    if not check_service_running(8005):
        print("[INFO] Protected relay service (port 8005) not running, starting it...")
        process = start_service("Secure SSRF Relay Service", "external_service.secure_ssrf_relay_service", 8005)
        if process:
            background_processes.append(process)
            protected_relay_started = True
    else:
        print("[OK] Protected relay service (port 8005) is already running (will reuse existing)")
    
    # Give services a moment to fully initialize
    if internal_service_started or protected_relay_started:
        print("[INFO] Waiting for services to fully initialize...")
        time.sleep(2)
    
    print("\n[WARNING] Testing SSRF protection - attacks should be BLOCKED!")
    print("="*80 + "\n")
    
    # Number the attacks
    for i, attack in enumerate(SSRF_ATTACK_SCENARIOS, 1):
        attack['number'] = i
    
    # Run all tests
    print(f"[RUN] Running {len(SSRF_ATTACK_SCENARIOS)} SSRF protection tests...\n")
    
    blocked_count = 0
    allowed_count = 0
    
    for attack_scenario in SSRF_ATTACK_SCENARIOS:
        await test_protected_relay(attack_scenario)
        # Check if it was blocked (we'll count from the output)
    
    # Get protection stats
    try:
        stats_response = requests.get("http://127.0.0.1:8005/protection/stats", timeout=5)
        if stats_response.status_code == 200:
            stats = stats_response.json().get("protection_stats", {})
            blocked_count = stats.get("blocked_count", 0)
            allowed_count = stats.get("allowed_count", 0)
    except:
        pass
    
    print("\n" + "="*80)
    print("  SSRF PROTECTION DEMONSTRATION COMPLETE")
    print("="*80)
    print("\nSummary:")
    print("  Protection: SSRF protection wrapper validates URLs before MCP server fetches them")
    print("  Blocked URLs: Internal/localhost URLs, file:// protocol, private IPs")
    print("  Allowed URLs: Safe external public URLs")
    print(f"\n  Protection Statistics:")
    print(f"    - URLs blocked: {blocked_count}")
    print(f"    - URLs allowed: {allowed_count}")
    print(f"    - Total requests: {blocked_count + allowed_count}")
    print("\n  The wrapper successfully prevents SSRF attacks by blocking:")
    print("    - localhost/127.0.0.1 addresses")
    print("    - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)")
    print("    - file:// protocol")
    print("    - Internal/private domains")
    print("    - Cloud metadata service IPs (169.254.169.254)")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_protection_demo())
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Cleaning up...")
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        cleanup_processes()
        sys.exit(1)

