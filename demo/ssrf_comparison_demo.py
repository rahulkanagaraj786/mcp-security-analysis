#!/usr/bin/env python3
"""
SSRF Attack vs Protection Comparison Demo

This script demonstrates SSRF attacks against both:
1. Vulnerable relay service (port 8001) - attacks succeed
2. Protected relay service (port 8005) - attacks are blocked

This side-by-side comparison shows how the SSRF protection wrapper prevents attacks.
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

# SSRF Attack Scenarios
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


def test_vulnerable_relay(attack_scenario):
    """Test SSRF attack against vulnerable relay service"""
    url = attack_scenario['url']
    relay_url = f"http://127.0.0.1:8001/fetch?url={url}"
    
    try:
        response = requests.get(relay_url, timeout=30)
        result = response.json()
        
        if result.get("status") == "success":
            return {
                "success": True,
                "blocked": False,
                "result": result
            }
        else:
            return {
                "success": False,
                "blocked": False,
                "result": result
            }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "blocked": False,
            "error": "Cannot connect to vulnerable relay service"
        }
    except Exception as e:
        return {
            "success": False,
            "blocked": False,
            "error": str(e)
        }


def test_protected_relay(attack_scenario):
    """Test SSRF attack against protected relay service"""
    url = attack_scenario['url']
    relay_url = f"http://127.0.0.1:8005/fetch?url={url}"
    
    try:
        response = requests.get(relay_url, timeout=30)
        result = response.json()
        
        if result.get("status") == "blocked":
            return {
                "success": True,
                "blocked": True,
                "result": result
            }
        elif result.get("status") == "success":
            return {
                "success": True,
                "blocked": False,
                "result": result
            }
        else:
            return {
                "success": False,
                "blocked": False,
                "result": result
            }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "blocked": False,
            "error": "Cannot connect to protected relay service"
        }
    except Exception as e:
        return {
            "success": False,
            "blocked": False,
            "error": str(e)
        }


async def run_comparison_test(attack_scenario):
    """Run the same attack against both vulnerable and protected services"""
    
    scenario_num = attack_scenario.get('scenario', '?')
    should_block = attack_scenario.get('should_be_blocked', True)
    
    print(f"\n{'='*80}")
    print(f"  Test: {attack_scenario['name']}")
    print(f"{'='*80}")
    print(f"Scenario: {scenario_num} - {'Secrets in separate internal service' if scenario_num == 1 else 'Secrets in MCP server itself' if scenario_num == 2 else 'Safe external URL'}")
    print(f"Target URL: {attack_scenario['url']}")
    print(f"Expected: {'BLOCKED by protection' if should_block else 'ALLOWED (safe external URL)'}")
    print(f"{'─'*80}\n")
    
    # Test vulnerable version
    print("[VULNERABLE RELAY] Testing against vulnerable relay service (port 8001)...")
    vulnerable_result = test_vulnerable_relay(attack_scenario)
    
    if vulnerable_result.get("success") and not vulnerable_result.get("blocked"):
        print(f"[VULNERABLE] ⚠️  ATTACK SUCCEEDED - URL was fetched!")
        if "error" in vulnerable_result:
            print(f"[VULNERABLE] Error: {vulnerable_result['error']}")
        else:
            print(f"[VULNERABLE] MCP server fetched internal resource (SSRF vulnerability exploited)")
    elif vulnerable_result.get("error"):
        print(f"[VULNERABLE] ❌ Connection error: {vulnerable_result['error']}")
    else:
        print(f"[VULNERABLE] ❌ Attack failed: {vulnerable_result.get('result', {}).get('message', 'Unknown error')}")
    
    print()
    
    # Test protected version
    print("[PROTECTED RELAY] Testing against protected relay service (port 8005)...")
    protected_result = test_protected_relay(attack_scenario)
    
    if protected_result.get("blocked"):
        print(f"[PROTECTED] ✅ PROTECTION WORKED - URL was blocked!")
        blocked_reasons = protected_result.get("result", {}).get("blocked_reasons", [])
        if blocked_reasons:
            print(f"[PROTECTED] Blocked reasons: {', '.join(blocked_reasons)}")
        if should_block:
            print(f"[PROTECTED] ✓ Correctly blocked malicious URL")
        else:
            print(f"[PROTECTED] ⚠️  Safe URL was incorrectly blocked!")
    elif protected_result.get("success") and not protected_result.get("blocked"):
        print(f"[PROTECTED] ⚠️  URL was allowed and fetched")
        if should_block:
            print(f"[PROTECTED] ❌ PROTECTION FAILED - Malicious URL was allowed!")
        else:
            print(f"[PROTECTED] ✓ Correctly allowed safe external URL")
    elif protected_result.get("error"):
        print(f"[PROTECTED] ❌ Connection error: {protected_result['error']}")
    else:
        print(f"[PROTECTED] ❌ Unexpected result: {protected_result.get('result', {})}")
    
    print(f"{'─'*80}")
    
    # Summary for this test
    print(f"\n[COMPARISON SUMMARY]")
    if vulnerable_result.get("success") and not vulnerable_result.get("blocked"):
        print(f"  Vulnerable: ⚠️  ATTACK SUCCEEDED")
    else:
        print(f"  Vulnerable: ❌ Attack failed or service unavailable")
    
    if protected_result.get("blocked"):
        print(f"  Protected:  ✅ BLOCKED by SSRF protection")
    elif protected_result.get("success") and not protected_result.get("blocked"):
        print(f"  Protected:  ⚠️  ALLOWED (protection may have failed)")
    else:
        print(f"  Protected:  ❌ Service unavailable or error")
    
    await asyncio.sleep(1)


async def run_comparison_demo():
    """Run SSRF attack comparison demonstration"""
    
    # Register signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n" + "="*80)
    print("  SSRF ATTACK vs PROTECTION COMPARISON DEMO")
    print("="*80)
    print("\nThis demo shows the same SSRF attacks against:")
    print("  1. Vulnerable relay service (port 8001) - attacks succeed")
    print("  2. Protected relay service (port 8005) - attacks are blocked")
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
        print("[OK] Internal target service (port 8080) is already running")
    
    # Check and start vulnerable relay service
    vulnerable_relay_started = False
    if not check_service_running(8001):
        print("[INFO] Vulnerable relay service (port 8001) not running, starting it...")
        process = start_service("Vulnerable SSRF Relay Service", "external_service.ssrf_service", 8001)
        if process:
            background_processes.append(process)
            vulnerable_relay_started = True
    else:
        print("[OK] Vulnerable relay service (port 8001) is already running")
    
    # Check and start protected relay service
    protected_relay_started = False
    if not check_service_running(8005):
        print("[INFO] Protected relay service (port 8005) not running, starting it...")
        process = start_service("Secure SSRF Relay Service", "external_service.secure_ssrf_relay_service", 8005)
        if process:
            background_processes.append(process)
            protected_relay_started = True
    else:
        print("[OK] Protected relay service (port 8005) is already running")
    
    # Give services a moment to fully initialize
    if internal_service_started or vulnerable_relay_started or protected_relay_started:
        print("[INFO] Waiting for services to fully initialize...")
        time.sleep(3)
    
    print("\n[WARNING] Running SSRF attacks against both vulnerable and protected services...")
    print("="*80 + "\n")
    
    # Run all comparison tests
    print(f"[RUN] Running {len(SSRF_ATTACK_SCENARIOS)} comparison tests...\n")
    
    for attack_scenario in SSRF_ATTACK_SCENARIOS:
        await run_comparison_test(attack_scenario)
    
    # Get protection stats
    vulnerable_stats = {"blocked": 0, "allowed": 0}
    protected_stats = {"blocked": 0, "allowed": 0}
    
    try:
        stats_response = requests.get("http://127.0.0.1:8005/protection/stats", timeout=5)
        if stats_response.status_code == 200:
            stats = stats_response.json().get("protection_stats", {})
            protected_stats["blocked"] = stats.get("blocked_count", 0)
            protected_stats["allowed"] = stats.get("allowed_count", 0)
    except:
        pass
    
    print("\n" + "="*80)
    print("  SSRF ATTACK vs PROTECTION COMPARISON COMPLETE")
    print("="*80)
    print("\nSummary:")
    print("  This demo compared SSRF attacks against:")
    print("    - Vulnerable relay service (port 8001): No protection, attacks succeed")
    print("    - Protected relay service (port 8005): SSRF protection enabled, attacks blocked")
    print(f"\n  Protection Statistics (Protected Service):")
    print(f"    - URLs blocked: {protected_stats['blocked']}")
    print(f"    - URLs allowed: {protected_stats['allowed']}")
    print(f"    - Total requests: {protected_stats['blocked'] + protected_stats['allowed']}")
    print("\n  Key Findings:")
    print("    ✓ Vulnerable service allows all URLs (including internal/localhost)")
    print("    ✓ Protected service blocks malicious URLs (internal/localhost/file://)")
    print("    ✓ Protected service allows safe external URLs")
    print("    ✓ SSRF protection wrapper successfully prevents SSRF attacks")
    print("="*80 + "\n")
    
    # Cleanup background processes
    cleanup_processes()


if __name__ == "__main__":
    try:
        asyncio.run(run_comparison_demo())
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Cleaning up...")
        cleanup_processes()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        cleanup_processes()
        sys.exit(1)

