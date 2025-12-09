#!/usr/bin/env python3
"""
Start All External Services

Helper script to start all three external attack services simultaneously.
Each service runs in a separate process.

Usage:
    python start_all_services.py
"""

import subprocess
import sys
import time
import signal
import os
from pathlib import Path

# Get the directory where this script is located
script_dir = Path(__file__).parent
services = []


def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully stop all services"""
    print("\n\n[STOP] Stopping all services...")
    for process in services:
        try:
            process.terminate()
        except:
            pass
    
    # Wait a bit, then kill if still running
    time.sleep(1)
    for process in services:
        try:
            process.kill()
        except:
            pass
    
    print("[OK] All services stopped")
    sys.exit(0)


def start_service(name, script_path, port):
    """Start a service in a separate process"""
    print(f"[START] Starting {name} on port {port}...")
    
    try:
        process = subprocess.Popen(
            [sys.executable, str(script_path)],
            cwd=str(script_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        services.append(process)
        
        # Give it a moment to start
        time.sleep(0.5)
        
        # Check if process is still running
        if process.poll() is None:
            print(f"[OK] {name} started (PID: {process.pid})")
            return True
        else:
            print(f"[ERROR] {name} failed to start")
            return False
            
    except Exception as e:
        print(f"[ERROR] Failed to start {name}: {e}")
        return False


def main():
    """Main function to start all services"""
    print("\n" + "="*70)
    print("  Starting All External Attack Services")
    print("="*70)
    print()
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Define services
    service_configs = [
        ("SSRF Service", script_dir / "ssrf_service.py", 8001),
        ("RCE Service", script_dir / "rce_service.py", 8002),
        ("XSS Service", script_dir / "xss_service.py", 8003),
        ("XSS Relay Service", script_dir / "xss_relay_service.py", 8004),
    ]
    
    # Start all services
    success_count = 0
    for name, script_path, port in service_configs:
        if script_path.exists():
            if start_service(name, script_path, port):
                success_count += 1
        else:
            print(f"[ERROR] Service file not found: {script_path}")
    
    if success_count == 0:
        print("\n[ERROR] No services started successfully")
        sys.exit(1)
    
    print("\n" + "="*70)
    print(f"  {success_count}/{len(service_configs)} services started")
    print("="*70)
    print("\nServices running:")
    print("  - SSRF Service:     http://127.0.0.1:8001")
    print("  - RCE Service:       http://127.0.0.1:8002")
    print("  - XSS Service:       http://127.0.0.1:8003")
    print("  - XSS Relay Service: http://127.0.0.1:8004")
    print("\nPress Ctrl+C to stop all services")
    print("="*70 + "\n")
    
    # Keep running and monitor services
    try:
        while True:
            time.sleep(1)
            # Check if any service has died
            for i, process in enumerate(services):
                if process.poll() is not None:
                    name = service_configs[i][0]
                    print(f"\n[WARNING] {name} has stopped (exit code: {process.returncode})")
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()

