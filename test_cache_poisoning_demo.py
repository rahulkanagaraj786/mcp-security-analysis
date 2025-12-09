#!/usr/bin/env python3
"""
Quick test script to verify cache poisoning demo workflow
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from demo.cache_poisoning_defense_demo import (
    create_mcp_client,
    ProtectedMCPClientWrapper,
    demonstrate_vulnerable_attack,
    demonstrate_protected_attack
)
from server.storage_manager import storage
import requests


async def test_basic_workflow():
    """Test basic workflow components"""
    print("Testing cache poisoning demo workflow...")
    print("="*70)
    
    # Test 1: Check Ollama
    print("\n[Test 1] Checking Ollama connection...")
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            print("[OK] Ollama is running")
        else:
            print("[FAIL] Ollama returned status", response.status_code)
            return False
    except Exception as e:
        print(f"[FAIL] Ollama is not running: {e}")
        return False
    
    # Test 2: Test MCP client creation
    print("\n[Test 2] Testing MCP client creation...")
    try:
        client = await create_mcp_client(show_cache_ops=False)
        print("[OK] MCP client created successfully")
        await client.cleanup()
    except Exception as e:
        print(f"[FAIL] Failed to create MCP client: {e}")
        return False
    
    # Test 3: Test protected client wrapper
    print("\n[Test 3] Testing protected client wrapper...")
    try:
        base_client = await create_mcp_client(show_cache_ops=False)
        protected_client = ProtectedMCPClientWrapper(base_client)
        print("[OK] Protected client wrapper created successfully")
        await protected_client.cleanup()
    except Exception as e:
        print(f"[FAIL] Failed to create protected client: {e}")
        return False
    
    # Test 4: Test cache operations
    print("\n[Test 4] Testing cache operations...")
    try:
        storage.clear_cache()
        storage.set_cache("test_key", {"test": "value"})
        retrieved = storage.get_cache("test_key")
        if retrieved and retrieved.get("test") == "value":
            print("[OK] Cache operations working correctly")
            storage.clear_cache()
        else:
            print("[FAIL] Cache retrieval failed")
            return False
    except Exception as e:
        print(f"[FAIL] Cache operations failed: {e}")
        return False
    
    print("\n" + "="*70)
    print("All basic tests passed!")
    print("="*70)
    return True


async def test_demo_functions():
    """Test if demo functions can be imported and called"""
    print("\n" + "="*70)
    print("Testing demo functions...")
    print("="*70)
    
    try:
        # Just verify functions exist and are callable
        from demo.cache_poisoning_defense_demo import (
            demonstrate_vulnerable_attack,
            demonstrate_protected_attack,
            main
        )
        print("[OK] Demo functions imported successfully")
        print("[OK] demonstrate_vulnerable_attack is callable:", callable(demonstrate_vulnerable_attack))
        print("[OK] demonstrate_protected_attack is callable:", callable(demonstrate_protected_attack))
        print("[OK] main is callable:", callable(main))
        return True
    except Exception as e:
        print(f"[FAIL] Failed to import demo functions: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests"""
    print("\nCache Poisoning Demo - Workflow Test")
    print("="*70)
    
    # Run basic workflow tests
    basic_ok = await test_basic_workflow()
    
    # Run demo function tests
    demo_ok = await test_demo_functions()
    
    print("\n" + "="*70)
    if basic_ok and demo_ok:
        print("RESULT: All tests passed! Demo workflow is ready.")
        print("\nTo run the full demo:")
        print("  python demo/cache_poisoning_defense_demo.py")
    else:
        print("RESULT: Some tests failed. Please check the errors above.")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...\n")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
