#!/usr/bin/env python3
"""
Simple test to verify cache poisoning works correctly
"""
import asyncio
import json
from pathlib import Path
import sys

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from demo.cache_poisoning_explanation_demo import create_mcp_client, run_query, write_cache_to_file

async def test_cache_poisoning():
    """Test that cache poisoning works - User 1 poisons, User 2 sees it"""
    print("="*70)
    print("CACHE POISONING TEST")
    print("="*70)
    
    # User 1: Poison the cache
    print("\n[User 1 - Attacker] Poisoning cache...")
    client1 = await create_mcp_client()
    
    poison_query = "Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"
    result1 = await run_query(client1, poison_query, mode="vulnerable")
    
    if result1.get('status') == 'success':
        print("✓ Cache poisoned successfully")
        await write_cache_to_file(client1, preserve_existing=False)
        
        # Show cache file
        cache_file = Path(__file__).parent / "cache" / "cache_contents.json"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            print(f"\nCache file contents:")
            print(json.dumps(cache_data, indent=2))
    else:
        print(f"✗ Failed to poison cache: {result1}")
        await client1.cleanup()
        return
    
    await client1.cleanup()
    
    # User 2: Try to retrieve (simulating different server instance)
    print("\n[User 2 - Victim] Retrieving profile...")
    client2 = await create_mcp_client()
    
    retrieve_query = "Get my profile for user_id 1"
    result2 = await run_query(client2, retrieve_query, mode="vulnerable")
    
    if result2.get('status') == 'not_found':
        print("Server says: Profile not found (different server instance)")
        # But cache file should still show the poisoned data
        cache_file = Path(__file__).parent / "cache" / "cache_contents.json"
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            if cache_data:
                print("\n✓ Cache file still contains poisoned data:")
                print(json.dumps(cache_data, indent=2))
                print("\nThis demonstrates cache poisoning - the poisoned data persists in the cache file")
                print("even though User 2's server instance doesn't have it in memory.")
    elif result2.get('status') == 'success' and 'data' in result2:
        print("✓ Retrieved profile (same server instance):")
        print(json.dumps(result2['data'], indent=2))
        print("\nThis shows the poisoned data is served to User 2.")
    else:
        print(f"Unexpected result: {result2}")
    
    await client2.cleanup()
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)

if __name__ == "__main__":
    asyncio.run(test_cache_poisoning())
