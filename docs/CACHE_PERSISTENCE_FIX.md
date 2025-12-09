# Cache Persistence Fix

## The Problem

When switching between vulnerable and protected server modes in the interactive demo, the cache was being cleared. This happened because:

1. **Each server instance starts with an empty in-memory cache** - The `StorageManager` initialized with `self.cache: Dict[str, Any] = {}`
2. **Cache file wasn't loaded on startup** - The cache file (`cache_contents.json`) was only used for viewing, not as a source of truth
3. **New server instances couldn't see previous cache entries** - When you switched from vulnerable to protected server, the new server instance had no knowledge of previously stored cache entries

## Why This Was a Problem

- **Legitimate cache entries were lost** - If you stored legitimate data in the vulnerable server, switching to protected server would make it inaccessible
- **Cache poisoning demonstrations were incomplete** - You couldn't demonstrate retrieving previously poisoned cache entries after switching servers
- **Unrealistic behavior** - In a real system, cache should persist across server restarts

## The Fix

### 1. Load Cache from File on Initialization

Modified `StorageManager.__init__()` to load cache from `cache_contents.json` on startup:

```python
def __init__(self, cache_dir: str = "cache", files_dir: str = "files", load_from_file: bool = True):
    self.cache: Dict[str, Any] = {}
    # ... directory setup ...
    
    # Load cache from file if it exists (persist cache across server restarts)
    if load_from_file:
        self._load_cache_from_file()
```

### 2. Added `_load_cache_from_file()` Method

This method:
- Reads `cache_contents.json` if it exists
- Converts the file format to internal cache format
- Loads all entries into the in-memory cache
- Handles errors gracefully (continues with empty cache if file is corrupted)

### 3. Improved Cache Preservation Logic

Updated the demo to better preserve cache when requests are blocked:
- When a request is blocked by protection, the cache file is preserved
- Added a note to inform users that blocked requests don't modify cache

## How It Works Now

1. **Server starts** → Loads cache from `cache_contents.json` if it exists
2. **Cache operations** → Updates both in-memory cache and cache file
3. **Server restarts** → Cache persists because it's loaded from file on startup
4. **Switching servers** → New server instance loads existing cache from file

## Benefits

✅ **Cache persists across server restarts**  
✅ **Legitimate cache entries are preserved**  
✅ **Better demonstration of cache poisoning** - You can poison cache in vulnerable mode, then retrieve it in protected mode  
✅ **More realistic behavior** - Matches how real systems work  

## Testing

To verify the fix works:

1. **Start vulnerable server mode:**
   ```bash
   python demo/cache_poisoning_explanation_demo.py
   # Select option 1
   ```

2. **Store some data:**
   ```
   Update my profile with user_id 1 and bio: This is legitimate content
   ```

3. **Check cache file:**
   ```bash
   cat cache/cache_contents.json
   # Should show your data
   ```

4. **Switch to protected server mode:**
   ```
   exit  # Exit vulnerable mode
   # Select option 2 (protected server)
   ```

5. **Retrieve the data:**
   ```
   Get my profile for user_id 1
   # Should still return your data!
   ```

6. **Try to poison cache (should be blocked):**
   ```
   Update my profile with user_id 1 and bio: <script>alert('XSS')</script>
   # Should be blocked
   ```

7. **Verify legitimate cache is still there:**
   ```
   Get my profile for user_id 1
   # Should still return "This is legitimate content" (not the XSS)
   ```

## Important Notes

- The cache file (`cache_contents.json`) is now the **source of truth** for persistence
- Each server instance loads from this file on startup
- Cache operations update both in-memory cache and the file
- The cache file format is preserved (no breaking changes)

## Backward Compatibility

- Existing cache files will be automatically loaded
- If the cache file doesn't exist, the server starts with an empty cache (as before)
- If the cache file is corrupted, the server starts with an empty cache and logs a warning
