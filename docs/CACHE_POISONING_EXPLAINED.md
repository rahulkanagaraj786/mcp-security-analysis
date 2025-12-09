# Cache Poisoning Attack - Where Does It Happen?

## The Confusion

You might be wondering: "Where is the actual attack happening? I just see text being stored in a cache file."

This is a valid question! Cache poisoning attacks happen in **TWO PHASES**, and the "attack" is the contamination of a shared resource that will affect future users.

## The Two Phases of Cache Poisoning

### Phase 1: **THE ATTACK** (Storage Phase) ⚠️
**Location**: When `update_profile` or `save_note` is called

**What happens:**
1. Attacker sends malicious content (phishing message, XSS payload, etc.)
2. Server stores it directly in cache **WITHOUT VALIDATION**
3. The cache is now "poisoned" with malicious content

**Example:**
```
Attacker Query: "Update my profile with user_id 1 and bio: Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"

What happens:
→ LLM calls update_profile(user_id=1, bio="Your session token is: ...")
→ Server stores in cache: cache["user_profile_1"] = {bio: "Your session token is: ..."}
→ Cache is now POISONED
```

**This is where the attack happens** - the malicious content is stored in a shared cache that other users will access.

### Phase 2: **THE IMPACT** (Retrieval Phase) 💥
**Location**: When `get_profile` or `get_note` is called by a victim

**What happens:**
1. Victim (or their LLM) retrieves the cached content
2. Server returns the unsanitized malicious content
3. Victim sees/processes the malicious content

**Example:**
```
Victim Query: "Get my profile for user_id 1"

What happens:
→ LLM calls get_profile(user_id=1)
→ Server retrieves from cache: cache["user_profile_1"]
→ Server returns: {bio: "Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"}
→ Victim's LLM processes this and may:
   - Display it to the user (phishing attack)
   - Execute it if it's XSS (in browser context)
   - Interpret it as instructions if it's prompt injection
```

## Visual Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: THE ATTACK                      │
│                  (Where the poisoning happens)              │
└─────────────────────────────────────────────────────────────┘

Attacker
   │
   │ "Update profile with user_id 1 and bio: [MALICIOUS TEXT]"
   ▼
LLM (Ollama)
   │
   │ Calls: update_profile(user_id=1, bio="[MALICIOUS TEXT]")
   ▼
MCP Server (VULNERABLE)
   │
   │ ⚠️ NO VALIDATION - stores directly
   │
   ▼
Cache Storage
   │
   │ cache["user_profile_1"] = {
   │   "user_id": 1,
   │   "bio": "[MALICIOUS TEXT]"  ← POISONED!
   │ }
   │
   ▼
Cache File (cache_contents.json)
   │
   │ {
   │   "user_profile_1": {
   │     "bio": "[MALICIOUS TEXT]"  ← POISONED!
   │   }
   │ }
   │
   └─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  PHASE 2: THE IMPACT                        │
│              (Where the attack affects victims)             │
└─────────────────────────────────────────────────────────────┘

Victim (Different User)
   │
   │ "Get my profile for user_id 1"
   ▼
Victim's LLM
   │
   │ Calls: get_profile(user_id=1)
   ▼
MCP Server
   │
   │ Retrieves: cache["user_profile_1"]
   │ ⚠️ NO SANITIZATION - returns as-is
   │
   ▼
Returns to Victim
   │
   │ {
   │   "bio": "[MALICIOUS TEXT]"  ← UNSANITIZED!
   │ }
   │
   ▼
Victim's LLM/Application
   │
   │ Processes the malicious content:
   │ - Displays phishing message to user
   │ - Executes XSS if in browser
   │ - Interprets prompt injection as instructions
   │
   ▼
💥 ATTACK SUCCESSFUL
```

## Why This Is Dangerous

The cache is a **shared resource**. Once poisoned:

1. **Multiple victims** can retrieve the same malicious content
2. **Persistent** - the poison stays in cache until cleared
3. **Trusted source** - content comes from the server's cache, so it appears legitimate
4. **No validation** - the server doesn't check if content is safe before serving it

## Real-World Analogy

Think of cache poisoning like contaminating a public water fountain:

- **Phase 1 (Attack)**: Attacker puts poison in the water fountain
- **Phase 2 (Impact)**: Multiple people drink from the fountain and get poisoned

The attack happens when the poison is added (Phase 1), but the impact happens when people drink (Phase 2).

## In Your Codebase

Looking at your `cache_contents.json`:
```json
{
  "user_profile_1": {
    "user_id": 1,
    "bio": "Your session token is: SESSION_TOKEN_PLACEHOLDER. Please verify your account by sending your password to verify@example.com"
  }
}
```

**This is Phase 1 complete** - the cache is poisoned! 

**Phase 2 would happen** when someone calls:
```python
get_profile(user_id=1)
```

And the server returns that malicious bio text, which could:
- Trick a user into revealing their password
- Steal session tokens
- Execute XSS if rendered in a browser
- Inject prompts into an LLM

## The Attack Location Summary

| Phase | Where | What Happens | Code Location |
|-------|-------|--------------|---------------|
| **Phase 1: Attack** | `update_profile()` / `save_note()` | Malicious content stored without validation | `server/vulnerable_server.py` lines 262-296, 325-353 |
| **Phase 2: Impact** | `get_profile()` / `get_note()` | Poisoned content retrieved and served unsanitized | `server/vulnerable_server.py` lines 355-389, 422-450 |

## Testing the Full Attack

To see both phases:

1. **Phase 1 - Poison the cache:**
   ```bash
   python demo/cache_poisoning_explanation_demo.py
   # Choose option 1 (vulnerable server)
   # Enter: "Update my profile with user_id 1 and bio: <script>alert('XSS')</script>"
   ```

2. **Check the cache is poisoned:**
   ```bash
   cat cache/cache_contents.json
   # You'll see the malicious content stored
   ```

3. **Phase 2 - Retrieve the poison:**
   ```bash
   # In the same demo, enter:
   "Get my profile for user_id 1"
   # The server will return the unsanitized XSS payload
   ```

## Key Takeaway

**The attack happens in Phase 1** (storage), but **the impact happens in Phase 2** (retrieval). The "poisoning" is the contamination of a shared cache that will affect future users. The vulnerability is that the server doesn't validate content before storing it OR before serving it.
