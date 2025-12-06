# Cache Poisoning Protection Explained

## Overview

Cache poisoning protection prevents malicious content (XSS, prompt injection, etc.) from being stored in the server's cache and later served to users or LLMs. This protection layer sits between the LLM/client and the MCP server, intercepting cache operations and validating content.

## Architecture

```
LLM/Client → Cache Poisoning Protection Wrapper → MCP Server
```

The wrapper intercepts:
- **Cache storage operations**: `update_profile`, `save_note`
- **Cache retrieval operations**: `get_profile`, `get_note`

## Protection Features

The wrapper detects and blocks:

### 1. XSS (Cross-Site Scripting) Payloads
- `<script>` tags
- Event handlers (`onclick`, `onerror`, `onload`, etc.)
- JavaScript protocol (`javascript:`)
- `<iframe>`, `<img>`, `<svg>` with event handlers
- `eval()`, `expression()` calls

### 2. Prompt Injection Patterns
- "IGNORE ALL PREVIOUS INSTRUCTIONS"
- "SYSTEM OVERRIDE"
- "BYPASS SECURITY"
- "REVEAL YOUR SYSTEM PROMPT"
- "YOU ARE NOW IN DEVELOPER MODE"
- Other instruction override patterns

### 3. SQL Injection Patterns
- SQL injection patterns (even though server uses no-SQL cache)
- Demonstrates comprehensive input validation

## Components

### 1. Content Sanitizer (`defenses/input_validation/content_sanitizer.py`)

The core validation logic that checks content for malicious patterns.

**Key Methods:**
- `detect_xss(content: str) -> Tuple[bool, List[str]]`: Detects XSS patterns
- `detect_prompt_injection(content: str) -> Tuple[bool, List[str]]`: Detects prompt injection patterns
- `detect_sql_injection(content: str) -> Tuple[bool, List[str]]`: Detects SQL injection patterns
- `validate_content(content: str) -> Tuple[bool, str, Dict]`: Validates content and returns whether it's safe
- `sanitize_content(content: str) -> str`: Escapes HTML entities to sanitize content

**Configuration:**
- `strict_mode`: If True, blocks malicious content. If False, only logs warnings.
- `sanitize_output`: If True, sanitizes content by escaping HTML. If False, only detects.

### 2. Cache Poisoning Protection Wrapper (`defenses/cache_poisoning_protection_wrapper.py`)

The wrapper that intercepts tool calls and applies cache poisoning protection.

**Key Methods:**
- `call_tool(tool_name: str, arguments: dict) -> dict`: Intercepts cache operations and validates content
- `get_protection_stats() -> Dict`: Returns statistics about blocked/allowed requests

**How it works:**

1. **Storage Phase (Input Validation)**:
   - Intercepts `update_profile` and `save_note` tool calls
   - Extracts `bio` or `content` fields
   - Validates content using ContentSanitizer
   - Blocks if malicious patterns detected
   - Optionally sanitizes content before storing (defense in depth)

2. **Retrieval Phase (Output Sanitization)**:
   - Intercepts `get_profile` and `get_note` tool calls
   - Calls the tool to retrieve cached content
   - Sanitizes retrieved content (escapes HTML entities)
   - Returns sanitized content

## Usage

### Basic Usage

```python
from defenses.cache_poisoning_protection_wrapper import create_cache_poisoning_protection_wrapper

# Create base MCP client
base_client = await create_mcp_client()

# Wrap with cache poisoning protection
protected_client = create_cache_poisoning_protection_wrapper(
    base_client,
    strict_mode=True,      # Block malicious content
    sanitize_output=True    # Sanitize output when retrieving
)

# Use protected client with Ollama
ollama_llm = OllamaLLM(protected_client, model="llama3.1")
```

### Configuration Options

- **strict_mode=True**: Blocks malicious content (recommended)
- **strict_mode=False**: Only logs warnings, allows content through
- **sanitize_output=True**: Sanitizes content when storing and retrieving (recommended)
- **sanitize_output=False**: Only validates, doesn't sanitize

## Example: How Protection Works

### Attack Attempt (Blocked)

**User Query:**
```
Update my profile with user_id 1 and bio: <script>alert('XSS')</script>
```

**What happens:**
1. LLM calls `update_profile` tool
2. Protection wrapper intercepts the call
3. Content sanitizer detects XSS pattern (`<script>` tag)
4. Wrapper blocks the call
5. Returns error: `CACHE_POISONING_PROTECTION`

**Result:**
```
[CACHE POISONING PROTECTION] [BLOCKED] Tool: update_profile
[CACHE POISONING PROTECTION] Reason: Blocked: Cache poisoning detected. Threats: XSS
[CACHE POISONING PROTECTION] Detected threats: ['XSS']
```

### Safe Content (Allowed)

**User Query:**
```
Update my profile with user_id 1 and bio: Software developer passionate about security
```

**What happens:**
1. LLM calls `update_profile` tool
2. Protection wrapper intercepts the call
3. Content sanitizer validates content - no threats detected
4. Wrapper allows the call (optionally sanitizes)
5. Content stored in cache

**Result:**
```
[CACHE POISONING PROTECTION] [ALLOWED] Tool: update_profile
```

## Defense in Depth

The protection uses multiple layers:

1. **Input Validation**: Validates content before storing in cache
2. **Content Sanitization**: Escapes HTML entities when storing
3. **Output Sanitization**: Sanitizes content when retrieving from cache
4. **Pattern Detection**: Detects multiple threat types (XSS, prompt injection, SQL injection)

## Statistics

The wrapper tracks:
- `blocked_count`: Number of blocked tool calls
- `allowed_count`: Number of allowed tool calls
- `sanitized_retrievals`: Number of times content was sanitized on retrieval
- `detected_threats`: Number of threats detected

## Testing

Run the defense demonstration:

```bash
cd /cis_project/mcp_security_project
source venv_mcp/bin/activate
python demo/cache_poisoning_defense_demo.py
```

This demonstrates:
1. Cache poisoning attacks against vulnerable system (attacks succeed)
2. Cache poisoning attacks against protected system (attacks blocked)

## Comparison with Other Defenses

- **Path Traversal Protection**: Validates file paths
- **Prompt Injection Protection**: Detects instruction override patterns in tool calls
- **SSRF Protection**: Validates URLs before fetching
- **Cache Poisoning Protection**: Validates content before storing in cache

All defenses work together to provide comprehensive protection.

