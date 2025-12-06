# SSRF Protection Wrapper

## Overview

The SSRF Protection Wrapper is a security layer that sits between external services (relay services) and the MCP server. It intercepts `http_get` tool calls and validates URLs before allowing the MCP server to fetch them, preventing Server-Side Request Forgery (SSRF) attacks.

## Architecture

```
External Service (Relay) → SSRF Protection Wrapper → MCP Server
```

The wrapper intercepts tool calls, specifically `http_get`, and validates the URL before passing it to the MCP server.

## Protection Features

The wrapper blocks the following types of URLs:

1. **Localhost/Internal Hostnames**
   - `localhost`
   - `127.0.0.1`
   - `0.0.0.0`
   - `::1` (IPv6 localhost)

2. **Private IP Ranges**
   - `10.0.0.0/8` (10.x.x.x)
   - `172.16.0.0/12` (172.16-31.x.x)
   - `192.168.0.0/16` (192.168.x.x)
   - `127.0.0.0/8` (localhost range)
   - `169.254.0.0/16` (Link-local, includes cloud metadata services)

3. **Blocked Protocols**
   - `file://` (file system access)
   - `gopher://`
   - `ldap://`
   - `ldaps://`

4. **Optional Domain Whitelist**
   - If configured, only allows URLs from whitelisted domains

## Components

### 1. SSRF URL Validator (`defenses/input_validation/ssrf_url_validator.py`)

The core validation logic that checks URLs against SSRF attack patterns.

**Key Methods:**
- `validate_url(url: str) -> Tuple[bool, str, Dict]`: Validates a URL and returns whether it's allowed
- `is_private_ip(ip: str) -> bool`: Checks if an IP is in a private range
- `is_blocked_protocol(protocol: str) -> bool`: Checks if a protocol is blocked
- `is_blocked_hostname(hostname: str) -> bool`: Checks if a hostname is blocked

### 2. SSRF Protection Wrapper (`defenses/ssrf_protection_wrapper.py`)

The wrapper that intercepts tool calls and applies SSRF protection.

**Key Methods:**
- `call_tool(tool_name: str, arguments: dict) -> dict`: Intercepts `http_get` calls and validates URLs
- `get_protection_stats() -> Dict`: Returns statistics about blocked/allowed requests

### 3. Secure SSRF Relay Service (`external_service/secure_ssrf_relay_service.py`)

A protected version of the relay service that uses the SSRF protection wrapper.

**Features:**
- Runs on port 8005 (different from vulnerable version on 8001)
- Automatically wraps MCP client with SSRF protection
- Provides `/protection/stats` endpoint to view protection statistics

## Usage

### Basic Usage

```python
from defenses.ssrf_protection_wrapper import create_ssrf_protection_wrapper

# Create wrapper around your MCP client
protected_client = create_ssrf_protection_wrapper(
    base_client=your_mcp_client,
    strict_mode=True,
    allowed_domains=None  # Allow all public domains, block only internal
)

# Use the protected client
result = await protected_client.call_tool("http_get", {"url": "https://example.com"})
```

### With Domain Whitelist

```python
protected_client = create_ssrf_protection_wrapper(
    base_client=your_mcp_client,
    strict_mode=True,
    allowed_domains=["example.com", "api.example.com"]  # Only allow these domains
)
```

### Running the Protected Relay Service

```bash
# Activate virtual environment
source venv_mcp/bin/activate

# Run the protected relay service
python -m external_service.secure_ssrf_relay_service
```

The service will start on port 8005.

### Testing Protection

Run the protection demonstration:

```bash
python demo/ssrf_defense_demo.py
```

This will:
1. Start the protected relay service (if not running)
2. Start the internal target service (if not running)
3. Attempt various SSRF attacks
4. Show that all malicious URLs are blocked
5. Show that safe external URLs are allowed

## Attack Scenarios Protected

### Scenario 1: Secrets in Other Internal Services
- **Attack**: Requesting `http://127.0.0.1:8080/admin/config`
- **Protection**: Blocked because `127.0.0.1` is a private IP address

### Scenario 2: Secrets in MCP Server Itself
- **Attack**: Requesting `file:///path/to/secrets.json`
- **Protection**: Blocked because `file://` protocol is not allowed
- **Attack**: Requesting `file:///proc/self/environ`
- **Protection**: Blocked because `file://` protocol is not allowed

## Protection Statistics

The wrapper tracks:
- Number of blocked URLs
- Number of allowed URLs
- Details of blocked attempts (URL, reason, type)

Access statistics via:
```python
stats = protected_client.get_protection_stats()
```

Or via the protected relay service:
```bash
curl http://127.0.0.1:8005/protection/stats
```

## Comparison: Vulnerable vs Protected

### Vulnerable Relay Service (Port 8001)
- No URL validation
- Allows all URLs including internal/localhost
- Allows `file://` protocol
- Vulnerable to SSRF attacks

### Protected Relay Service (Port 8005)
- Validates all URLs before fetching
- Blocks internal/localhost URLs
- Blocks `file://` protocol
- Protects against SSRF attacks

## Implementation Details

### URL Validation Flow

1. **Parse URL**: Extract protocol, hostname, port
2. **Check Protocol**: Block `file://`, `gopher://`, etc.
3. **Check Hostname**: Block `localhost`, `127.0.0.1`, etc.
4. **Check IP Address**: Block private IP ranges
5. **Check Whitelist**: If whitelist enabled, verify domain is allowed
6. **Allow/Block**: Return decision with metadata

### Error Handling

When a URL is blocked:
- Returns error response with `"error": "SSRF_PROTECTION"`
- Includes blocking reason and metadata
- Logs the blocked attempt
- Increments blocked counter

When a URL is allowed:
- Passes through to MCP server
- Logs the allowed URL
- Increments allowed counter
- Adds protection metadata to result

## Limitations

1. **DNS Rebinding**: The wrapper validates the hostname/IP in the URL, but doesn't prevent DNS rebinding attacks where the DNS resolves to different IPs. Additional DNS validation may be needed.

2. **Redirects**: The wrapper validates the initial URL, but doesn't validate redirects. The MCP server's HTTP client should be configured to not follow redirects to internal IPs.

3. **IPv6**: Basic IPv6 support is included, but comprehensive IPv6 private range checking may need enhancement.

4. **URL Encoding**: The wrapper parses URLs, but sophisticated URL encoding/obfuscation might bypass some checks. The `urlparse` function handles most cases.

## Future Enhancements

1. **DNS Resolution Validation**: Resolve hostnames and validate resolved IPs
2. **Redirect Validation**: Validate redirect targets
3. **Rate Limiting**: Add rate limiting to prevent abuse
4. **Logging**: Enhanced logging and alerting for blocked attempts
5. **Configuration**: External configuration file for allowed domains, blocked patterns

## Testing

Run the protection demo:
```bash
python demo/ssrf_defense_demo.py
```

Compare with vulnerable version:
```bash
python -m attacks.backward.attack4_ssrf
```

## Files

- `defenses/input_validation/ssrf_url_validator.py`: URL validation logic
- `defenses/ssrf_protection_wrapper.py`: Protection wrapper
- `external_service/secure_ssrf_relay_service.py`: Protected relay service
- `demo/ssrf_defense_demo.py`: Protection demonstration

