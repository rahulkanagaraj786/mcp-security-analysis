# How SSRF Protection Works - Step by Step

## Overview

The SSRF protection wrapper uses a **multi-layer validation system** to determine which URLs are safe and which are dangerous. It checks URLs in a specific order and blocks them if they match any dangerous pattern.

## The Validation Process

When a URL is requested, the wrapper goes through these checks **in order**:

```
URL Request → Parse URL → Check 1 → Check 2 → Check 3 → Check 4 → Allow/Block
```

## Step-by-Step Validation

### Step 1: Parse the URL

First, the wrapper parses the URL to extract:
- **Protocol** (http, https, file, etc.)
- **Hostname** (www.example.com, 127.0.0.1, localhost, etc.)
- **Port** (80, 443, 8080, etc.)

Example:
- `http://127.0.0.1:8080/admin/config`
  - Protocol: `http`
  - Hostname: `127.0.0.1`
  - Port: `8080`

### Step 2: Check 1 - Blocked Protocols

**What it checks:** Is the protocol in the blocked list?

**Blocked protocols:**
- `file://` - File system access (can read local files)
- `gopher://` - Old protocol that can be used for SSRF
- `ldap://` / `ldaps://` - LDAP protocol

**Examples:**
- ❌ `file:///etc/passwd` → **BLOCKED** (file:// protocol)
- ❌ `file://./server/secrets.json` → **BLOCKED** (file:// protocol)
- ✅ `http://example.com` → **PASS** (http is allowed)
- ✅ `https://example.com` → **PASS** (https is allowed)

**Why:** The `file://` protocol allows reading local files, which is exactly what SSRF attackers want to do.

### Step 3: Check 2 - Blocked Hostnames

**What it checks:** Is the hostname in the blocked list?

**Blocked hostnames:**
- `localhost`
- `127.0.0.1`
- `0.0.0.0`
- `::1` (IPv6 localhost)
- Any hostname starting with `localhost` (e.g., `localhost.localdomain`)

**Examples:**
- ❌ `http://localhost/admin` → **BLOCKED** (localhost hostname)
- ❌ `http://127.0.0.1:8080/config` → **BLOCKED** (127.0.0.1 hostname)
- ✅ `http://www.example.com` → **PASS** (public domain)
- ✅ `http://api.example.com` → **PASS** (public domain)

**Why:** Localhost addresses point to the server itself, allowing access to internal services.

### Step 4: Check 3 - Private IP Addresses

**What it checks:** Is the hostname a private/internal IP address?

**Private IP ranges blocked:**
- `10.0.0.0/8` → `10.0.0.0` to `10.255.255.255` (10.x.x.x)
- `172.16.0.0/12` → `172.16.0.0` to `172.31.255.255` (172.16-31.x.x)
- `192.168.0.0/16` → `192.168.0.0` to `192.168.255.255` (192.168.x.x)
- `127.0.0.0/8` → `127.0.0.0` to `127.255.255.255` (localhost range)
- `169.254.0.0/16` → `169.254.0.0` to `169.254.255.255` (link-local, includes cloud metadata)

**How it works:**
1. Tries to parse the hostname as an IP address
2. If it's a valid IP, checks if it falls into any private IP range
3. If yes → **BLOCKED**

**Examples:**
- ❌ `http://127.0.0.1:8080/admin` → **BLOCKED** (127.0.0.1 is private IP)
- ❌ `http://10.0.0.1/config` → **BLOCKED** (10.x.x.x is private range)
- ❌ `http://192.168.1.1/admin` → **BLOCKED** (192.168.x.x is private range)
- ❌ `http://172.16.0.1/api` → **BLOCKED** (172.16-31.x.x is private range)
- ❌ `http://169.254.169.254/metadata` → **BLOCKED** (cloud metadata service)
- ✅ `http://8.8.8.8` → **PASS** (8.8.8.8 is Google's public DNS, not private)
- ✅ `http://1.1.1.1` → **PASS** (1.1.1.1 is Cloudflare's public DNS, not private)

**Why:** Private IP addresses are used for internal networks. Attackers can't access them directly, but the MCP server can, so we block them.

### Step 5: Check 4 - Domain Whitelist (Optional)

**What it checks:** If a whitelist is configured, is the domain in the whitelist?

**How it works:**
- If `allowed_domains` is set (not None/empty), only domains in the whitelist are allowed
- If `allowed_domains` is None/empty, all public domains are allowed (default)

**Examples (with whitelist = ["example.com"]):**
- ✅ `http://example.com` → **PASS** (in whitelist)
- ✅ `http://api.example.com` → **PASS** (subdomain of whitelisted domain)
- ❌ `http://other.com` → **BLOCKED** (not in whitelist)

**Examples (without whitelist - default):**
- ✅ `http://example.com` → **PASS** (public domain)
- ✅ `http://google.com` → **PASS** (public domain)
- ✅ `http://any-public-domain.com` → **PASS** (public domain)

**Why:** Whitelisting provides extra security by only allowing specific trusted domains.

## Real Examples from the Demo

### Example 1: Internal Service Attack (BLOCKED)
```
URL: http://127.0.0.1:8080/admin/config

Step 1: Parse
  Protocol: http ✅
  Hostname: 127.0.0.1
  Port: 8080

Step 2: Check Protocol
  http is not in blocked list ✅

Step 3: Check Hostname
  127.0.0.1 is in blocked hostnames list ❌
  → BLOCKED: "Blocked hostname '127.0.0.1' (localhost/internal)"
```

### Example 2: File Protocol Attack (BLOCKED)
```
URL: file:///cis_project/mcp_security_project/server/mcp_secrets.json

Step 1: Parse
  Protocol: file
  Hostname: (empty)
  Port: (none)

Step 2: Check Protocol
  file is in blocked protocols list ❌
  → BLOCKED: "Blocked protocol 'file' is not allowed"
```

### Example 3: Safe External URL (ALLOWED)
```
URL: https://www.example.com

Step 1: Parse
  Protocol: https ✅
  Hostname: www.example.com
  Port: (default 443)

Step 2: Check Protocol
  https is not in blocked list ✅

Step 3: Check Hostname
  www.example.com is not in blocked hostnames ✅

Step 4: Check Private IP
  www.example.com is not an IP address (it's a domain name)
  → Need to resolve DNS, but we don't do that in basic check
  → Since it's not a direct IP, we check if it's a blocked hostname
  → It's not, so ✅

Step 5: Check Whitelist
  No whitelist configured (default)
  → ✅

→ ALLOWED: "URL is safe and allowed"
```

## The Decision Flow

```
┌─────────────────┐
│  URL Request    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Parse URL      │
│  (protocol,     │
│   hostname,     │
│   port)         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      YES    ┌──────────────┐
│ Protocol        │─────────────▶│   BLOCKED    │
│ blocked?        │              │  (file://)   │
└────────┬────────┘              └──────────────┘
         │ NO
         ▼
┌─────────────────┐      YES    ┌──────────────┐
│ Hostname        │─────────────▶│   BLOCKED    │
│ blocked?        │              │ (localhost)  │
└────────┬────────┘              └──────────────┘
         │ NO
         ▼
┌─────────────────┐      YES    ┌──────────────┐
│ Private IP?     │─────────────▶│   BLOCKED    │
│                 │              │ (10.x, etc.) │
└────────┬────────┘              └──────────────┘
         │ NO
         ▼
┌─────────────────┐      NO     ┌──────────────┐
│ Whitelist       │─────────────▶│   BLOCKED    │
│ enabled &       │              │ (not in list)│
│ in whitelist?   │              └──────────────┘
└────────┬────────┘
         │ YES (or no whitelist)
         ▼
┌─────────────────┐
│   ALLOWED ✅    │
└─────────────────┘
```

## Key Points

1. **Order matters**: Checks are done in a specific order, and the first match blocks the URL
2. **Fail-safe**: If any check fails, the URL is blocked (better safe than sorry)
3. **Public domains allowed**: By default, all public domains are allowed (unless whitelist is set)
4. **Private/internal blocked**: All private IPs, localhost, and file:// are always blocked
5. **No DNS resolution**: The validator checks the URL as-is, it doesn't resolve DNS (this is a limitation but also a feature - it's faster and prevents DNS rebinding attacks during validation)

## Why This Works

The protection works because:
- **Attackers can't access internal resources directly** - They can't reach `127.0.0.1:8080` from outside
- **MCP server CAN access internal resources** - It's running on the same machine/network
- **SSRF attack tries to trick MCP** - By asking it to fetch `127.0.0.1:8080`, which the attacker can't reach
- **Protection blocks internal URLs** - So MCP never fetches them, preventing the attack

## Limitations & Future Enhancements

1. **DNS Rebinding**: Currently doesn't resolve DNS to check if a domain resolves to a private IP. This could be added.
2. **Redirects**: Validates initial URL but not redirects. The HTTP client should be configured to not follow redirects to private IPs.
3. **IPv6**: Basic IPv6 support exists but could be enhanced.

