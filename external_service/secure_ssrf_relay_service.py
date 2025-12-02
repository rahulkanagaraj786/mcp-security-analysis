"""
Secure SSRF Relay Service (Protected)

This is the protected version of the SSRF relay service that uses the SSRF protection wrapper
to validate URLs before allowing the MCP server to fetch them.

The wrapper sits between the relay service and the MCP server, intercepting http_get tool calls
and blocking internal/localhost URLs and file:// protocol to prevent SSRF attacks.

Port: 8005 (different from vulnerable version on 8001)
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
from defenses.ssrf_protection_wrapper import SSRFProtectionWrapper, create_ssrf_protection_wrapper


class MCPClientWrapper:
    """Wrapper to make MCP client session work with the protection wrapper"""
    
    def __init__(self, session, session_context, stdio_context):
        self.session = session
        self.session_context = session_context
        self.stdio_context = stdio_context
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool on the MCP server"""
        try:
            result = await self.session.call_tool(tool_name, arguments)
            if result.content:
                content_text = result.content[0].text if result.content else ""
                try:
                    return json.loads(content_text)
                except json.JSONDecodeError:
                    return {"raw": content_text}
            return {"status": "success"}
        except Exception as e:
            return {"error": str(e)}
    
    async def initialize(self):
        """Initialize (no-op for this wrapper)"""
        pass
    
    async def cleanup(self):
        """Cleanup (no-op for this wrapper)"""
        pass


app = FastAPI(title="Secure SSRF Relay Service", description="Protected relay service with SSRF protection")

# Track requests for logging/demonstration
request_log = []

# Global protected MCP client (initialized on startup)
protected_mcp_client = None
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
    print(f"[Secure SSRF Relay] {timestamp} - {request.method} {request.url.path} from {log_entry['client']}")
    
    response = await call_next(request)
    return response


@app.get("/")
async def root():
    """
    Root endpoint - explain the service
    
    This service uses SSRF protection wrapper to validate URLs.
    """
    return {
        "service": "Secure SSRF Relay Service (Protected)",
        "description": "Protected relay service with SSRF protection wrapper",
        "note": "This service uses SSRF protection wrapper to validate URLs before allowing MCP server to fetch them.",
        "endpoint": "/fetch?url=<URL_TO_FETCH>",
        "protection": {
            "enabled": True,
            "blocks": [
                "localhost/127.0.0.1 addresses",
                "Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)",
                "file:// protocol",
                "Internal/private domains",
                "Cloud metadata service IPs (169.254.169.254)"
            ]
        }
    }


async def get_protected_mcp_client():
    """Get or create protected MCP client connection"""
    global protected_mcp_client
    
    async with mcp_client_lock:
        if protected_mcp_client is None:
            print("[Secure SSRF Relay] Initializing protected MCP client connection...")
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
                
                # Create base client wrapper
                base_client = MCPClientWrapper(session, session_context, stdio_context)
                
                # Wrap with SSRF protection
                protected_mcp_client_wrapper = create_ssrf_protection_wrapper(
                    base_client,
                    strict_mode=True,
                    allowed_domains=None  # Allow all public domains, block only internal
                )
                
                await protected_mcp_client_wrapper.initialize()
                
                # Store both the wrapper and the underlying connections for cleanup
                protected_mcp_client = {
                    "wrapper": protected_mcp_client_wrapper,
                    "session_context": session_context,
                    "stdio_context": stdio_context
                }
                
                print("[Secure SSRF Relay] ✓ Protected MCP client connected (SSRF protection enabled)")
            except Exception as e:
                print(f"[Secure SSRF Relay] ERROR: Failed to connect to MCP server: {e}")
                raise
    
    return protected_mcp_client


@app.get("/fetch")
async def fetch_url(url: str = Query(..., description="URL to fetch via MCP")):
    """
    Relay endpoint that asks MCP to fetch a URL (with SSRF protection)
    
    This service uses SSRF protection wrapper to validate URLs before
    allowing the MCP server to fetch them.
    """
    print(f"[Secure SSRF Relay] Received request to fetch: {url}")
    
    try:
        # Get protected MCP client connection
        client_data = await get_protected_mcp_client()
        protected_client = client_data["wrapper"]
        
        # Call protected http_get tool (wrapper will validate URL)
        print(f"[Secure SSRF Relay] Calling protected MCP http_get tool with URL: {url}")
        result = await protected_client.call_tool("http_get", {"url": url})
        
        # Check if URL was blocked
        if result.get("blocked") or result.get("error") == "SSRF_PROTECTION":
            print(f"[Secure SSRF Relay] ⛔ URL blocked by SSRF protection")
            return {
                "status": "blocked",
                "message": result.get("message", "URL blocked by SSRF protection"),
                "requested_url": url,
                "protection": "SSRF protection wrapper blocked this URL",
                "blocked_reasons": result.get("protection_metadata", {}).get("blocked_reasons", [])
            }
        
        # Parse result
        if result.get("status") == "success" or "content" in result:
            print(f"[Secure SSRF Relay] ✓ URL validated and fetched successfully")
            return {
                "status": "success",
                "relay_service": "Secure SSRF Relay (Protected)",
                "mcp_result": result,
                "protection": "URL was validated by SSRF protection wrapper"
            }
        else:
            return {
                "status": "error",
                "message": result.get("error", "Unknown error"),
                "requested_url": url
            }
            
    except Exception as e:
        print(f"[Secure SSRF Relay] ERROR: {e}")
        return {
            "status": "error",
            "message": str(e),
            "requested_url": url,
            "note": "Failed to fetch URL via protected MCP server"
        }


@app.get("/protection/stats")
async def get_protection_stats():
    """Get SSRF protection statistics"""
    if protected_mcp_client and "wrapper" in protected_mcp_client:
        stats = protected_mcp_client["wrapper"].get_protection_stats()
        return {
            "status": "success",
            "protection_stats": stats
        }
    return {
        "status": "error",
        "message": "Protected MCP client not initialized"
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
    """Clean up protected MCP client on shutdown"""
    global protected_mcp_client
    if protected_mcp_client:
        try:
            # Cleanup wrapper
            if "wrapper" in protected_mcp_client:
                await protected_mcp_client["wrapper"].cleanup()
            # Cleanup underlying session
            if "session_context" in protected_mcp_client:
                await protected_mcp_client["session_context"].__aexit__(None, None, None)
            if "stdio_context" in protected_mcp_client:
                await protected_mcp_client["stdio_context"].__aexit__(None, None, None)
            print("[Secure SSRF Relay] Protected MCP client disconnected")
        except Exception as e:
            print(f"[Secure SSRF Relay] Error during shutdown: {e}")


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  Secure SSRF Relay Service - Protected Relay Server")
    print("="*70)
    print("  Port: 8005")
    print("  Purpose: Relay URL fetch requests to MCP server with SSRF protection")
    print("  Endpoint: GET /fetch?url=<URL>")
    print("  Protection: SSRF protection wrapper validates URLs before MCP fetches them")
    print("="*70 + "\n")
    
    # Run on 0.0.0.0 to be publicly accessible (for demonstration)
    uvicorn.run(app, host="0.0.0.0", port=8005, log_level="info")

