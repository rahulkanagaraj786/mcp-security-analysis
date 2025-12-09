"""
XSS Relay Service

A public relay server that accepts a URL parameter and asks the MCP to fetch it.
The service fetches content from external sources (like the XSS service on port 8003)
and returns it to the user. If the content contains XSS payloads and is not sanitized,
it demonstrates the Backward XSS vulnerability.

Why the MCP is vulnerable:
The MCP server fetches content from external services and returns it without sanitization.
If an external service (like the XSS service) returns malicious HTML/JavaScript, the MCP
forwards it to the user, allowing XSS attacks to execute in the user's browser.

Port: 8004
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

app = FastAPI(title="XSS Relay Service", description="Public relay for Backward XSS attacks")

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
    print(f"[XSS Relay] {timestamp} - {request.method} {request.url.path} from {log_entry['client']}")
    
    response = await call_next(request)
    return response


@app.get("/")
async def root():
    """
    Root endpoint - explain the service
    
    This service contains NO malicious content. It's just a relay.
    The malicious content comes from the XSS service (port 8003).
    """
    return {
        "service": "XSS Relay Service",
        "description": "Public relay that forwards URL fetch requests to MCP server",
        "note": "This service contains NO malicious content. The XSS payloads come from the XSS service (port 8003).",
        "endpoint": "/fetch?url=<URL_TO_FETCH>",
        "examples": {
            "xss_page": "/fetch?url=http://127.0.0.1:8003/page (HTML with script tags)",
            "xss_widget": "/fetch?url=http://127.0.0.1:8003/widget (HTML with event handlers)",
            "xss_embed": "/fetch?url=http://127.0.0.1:8003/embed (HTML with inline handlers)",
            "xss_marker": "/fetch?url=http://127.0.0.1:8003/marker (Obvious XSS marker)"
        },
        "attack_flow": {
            "step1": "User requests content from XSS service via relay",
            "step2": "Relay service asks MCP server to fetch from XSS service",
            "step3": "MCP server fetches HTML/JSON with XSS payloads",
            "step4": "MCP returns unsanitized content to relay",
            "step5": "Relay returns unsanitized content to user",
            "step6": "XSS payloads execute in user's browser (if not sanitized)"
        },
        "warning": "This relay service contains no malicious content. The XSS payloads come from the XSS service (port 8003)."
    }


async def get_mcp_client():
    """Get or create MCP client connection"""
    global mcp_client
    
    async with mcp_client_lock:
        if mcp_client is None:
            print("[XSS Relay] Initializing MCP client connection...")
            
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
                    "stdio_context": stdio_context,
                    "stdio_transport": stdio_transport,
                    "session_context": session_context
                }
                
                print("[XSS Relay] MCP client connected successfully")
            except Exception as e:
                print(f"[XSS Relay] ERROR: Failed to connect to MCP server: {e}")
                raise
    
    return mcp_client


@app.get("/fetch")
async def fetch_url(url: str = Query(..., description="URL to fetch via MCP")):
    """
    Relay endpoint that asks MCP to fetch a URL
    
    This service has NO malicious content - it just forwards the URL to MCP.
    The attack works because MCP returns unsanitized content from external services.
    """
    print(f"[XSS Relay] Received request to fetch: {url}")
    
    try:
        # Get MCP client connection
        client = await get_mcp_client()
        session = client["session"]
        
        # Call MCP's http_get tool
        print(f"[XSS Relay] Calling MCP http_get tool with URL: {url}")
        result = await session.call_tool("http_get", {"url": url})
        
        # Parse result
        if result.content:
            content_text = result.content[0].text if result.content else ""
            try:
                mcp_result = json.loads(content_text)
                print(f"[XSS Relay] [OK] MCP fetch successful")
                
                # Extract content from MCP result
                content = mcp_result.get("content", "")
                status_code = mcp_result.get("status_code", 200)
                
                return {
                    "status": "success",
                    "relay_service": "XSS Relay (no malicious content)",
                    "requested_url": url,
                    "mcp_result": mcp_result,
                    "content": content,  # This may contain XSS payloads if not sanitized
                    "status_code": status_code,
                    "note": "This relay service contains no malicious content. The XSS payloads come from the fetched URL. If content is not sanitized, XSS attacks can execute."
                }
            except json.JSONDecodeError:
                return {
                    "status": "success",
                    "relay_service": "XSS Relay (no malicious content)",
                    "requested_url": url,
                    "mcp_result": {"raw": content_text},
                    "content": content_text,  # Raw content may contain XSS
                    "note": "This relay service contains no malicious content. The XSS payloads come from the fetched URL."
                }
        else:
            return {
                "status": "error",
                "message": "MCP returned no content",
                "requested_url": url
            }
            
    except Exception as e:
        print(f"[XSS Relay] ERROR: {e}")
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


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  XSS Relay Service - Backward XSS Attack Relay")
    print("="*70)
    print("  Port: 8004")
    print("  Purpose: Relay service that forwards URL fetch requests to MCP")
    print("  Note: This service contains NO malicious content")
    print("  Malicious content comes from XSS service (port 8003)")
    print("="*70)
    print("\n  Endpoints:")
    print("    - GET / (service info)")
    print("    - GET /fetch?url=<URL> (fetch URL via MCP)")
    print("    - GET /logs (request logs)")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8004, log_level="info")

