"""
SSRF Attack Service - Mock Internal Metadata API

This service simulates an internal-only API that should only be accessible
from within the network. It returns sensitive data that attackers can access
via SSRF if the MCP server fetches URLs without validation.

Port: 8001
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from datetime import datetime
import json

app = FastAPI(title="Mock Internal Metadata API", description="SSRF Attack Target")

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
    print(f"[SSRF Service] {timestamp} - {request.method} {request.url.path} from {log_entry['client']}")
    
    response = await call_next(request)
    return response


@app.get("/")
async def root():
    """Root endpoint - list available endpoints"""
    return {
        "service": "Mock Internal Metadata API",
        "description": "This service simulates internal-only endpoints",
        "endpoints": {
            "/admin/config": "Admin configuration (sensitive)",
            "/internal/keys": "Internal API keys and secrets",
            "/metadata/instance": "Cloud instance metadata",
            "/health": "Internal health status",
            "/logs": "Request logs (for demonstration)"
        },
        "warning": "This service should only be accessible from internal network"
    }


@app.get("/admin/config")
async def admin_config():
    """
    Admin configuration endpoint
    
    Returns sensitive admin configuration that should only be accessible
    from internal network. This demonstrates SSRF vulnerability when MCP
    fetches this URL without validation.
    """
    return {
        "status": "success",
        "data": {
            "admin_password": "super_secret_admin_password_123",
            "database_url": "postgresql://admin:secret@internal-db:5432/production",
            "redis_url": "redis://internal-redis:6379/0",
            "jwt_secret": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "encryption_key": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            "api_rate_limit": 10000,
            "debug_mode": False,
            "internal_network_only": True
        },
        "message": "SSRF_SUCCESS: Admin config retrieved via internal network"
    }


@app.get("/internal/keys")
async def internal_keys():
    """
    Internal API keys endpoint
    
    Returns fake API keys and secrets that should never be exposed.
    Demonstrates SSRF when MCP fetches this without URL validation.
    """
    return {
        "status": "success",
        "data": {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "slack_webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            "stripe_secret_key": "sk_live_51H1234567890abcdefghijklmnopqrstuvwxyz",
            "mongodb_connection_string": "mongodb://admin:password@internal-mongo:27017/admin",
            "s3_bucket": "internal-secrets-bucket",
            "s3_access_key": "AKIAEXAMPLE123456"
        },
        "message": "SSRF_SUCCESS: Internal keys retrieved via internal network"
    }


@app.get("/metadata/instance")
async def instance_metadata():
    """
    Cloud instance metadata endpoint
    
    Simulates cloud provider metadata service (like AWS IMDS, GCP metadata server).
    These services are typically only accessible from within the instance.
    """
    return {
        "status": "success",
        "data": {
            "instance_id": "i-1234567890abcdef0",
            "instance_type": "t3.large",
            "availability_zone": "us-east-1a",
            "private_ip": "10.0.1.42",
            "public_ip": "54.123.45.67",
            "iam_role": "arn:aws:iam::123456789012:role/internal-service-role",
            "security_groups": ["sg-internal-only"],
            "user_data": "#!/bin/bash\necho 'Instance initialization script'",
            "tags": {
                "Environment": "production",
                "Service": "internal-api",
                "Owner": "devops-team"
            }
        },
        "message": "SSRF_SUCCESS: Instance metadata retrieved via internal network"
    }


@app.get("/health")
async def health():
    """
    Internal health check endpoint
    
    Returns internal system health information that should not be
    exposed to external users.
    """
    return {
        "status": "healthy",
        "data": {
            "uptime_seconds": 86400,
            "memory_usage_percent": 45.2,
            "cpu_usage_percent": 12.8,
            "active_connections": 234,
            "database_status": "connected",
            "cache_status": "operational",
            "internal_services": {
                "auth_service": "healthy",
                "db_service": "healthy",
                "cache_service": "healthy"
            }
        },
        "message": "SSRF_SUCCESS: Internal health data retrieved"
    }


@app.get("/logs")
async def get_logs():
    """
    Request logs endpoint
    
    Returns all requests made to this service. Useful for demonstrating
    that the MCP server accessed this service.
    """
    return {
        "status": "success",
        "total_requests": len(request_log),
        "logs": request_log[-50:]  # Last 50 requests
    }


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  SSRF Attack Service - Mock Internal Metadata API")
    print("="*70)
    print("  Port: 8001")
    print("  Purpose: Simulate internal-only API for SSRF attacks")
    print("  Endpoints:")
    print("    - GET /admin/config")
    print("    - GET /internal/keys")
    print("    - GET /metadata/instance")
    print("    - GET /health")
    print("    - GET /logs")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")

