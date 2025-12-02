"""
SSRF Protection Wrapper

This wrapper sits between the external service (relay) and the MCP server,
intercepting http_get tool calls and validating URLs to prevent SSRF attacks.

The wrapper validates URLs before allowing the MCP server to fetch them,
blocking internal/localhost URLs and file:// protocol.
"""

import json
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from defenses.input_validation.ssrf_url_validator import SSRFURLValidator, create_ssrf_url_validator


class SSRFProtectionWrapper:
    """
    Wrapper that protects against SSRF attacks by validating URLs.
    
    This wrapper intercepts http_get tool calls and validates URLs before
    allowing the MCP server to fetch them. It blocks:
    - localhost/internal IP addresses
    - file:// protocol
    - Private IP ranges
    - Internal/private domains
    """
    
    def __init__(self, base_mcp_client, strict_mode: bool = True, allowed_domains: Optional[list] = None):
        """
        Initialize the SSRF protection wrapper.
        
        Args:
            base_mcp_client: The underlying MCP client to wrap
            strict_mode: If True, blocks suspicious URLs. If False, only logs warnings.
            allowed_domains: Optional list of allowed domains (whitelist)
        """
        self.base_client = base_mcp_client
        self.validator = create_ssrf_url_validator(strict_mode=strict_mode, allowed_domains=allowed_domains)
        self.strict_mode = strict_mode
        self.blocked_count = 0
        self.allowed_count = 0
        
        print(f"[SSRFProtectionWrapper] Initialized")
        print(f"[SSRFProtectionWrapper] SSRF protection enabled (strict_mode={strict_mode})")
        if allowed_domains:
            print(f"[SSRFProtectionWrapper] Domain whitelist: {allowed_domains}")
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on the MCP server with SSRF protection.
        
        This method intercepts http_get tool calls, validates URLs, and either
        blocks them or passes them through to the MCP server.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments for the tool
            
        Returns:
            Dictionary with tool result or error if blocked
        """
        # Intercept http_get tool calls for SSRF protection
        if tool_name == "http_get":
            url = arguments.get("url", "")
            
            if not url:
                self.blocked_count += 1
                print(f"\n[SSRF PROTECTION] ⛔ BLOCKED: URL parameter is required")
                return {
                    "error": "SSRF_PROTECTION",
                    "message": "URL parameter is required",
                    "tool": tool_name,
                    "blocked": True
                }
            
            # Validate the URL
            is_allowed, message, metadata = self.validator.validate_url(url)
            
            if not is_allowed:
                # URL is blocked
                self.blocked_count += 1
                print(f"\n[SSRF PROTECTION] ⛔ BLOCKED URL: {url}")
                print(f"[SSRF PROTECTION] Reason: {message}")
                print(f"[SSRF PROTECTION] Blocked reasons: {metadata.get('blocked_reasons', [])}")
                
                return {
                    "error": "SSRF_PROTECTION",
                    "message": message,
                    "tool": tool_name,
                    "url": url,
                    "blocked": True,
                    "protection_metadata": metadata,
                    "status": "blocked"
                }
            
            # URL is safe, log and allow
            self.allowed_count += 1
            print(f"\n[SSRF PROTECTION] ✓ ALLOWED URL: {url}")
            print(f"[SSRF PROTECTION] {message}")
        
        # For non-http_get tools, or if http_get URL is validated, pass through
        try:
            result = await self.base_client.call_tool(tool_name, arguments)
            
            # Add protection metadata to result
            if isinstance(result, dict) and tool_name == "http_get":
                result["ssrf_protected"] = True
                result["url_validated"] = True
            
            return result
        except Exception as e:
            return {
                "error": str(e),
                "tool": tool_name,
                "ssrf_protected": True
            }
    
    async def initialize(self):
        """Initialize the underlying MCP client."""
        if hasattr(self.base_client, 'initialize'):
            await self.base_client.initialize()
    
    async def cleanup(self):
        """Clean up the underlying MCP client."""
        if hasattr(self.base_client, 'cleanup'):
            await self.base_client.cleanup()
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about SSRF protection.
        
        Returns:
            Dictionary with protection statistics
        """
        return {
            "blocked_count": self.blocked_count,
            "allowed_count": self.allowed_count,
            "total_requests": self.blocked_count + self.allowed_count,
            "blocked_attempts": self.validator.get_blocked_attempts()
        }
    
    def reset_stats(self):
        """Reset protection statistics."""
        self.blocked_count = 0
        self.allowed_count = 0
        self.validator.reset()


def create_ssrf_protection_wrapper(base_client, strict_mode: bool = True, allowed_domains: Optional[list] = None) -> SSRFProtectionWrapper:
    """
    Create an SSRF protection wrapper around an MCP client.
    
    Args:
        base_client: The MCP client to wrap
        strict_mode: If True, blocks suspicious URLs
        allowed_domains: Optional list of allowed domains (whitelist)
        
    Returns:
        SSRFProtectionWrapper instance
    """
    return SSRFProtectionWrapper(base_client, strict_mode=strict_mode, allowed_domains=allowed_domains)

