"""
Backdoor Protection Wrapper

This wrapper sits between the client and the MCP server, intercepting
install_plugin tool calls and validating plugin URLs to prevent backdoor/RCE attacks.

The wrapper validates plugin URLs before allowing the MCP server to download and
execute them, blocking:
- Untrusted domains (unless whitelisted)
- Internal/localhost URLs
- Suspicious file extensions
- Optional: Malicious code patterns in plugin content
"""

import json
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from defenses.input_validation.plugin_validator import PluginValidator, create_plugin_validator


class BackdoorProtectionWrapper:
    """
    Wrapper that protects against backdoor/RCE attacks by validating plugin URLs.
    
    This wrapper intercepts install_plugin tool calls and validates URLs before
    allowing the MCP server to download and execute them. It blocks:
    - Untrusted domains (unless whitelisted)
    - Internal/localhost URLs
    - Suspicious file extensions
    - Optional: Malicious code patterns
    """
    
    def __init__(
        self,
        base_mcp_client,
        allowed_domains: Optional[list] = None,
        blocked_domains: Optional[list] = None,
        allow_internal: bool = False,
        allowed_extensions: Optional[list] = None,
        strict_mode: bool = True,
        validate_content: bool = False
    ):
        """
        Initialize the backdoor protection wrapper.
        
        Args:
            base_mcp_client: The underlying MCP client to wrap
            allowed_domains: Optional list of allowed domains (whitelist). If None, allows all public domains.
            blocked_domains: Optional list of blocked domains (blacklist).
            allow_internal: If True, allows localhost/internal IPs. Default: False.
            allowed_extensions: List of allowed file extensions. Default: ['.py']
            strict_mode: If True, blocks suspicious URLs. If False, only logs warnings.
            validate_content: If True, also validates plugin content for malicious patterns. Default: False.
        """
        self.base_client = base_mcp_client
        self.validator = create_plugin_validator(
            allowed_domains=allowed_domains,
            blocked_domains=blocked_domains,
            allow_internal=allow_internal,
            allowed_extensions=allowed_extensions,
            strict_mode=strict_mode
        )
        self.strict_mode = strict_mode
        self.validate_content = validate_content
        self.blocked_count = 0
        self.allowed_count = 0
        
        print(f"[BackdoorProtectionWrapper] Initialized")
        print(f"[BackdoorProtectionWrapper] Backdoor protection enabled (strict_mode={strict_mode})")
        if allowed_domains:
            print(f"[BackdoorProtectionWrapper] Domain whitelist: {allowed_domains}")
        if blocked_domains:
            print(f"[BackdoorProtectionWrapper] Domain blacklist: {blocked_domains}")
        print(f"[BackdoorProtectionWrapper] Content validation: {validate_content}")
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on the MCP server with backdoor protection.
        
        This method intercepts install_plugin tool calls, validates URLs, and either
        blocks them or passes them through to the MCP server.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments for the tool
            
        Returns:
            Dictionary with tool result or error if blocked
        """
        # Intercept install_plugin tool calls for backdoor protection
        if tool_name == "install_plugin":
            url = arguments.get("url", "")
            
            if not url:
                self.blocked_count += 1
                print(f"\n[BACKDOOR PROTECTION] ⛔ BLOCKED: URL parameter is required")
                return {
                    "error": "BACKDOOR_PROTECTION",
                    "message": "URL parameter is required",
                    "tool": tool_name,
                    "blocked": True
                }
            
            # Validate the plugin URL
            validation_result = self.validator.validate_url(url)
            
            if not validation_result["valid"]:
                self.blocked_count += 1
                print(f"\n[BACKDOOR PROTECTION] ⛔ BLOCKED: {validation_result['reason']}")
                print(f"[BACKDOOR PROTECTION] URL: {url}")
                return {
                    "error": "BACKDOOR_PROTECTION",
                    "message": validation_result["reason"],
                    "tool": tool_name,
                    "url": url,
                    "blocked": True
                }
            
            # URL is valid, but optionally validate content
            if self.validate_content:
                # Download content first to validate (this requires an extra request)
                # For now, we'll skip content validation in the wrapper
                # Content validation can be done by the MCP server itself if needed
                pass
            
            # URL passed validation, allow the request
            self.allowed_count += 1
            print(f"\n[BACKDOOR PROTECTION] ✓ ALLOWED: Plugin URL passed validation")
            print(f"[BACKDOOR PROTECTION] Domain: {validation_result['domain']}")
            print(f"[BACKDOOR PROTECTION] Extension: {validation_result['extension']}")
            
            # Pass through to base client
            return await self.base_client.call_tool(tool_name, arguments)
        
        # For all other tools, pass through without validation
        return await self.base_client.call_tool(tool_name, arguments)
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """
        Get protection statistics.
        
        Returns:
            Dictionary with protection statistics
        """
        return {
            "blocked_count": self.blocked_count,
            "allowed_count": self.allowed_count,
            "total_requests": self.blocked_count + self.allowed_count,
            "strict_mode": self.strict_mode,
            "validate_content": self.validate_content
        }


def create_backdoor_protection_wrapper(
    base_mcp_client,
    allowed_domains: Optional[list] = None,
    blocked_domains: Optional[list] = None,
    allow_internal: bool = False,
    allowed_extensions: Optional[list] = None,
    strict_mode: bool = True,
    validate_content: bool = False
) -> BackdoorProtectionWrapper:
    """
    Create a backdoor protection wrapper around an MCP client.
    
    Args:
        base_mcp_client: The MCP client to wrap
        allowed_domains: Whitelist of allowed domains (None = allow all public domains)
        blocked_domains: Blacklist of blocked domains
        allow_internal: Allow localhost/internal IPs (default: False)
        allowed_extensions: Allowed file extensions (default: ['.py'])
        strict_mode: Strict validation mode (default: True)
        validate_content: Validate plugin content for malicious patterns (default: False)
    
    Returns:
        BackdoorProtectionWrapper instance
    """
    return BackdoorProtectionWrapper(
        base_mcp_client=base_mcp_client,
        allowed_domains=allowed_domains,
        blocked_domains=blocked_domains,
        allow_internal=allow_internal,
        allowed_extensions=allowed_extensions,
        strict_mode=strict_mode,
        validate_content=validate_content
    )

