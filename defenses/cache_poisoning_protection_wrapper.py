"""
Cache Poisoning Protection Wrapper

This wrapper sits between the LLM/client and the MCP server, intercepting
cache storage operations (update_profile, save_note) and validating content
to prevent cache poisoning attacks.

The wrapper validates content before allowing it to be stored in cache,
blocking:
- XSS payloads (script tags, event handlers, etc.)
- Prompt injection patterns
- SQL injection patterns
- Other malicious content

It also sanitizes content when retrieved from cache (get_profile, get_note)
to provide defense in depth.
"""

import json
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from defenses.input_validation.content_sanitizer import ContentSanitizer, create_content_sanitizer


class CachePoisoningProtectionWrapper:
    """
    Wrapper that protects against cache poisoning attacks by validating content.
    
    This wrapper intercepts cache storage operations (update_profile, save_note)
    and validates content before allowing it to be stored. It also sanitizes
    content when retrieved from cache (get_profile, get_note).
    
    It blocks:
    - XSS payloads
    - Prompt injection patterns
    - SQL injection patterns
    - Other malicious content
    """
    
    # Tools that store content in cache (need input validation)
    CACHE_STORAGE_TOOLS = [
        "update_profile",
        "save_note",
    ]
    
    # Tools that retrieve content from cache (need output sanitization)
    CACHE_RETRIEVAL_TOOLS = [
        "get_profile",
        "get_note",
    ]
    
    def __init__(
        self,
        base_mcp_client,
        strict_mode: bool = True,
        sanitize_output: bool = True
    ):
        """
        Initialize the cache poisoning protection wrapper.
        
        Args:
            base_mcp_client: The underlying MCP client to wrap
            strict_mode: If True, blocks malicious content. If False, only logs warnings.
            sanitize_output: If True, sanitizes content when retrieved from cache.
        """
        self.base_client = base_mcp_client
        self.sanitizer = create_content_sanitizer(strict_mode=strict_mode, sanitize_output=sanitize_output)
        self.strict_mode = strict_mode
        self.sanitize_output = sanitize_output
        self.blocked_count = 0
        self.allowed_count = 0
        self.sanitized_retrievals = 0
        
        print(f"[CachePoisoningProtectionWrapper] Initialized")
        print(f"[CachePoisoningProtectionWrapper] Cache poisoning protection enabled (strict_mode={strict_mode})")
        print(f"[CachePoisoningProtectionWrapper] Output sanitization: {sanitize_output}")
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on the MCP server with cache poisoning protection.
        
        This method intercepts cache storage operations, validates content,
        and either blocks them or passes them through. It also sanitizes
        content when retrieved from cache.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments for the tool
            
        Returns:
            Dictionary with tool result or error if blocked
        """
        # Intercept cache storage operations
        if tool_name in self.CACHE_STORAGE_TOOLS:
            # Extract content to validate
            content = arguments.get("bio", "") or arguments.get("content", "")
            
            if not content:
                # Empty content is allowed
                return await self.base_client.call_tool(tool_name, arguments)
            
            # Validate content
            is_allowed, message, metadata = self.sanitizer.validate_content(content)
            
            if not is_allowed:
                # Content is blocked
                self.blocked_count += 1
                print(f"\n[CACHE POISONING PROTECTION] [BLOCKED] Tool: {tool_name}")
                print(f"[CACHE POISONING PROTECTION] Reason: {message}")
                print(f"[CACHE POISONING PROTECTION] Detected threats: {metadata.get('threat_types', [])}")
                print(f"[CACHE POISONING PROTECTION] Patterns: {metadata.get('detected_patterns', [])[:3]}...")  # Show first 3
                
                return {
                    "error": "CACHE_POISONING_PROTECTION",
                    "message": message,
                    "tool": tool_name,
                    "blocked": True,
                    "protection_metadata": metadata,
                    "status": "blocked"
                }
            
            # Content is safe, but sanitize it before storing (defense in depth)
            if self.sanitize_output:
                sanitized_content, _, _, _ = self.sanitizer.sanitize_and_validate(content)
                # Update arguments with sanitized content
                if "bio" in arguments:
                    arguments["bio"] = sanitized_content
                if "content" in arguments:
                    arguments["content"] = sanitized_content
            
            # Content passed validation, allow the request
            self.allowed_count += 1
            if metadata.get("threat_types"):
                print(f"\n[CACHE POISONING PROTECTION] [WARNING] Tool: {tool_name}")
                print(f"[CACHE POISONING PROTECTION] {message}")
            else:
                print(f"\n[CACHE POISONING PROTECTION] [ALLOWED] Tool: {tool_name}")
        
        # For cache retrieval operations, sanitize output
        elif tool_name in self.CACHE_RETRIEVAL_TOOLS:
            # Call the tool first
            result = await self.base_client.call_tool(tool_name, arguments)
            
            # If output sanitization is enabled, sanitize the retrieved content
            if self.sanitize_output and result.get("status") == "success":
                data = result.get("data", {})
                if isinstance(data, dict):
                    # Sanitize bio or content fields
                    if "bio" in data and isinstance(data["bio"], str):
                        data["bio"] = self.sanitizer.sanitize_content(data["bio"])
                        self.sanitized_retrievals += 1
                    if "content" in data and isinstance(data["content"], str):
                        data["content"] = self.sanitizer.sanitize_content(data["content"])
                        self.sanitized_retrievals += 1
                    result["data"] = data
            
            return result
        
        # For non-cache tools, pass through
        return await self.base_client.call_tool(tool_name, arguments)
    
    def get_protection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about cache poisoning protection.
        
        Returns:
            Dictionary with protection statistics
        """
        sanitizer_stats = self.sanitizer.get_security_summary()
        return {
            "blocked_count": self.blocked_count,
            "allowed_count": self.allowed_count,
            "sanitized_retrievals": self.sanitized_retrievals,
            "strict_mode": self.strict_mode,
            "sanitize_output": self.sanitize_output,
            "detected_threats": sanitizer_stats["detected_threats"],
            "sanitized_count": sanitizer_stats["sanitized_count"],
        }
    
    async def cleanup(self):
        """Clean up the wrapper (pass through to base client)."""
        if hasattr(self.base_client, 'cleanup'):
            await self.base_client.cleanup()


def create_cache_poisoning_protection_wrapper(
    base_mcp_client,
    strict_mode: bool = True,
    sanitize_output: bool = True
) -> CachePoisoningProtectionWrapper:
    """
    Create a cache poisoning protection wrapper.
    
    Args:
        base_mcp_client: The underlying MCP client to wrap
        strict_mode: If True, blocks malicious content. If False, only logs warnings.
        sanitize_output: If True, sanitizes content when retrieved from cache.
        
    Returns:
        CachePoisoningProtectionWrapper instance
    """
    return CachePoisoningProtectionWrapper(
        base_mcp_client,
        strict_mode=strict_mode,
        sanitize_output=sanitize_output
    )

