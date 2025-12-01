"""
Secure MCP Client Wrapper

This module provides a secure wrapper around the MCP client that validates
tool calls before they reach the MCP server. It protects against prompt
injection attacks by detecting and blocking suspicious tool calls.

The wrapper sits between the LLM and the MCP server, intercepting tool
calls and validating them using the prompt injection detector.
"""

import json
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from defenses.input_validation.prompt_injection_detector import PromptInjectionDetector


class SecureMCPClient:
    """
    Secure MCP client wrapper that validates tool calls.
    
    This wrapper intercepts tool calls from the LLM and validates them
    using the prompt injection detector before passing them to the MCP server.
    """
    
    def __init__(self, base_mcp_client, strict_mode: bool = True):
        """
        Initialize the secure MCP client wrapper.
        
        Args:
            base_mcp_client: The underlying MCP client to wrap
            strict_mode: If True, blocks suspicious tool calls.
                        If False, only logs warnings.
        """
        self.base_client = base_mcp_client
        self.detector = PromptInjectionDetector(strict_mode=strict_mode)
        self.strict_mode = strict_mode
        
        print(f"[SecureMCPClient] Initialized with strict_mode={strict_mode}")
        print(f"[SecureMCPClient] Prompt injection protection enabled")
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on the MCP server with security validation.
        
        This method intercepts tool calls, validates them for prompt injection
        attacks, and either blocks them or passes them through to the MCP server.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments for the tool
            
        Returns:
            Dictionary with tool result or error if blocked
        """
        # Validate the tool call
        is_allowed, message, metadata = self.detector.validate_tool_call(tool_name, arguments)
        
        if not is_allowed:
            # Tool call is blocked
            print(f"\n[SECURITY] ⛔ BLOCKED tool call: {tool_name}")
            print(f"[SECURITY] Reason: {message}")
            print(f"[SECURITY] Arguments: {json.dumps(arguments, indent=2)}")
            
            return {
                "error": "SECURITY_BLOCKED",
                "message": message,
                "tool": tool_name,
                "security_metadata": metadata,
                "blocked": True
            }
        
        # Tool call is allowed, pass through to MCP server
        if self.detector.warnings:
            print(f"\n[SECURITY] ⚠️  WARNING for tool call: {tool_name}")
            print(f"[SECURITY] {message}")
        
        # Call the underlying MCP client
        try:
            result = await self.base_client.call_tool(tool_name, arguments)
            
            # Add security metadata to result
            if isinstance(result, dict):
                result["security_validated"] = True
                result["security_message"] = message
            
            return result
        except Exception as e:
            return {
                "error": str(e),
                "tool": tool_name,
                "security_validated": True
            }
    
    async def initialize(self):
        """Initialize the underlying MCP client."""
        if hasattr(self.base_client, 'initialize'):
            await self.base_client.initialize()
    
    async def cleanup(self):
        """Clean up the underlying MCP client."""
        if hasattr(self.base_client, 'cleanup'):
            await self.base_client.cleanup()
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a summary of security events.
        
        Returns:
            Dictionary with security statistics
        """
        return self.detector.get_security_summary()
    
    def reset_security_stats(self):
        """Reset security statistics."""
        self.detector.reset()


def create_secure_mcp_client_wrapper(base_client, strict_mode: bool = True) -> SecureMCPClient:
    """
    Create a secure wrapper around an existing MCP client.
    
    Args:
        base_client: The MCP client to wrap
        strict_mode: If True, blocks suspicious tool calls
        
    Returns:
        SecureMCPClient instance
    """
    return SecureMCPClient(base_client, strict_mode=strict_mode)

