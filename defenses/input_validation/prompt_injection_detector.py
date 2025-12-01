"""
Prompt Injection Detector for Tool Calls

This module detects potential prompt injection attacks by analyzing
tool calls from the LLM before they reach the MCP server.

It identifies suspicious patterns such as:
- Information disclosure tools being called
- Unusual tool usage patterns
- Tools that could reveal sensitive system information
- Path traversal attacks in file operations
"""

from typing import Dict, Any, List, Tuple, Optional
import json
from pathlib import Path

# Import path sanitizer for file operation validation
from .path_sanitizer import PathSanitizer, create_path_sanitizer


class PromptInjectionDetector:
    """
    Detects potential prompt injection attacks in tool calls.
    
    Analyzes tool calls from the LLM to identify suspicious patterns
    that might indicate a prompt injection attack.
    """
    
    # Tools that reveal sensitive information (high risk for prompt injection)
    INFORMATION_DISCLOSURE_TOOLS = [
        "get_stats",      # Reveals storage statistics
        "get_profile",    # Could reveal user data
        "get_note",       # Could reveal cached data
        "read_file",      # Could read sensitive files
    ]
    
    # Tools that modify data (medium risk)
    DATA_MODIFICATION_TOOLS = [
        "update_profile",
        "write_file",
        "save_note",
    ]
    
    def __init__(self, strict_mode: bool = True, base_directory: str = "files"):
        """
        Initialize the detector.
        
        Args:
            strict_mode: If True, blocks information disclosure tools.
                        If False, only logs warnings.
            base_directory: Base directory for file operations (for path sanitization)
        """
        self.strict_mode = strict_mode
        self.blocked_calls = []
        self.warnings = []
        
        # Initialize path sanitizer for file operations
        self.path_sanitizer = create_path_sanitizer(base_directory, strict_mode)
    
    def is_information_disclosure_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is an information disclosure tool.
        
        Args:
            tool_name: Name of the tool being called
            
        Returns:
            True if the tool reveals sensitive information
        """
        return tool_name in self.INFORMATION_DISCLOSURE_TOOLS
    
    def is_data_modification_tool(self, tool_name: str) -> bool:
        """
        Check if a tool modifies data.
        
        Args:
            tool_name: Name of the tool being called
            
        Returns:
            True if the tool modifies data
        """
        return tool_name in self.DATA_MODIFICATION_TOOLS
    
    def analyze_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Analyze a tool call for potential prompt injection.
        
        Args:
            tool_name: Name of the tool being called
            arguments: Arguments passed to the tool
            
        Returns:
            Tuple of (is_safe, reason)
            - is_safe: True if the tool call is safe, False if suspicious
            - reason: Explanation of why it's safe or suspicious
        """
        # Check for information disclosure tools
        if self.is_information_disclosure_tool(tool_name):
            if self.strict_mode:
                return False, f"Blocked: {tool_name} is an information disclosure tool that could reveal sensitive system information. This may indicate a prompt injection attack."
            else:
                self.warnings.append({
                    "tool": tool_name,
                    "reason": f"Warning: {tool_name} is an information disclosure tool",
                    "arguments": arguments
                })
                return True, f"Warning: {tool_name} is an information disclosure tool"
        
        # Check for suspicious arguments in data modification tools
        if self.is_data_modification_tool(tool_name):
            suspicious = self._check_suspicious_arguments(tool_name, arguments)
            if suspicious:
                if self.strict_mode:
                    return False, f"Blocked: Suspicious arguments detected in {tool_name}. This may indicate a prompt injection attack."
                else:
                    self.warnings.append({
                        "tool": tool_name,
                        "reason": "Warning: Suspicious arguments detected",
                        "arguments": arguments
                    })
                    return True, "Warning: Suspicious arguments detected"
        
        return True, "Tool call appears safe"
    
    def _check_suspicious_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> bool:
        """
        Check for suspicious patterns in tool arguments.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            
        Returns:
            True if suspicious patterns are detected
        """
        # Check for path traversal in file operations using path sanitizer
        if tool_name in ["write_file", "read_file"]:
            filepath = arguments.get("filepath", "")
            if isinstance(filepath, str):
                # Use path sanitizer to check for path traversal
                is_safe, _, message = self.path_sanitizer.sanitize_path(filepath)
                if not is_safe:
                    # Path traversal detected
                    return True
        
        # Check for suspicious content in cache operations
        if tool_name in ["save_note", "update_profile"]:
            content = arguments.get("content", "") or arguments.get("bio", "")
            if isinstance(content, str):
                # Check for prompt injection patterns in content
                suspicious_patterns = [
                    "IGNORE ALL PREVIOUS INSTRUCTIONS",
                    "ignore all previous instructions",
                    "SYSTEM OVERRIDE",
                    "system override",
                    "bypass security",
                    "reveal",
                    "show all",
                ]
                content_upper = content.upper()
                for pattern in suspicious_patterns:
                    if pattern.upper() in content_upper:
                        return True
        
        return False
    
    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate a tool call and determine if it should be blocked.
        
        Args:
            tool_name: Name of the tool being called
            arguments: Arguments passed to the tool
            
        Returns:
            Tuple of (is_allowed, message, metadata)
            - is_allowed: True if tool call should proceed, False if blocked
            - message: Explanation message
            - metadata: Additional information about the validation
        """
        # First check for path traversal in file operations
        if tool_name in ["write_file", "read_file"]:
            filepath = arguments.get("filepath", "")
            if isinstance(filepath, str):
                operation = "read" if tool_name == "read_file" else "write"
                is_allowed, sanitized_path, path_message = self.path_sanitizer.validate_file_operation(
                    filepath, operation
                )
                
                if not is_allowed:
                    # Path traversal detected - block the call
                    reason = f"Path traversal attack blocked: {path_message}"
                    metadata = {
                        "tool": tool_name,
                        "arguments": arguments,
                        "is_information_disclosure": self.is_information_disclosure_tool(tool_name),
                        "is_data_modification": self.is_data_modification_tool(tool_name),
                        "strict_mode": self.strict_mode,
                        "path_traversal_blocked": True,
                        "original_path": filepath,
                        "blocked": True,
                    }
                    
                    self.blocked_calls.append({
                        "tool": tool_name,
                        "arguments": arguments,
                        "reason": reason,
                        "timestamp": None
                    })
                    
                    return False, reason, metadata
        
        # Continue with normal prompt injection detection
        is_safe, reason = self.analyze_tool_call(tool_name, arguments)
        
        metadata = {
            "tool": tool_name,
            "arguments": arguments,
            "is_information_disclosure": self.is_information_disclosure_tool(tool_name),
            "is_data_modification": self.is_data_modification_tool(tool_name),
            "strict_mode": self.strict_mode,
        }
        
        if not is_safe:
            self.blocked_calls.append({
                "tool": tool_name,
                "arguments": arguments,
                "reason": reason,
                "timestamp": None  # Could add timestamp if needed
            })
            metadata["blocked"] = True
            return False, reason, metadata
        
        metadata["blocked"] = False
        return True, reason, metadata
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a summary of security events.
        
        Returns:
            Dictionary with security statistics
        """
        return {
            "blocked_calls": len(self.blocked_calls),
            "warnings": len(self.warnings),
            "blocked_tools": [call["tool"] for call in self.blocked_calls],
            "strict_mode": self.strict_mode,
        }
    
    def reset(self):
        """Reset the detector state (clear blocked calls and warnings)."""
        self.blocked_calls = []
        self.warnings = []

