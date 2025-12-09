"""
Backward XSS Protection Wrapper

This wrapper sits between external services and the MCP server, intercepting
http_get tool responses and sanitizing HTML/JavaScript content to prevent
Backward XSS attacks.

The wrapper sanitizes content before it reaches users, blocking:
- <script> tags
- Event handlers (onclick, onerror, onload, etc.)
- JavaScript protocol (javascript:)
- Dangerous HTML tags (<iframe>, <object>, <embed>)
- Other XSS vectors

It sanitizes by:
- Stripping dangerous HTML tags
- Removing event handler attributes
- HTML-encoding content
- Converting < to &lt; and > to &gt;
"""

import json
import re
import html
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from defenses.input_validation.content_sanitizer import ContentSanitizer, create_content_sanitizer


class BackwardXSSProtectionWrapper:
    """
    Wrapper that protects against Backward XSS attacks by sanitizing responses.
    
    This wrapper intercepts http_get tool responses and sanitizes HTML/JavaScript
    content before it reaches users. It blocks:
    - <script> tags
    - Event handlers
    - JavaScript protocol
    - Dangerous HTML tags
    """
    
    def __init__(
        self,
        base_mcp_client,
        strict_mode: bool = True,
        sanitize_html: bool = True
    ):
        """
        Initialize the backward XSS protection wrapper.
        
        Args:
            base_mcp_client: The underlying MCP client to wrap
            strict_mode: If True, aggressively sanitizes content. If False, only logs warnings.
            sanitize_html: If True, strips HTML tags and encodes content. If False, only detects.
        """
        self.base_client = base_mcp_client
        self.sanitizer = create_content_sanitizer(strict_mode=strict_mode, sanitize_output=True)
        self.strict_mode = strict_mode
        self.sanitize_html = sanitize_html
        self.sanitized_count = 0
        self.blocked_count = 0
        
        print(f"[BackwardXSSProtectionWrapper] Initialized")
        print(f"[BackwardXSSProtectionWrapper] Backward XSS protection enabled (strict_mode={strict_mode})")
        print(f"[BackwardXSSProtectionWrapper] HTML sanitization: {sanitize_html}")
    
    def _sanitize_html_content(self, content: str) -> str:
        """
        Sanitize HTML content by stripping dangerous tags and encoding.
        
        Args:
            content: HTML content to sanitize
            
        Returns:
            Sanitized content
        """
        if not self.sanitize_html:
            return content
        
        # Remove script tags and their content
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.IGNORECASE | re.DOTALL)
        content = re.sub(r'<script[^>]*>', '', content, flags=re.IGNORECASE)
        
        # Remove event handlers (onclick, onerror, onload, etc.)
        content = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\s+on\w+\s*=\s*[^\s>]*', '', content, flags=re.IGNORECASE)
        
        # Remove javascript: protocol
        content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)
        
        # Remove dangerous tags
        dangerous_tags = ['iframe', 'object', 'embed', 'form', 'input', 'button']
        for tag in dangerous_tags:
            content = re.sub(rf'<{tag}[^>]*>.*?</{tag}>', '', content, flags=re.IGNORECASE | re.DOTALL)
            content = re.sub(rf'<{tag}[^>]*>', '', content, flags=re.IGNORECASE)
        
        # HTML-encode remaining content
        sanitized = html.escape(content)
        
        return sanitized
    
    def _detect_xss_in_content(self, content: str) -> tuple:
        """
        Detect XSS patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        
        # Check for script tags
        if re.search(r'<script[^>]*>', content, re.IGNORECASE):
            detected.append("script_tags")
        
        # Check for event handlers
        if re.search(r'\son\w+\s*=', content, re.IGNORECASE):
            detected.append("event_handlers")
        
        # Check for javascript: protocol
        if 'javascript:' in content.lower():
            detected.append("javascript_protocol")
        
        # Check for dangerous tags
        dangerous_tags = ['iframe', 'object', 'embed']
        for tag in dangerous_tags:
            if re.search(rf'<{tag}[^>]*>', content, re.IGNORECASE):
                detected.append(f"{tag}_tag")
        
        return len(detected) > 0, detected
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """
        Call a tool on the MCP server with backward XSS protection.
        
        This method intercepts http_get tool responses, sanitizes content,
        and returns sanitized content to prevent XSS attacks.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments for the tool
            
        Returns:
            Dictionary with tool result (sanitized if http_get)
        """
        # Call the underlying tool
        result = await self.base_client.call_tool(tool_name, arguments)
        
        # Intercept http_get responses for sanitization
        if tool_name == "http_get" and isinstance(result, dict):
            content = result.get("content", "")
            
            # Handle both string content (HTML) and dict content (JSON)
            content_to_sanitize = None
            content_path = None
            
            if isinstance(content, str) and content:
                # String content (HTML)
                content_to_sanitize = content
                content_path = "content"
            elif isinstance(content, dict):
                # JSON response - check content/body/data fields
                if "content" in content and isinstance(content["content"], str):
                    content_to_sanitize = content["content"]
                    content_path = "content.content"
                elif "body" in content and isinstance(content["body"], str):
                    content_to_sanitize = content["body"]
                    content_path = "content.body"
                elif "data" in content and isinstance(content["data"], dict):
                    data = content["data"]
                    if "body" in data and isinstance(data["body"], str):
                        content_to_sanitize = data["body"]
                        content_path = "content.data.body"
                    elif "content" in data and isinstance(data["content"], str):
                        content_to_sanitize = data["content"]
                        content_path = "content.data.content"
            
            if content_to_sanitize:
                # Detect XSS patterns
                is_malicious, detected_patterns = self._detect_xss_in_content(content_to_sanitize)
                
                if is_malicious:
                    print(f"\n[BACKWARD XSS PROTECTION] [WARNING] XSS patterns detected in response")
                    print(f"[BACKWARD XSS PROTECTION] Content path: {content_path}")
                    print(f"[BACKWARD XSS PROTECTION] Detected patterns: {', '.join(detected_patterns)}")
                    
                    # Sanitize the content
                    sanitized_content = self._sanitize_html_content(content_to_sanitize)
                    self.sanitized_count += 1
                    
                    # Update result with sanitized content
                    if content_path == "content":
                        result["content"] = sanitized_content
                    elif content_path == "content.content":
                        result["content"]["content"] = sanitized_content
                    elif content_path == "content.body":
                        result["content"]["body"] = sanitized_content
                    elif content_path == "content.data.body":
                        result["content"]["data"]["body"] = sanitized_content
                    elif content_path == "content.data.content":
                        result["content"]["data"]["content"] = sanitized_content
                    
                    result["original_content_length"] = len(content_to_sanitize)
                    result["sanitized_content_length"] = len(sanitized_content)
                    result["xss_protected"] = True
                    result["xss_patterns_detected"] = detected_patterns
                    result["sanitization_applied"] = True
                    
                    print(f"[BACKWARD XSS PROTECTION] [SANITIZED] Content sanitized")
                    print(f"[BACKWARD XSS PROTECTION] Original length: {len(content_to_sanitize)} bytes")
                    print(f"[BACKWARD XSS PROTECTION] Sanitized length: {len(sanitized_content)} bytes")
                else:
                    # No XSS detected, but still mark as protected
                    result["xss_protected"] = True
                    result["xss_patterns_detected"] = []
                    result["sanitization_applied"] = False
            else:
                # No content to sanitize, but mark as protected
                result["xss_protected"] = True
                result["xss_patterns_detected"] = []
                result["sanitization_applied"] = False
        
        return result
    
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
        Get statistics about backward XSS protection.
        
        Returns:
            Dictionary with protection statistics
        """
        return {
            "sanitized_count": self.sanitized_count,
            "blocked_count": self.blocked_count,
            "strict_mode": self.strict_mode,
            "sanitize_html": self.sanitize_html,
        }
    
    def reset_stats(self):
        """Reset protection statistics."""
        self.sanitized_count = 0
        self.blocked_count = 0


def create_backward_xss_protection_wrapper(
    base_client,
    strict_mode: bool = True,
    sanitize_html: bool = True
) -> BackwardXSSProtectionWrapper:
    """
    Create a backward XSS protection wrapper around an MCP client.
    
    Args:
        base_client: The MCP client to wrap
        strict_mode: If True, aggressively sanitizes content
        sanitize_html: If True, strips HTML tags and encodes content
        
    Returns:
        BackwardXSSProtectionWrapper instance
    """
    return BackwardXSSProtectionWrapper(
        base_client,
        strict_mode=strict_mode,
        sanitize_html=sanitize_html
    )

