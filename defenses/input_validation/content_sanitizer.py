"""
Content Sanitizer for Cache Poisoning Protection

This module sanitizes and validates content before it's stored in cache,
preventing XSS, prompt injection, and other malicious payloads from being
cached and later served to users or LLMs.

It detects and blocks:
- XSS payloads (script tags, event handlers, etc.)
- Prompt injection patterns
- SQL injection patterns
- Other malicious content patterns
"""

import re
import html
from typing import Dict, Any, Tuple, List, Optional


class ContentSanitizer:
    """
    Sanitizes content to prevent cache poisoning attacks.
    
    Detects and sanitizes:
    - XSS payloads (JavaScript, HTML event handlers)
    - Prompt injection patterns
    - SQL injection patterns
    - Other malicious content
    """
    
    # XSS patterns to detect
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'<script[^>]*>',  # Incomplete script tags
        r'javascript:',  # JavaScript protocol
        r'on\w+\s*=',  # Event handlers (onclick, onerror, etc.)
        r'<iframe[^>]*>',  # Iframe tags
        r'<img[^>]*onerror',  # Image with onerror
        r'<svg[^>]*onload',  # SVG with onload
        r'<body[^>]*onload',  # Body with onload
        r'<input[^>]*onfocus',  # Input with onfocus
        r'<iframe[^>]*src\s*=\s*["\']?javascript:',  # Iframe with javascript: src
        r'<object[^>]*>',  # Object tags
        r'<embed[^>]*>',  # Embed tags
        r'eval\s*\(',  # eval() calls
        r'expression\s*\(',  # CSS expression()
    ]
    
    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+all\s+previous\s+instructions',
        r'ignore\s+previous\s+instructions',
        r'system\s+override',
        r'bypass\s+security',
        r'reveal\s+(?:your\s+)?(?:system\s+)?prompt',
        r'show\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions)',
        r'you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|debug)\s+mode',
        r'forget\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
        r'override\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
        r'disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules)',
    ]
    
    # SQL injection patterns (for detection, even though server uses no-SQL)
    SQL_INJECTION_PATTERNS = [
        r"'\s*OR\s*'1'\s*=\s*'1",
        r"'\s*OR\s*1\s*=\s*1",
        r"'\s*UNION\s+SELECT",
        r"'\s*;\s*DROP\s+TABLE",
        r"'\s*;\s*DELETE\s+FROM",
        r"--\s*$",  # SQL comment
        r"/\*.*?\*/",  # SQL comment block
    ]
    
    def __init__(self, strict_mode: bool = True, sanitize_output: bool = True):
        """
        Initialize the content sanitizer.
        
        Args:
            strict_mode: If True, blocks malicious content. If False, only logs warnings.
            sanitize_output: If True, sanitizes content by escaping HTML. If False, only detects.
        """
        self.strict_mode = strict_mode
        self.sanitize_output = sanitize_output
        self.detected_threats = []
        self.blocked_count = 0
        self.sanitized_count = 0
        
        # Compile regex patterns for performance
        self.xss_regex = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in self.XSS_PATTERNS]
        self.prompt_injection_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.PROMPT_INJECTION_PATTERNS]
        self.sql_injection_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS]
    
    def detect_xss(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect XSS patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.xss_regex:
            if pattern.search(content):
                detected.append(pattern.pattern)
        
        return len(detected) > 0, detected
    
    def detect_prompt_injection(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect prompt injection patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.prompt_injection_regex:
            if pattern.search(content):
                detected.append(pattern.pattern)
        
        return len(detected) > 0, detected
    
    def detect_sql_injection(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect SQL injection patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.sql_injection_regex:
            if pattern.search(content):
                detected.append(pattern.pattern)
        
        return len(detected) > 0, detected
    
    def sanitize_content(self, content: str) -> str:
        """
        Sanitize content by escaping HTML entities.
        
        Args:
            content: Content to sanitize
            
        Returns:
            Sanitized content
        """
        if not self.sanitize_output:
            return content
        
        # Escape HTML entities
        sanitized = html.escape(content)
        return sanitized
    
    def validate_content(self, content: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate content and determine if it should be blocked.
        
        Args:
            content: Content to validate
            
        Returns:
            Tuple of (is_allowed, message, metadata)
            - is_allowed: True if content is safe, False if blocked
            - message: Explanation message
            - metadata: Additional information about detected threats
        """
        if not isinstance(content, str):
            return True, "Content is not a string", {}
        
        threats = []
        metadata = {
            "xss_detected": False,
            "prompt_injection_detected": False,
            "sql_injection_detected": False,
            "detected_patterns": [],
            "threat_types": []
        }
        
        # Check for XSS
        xss_detected, xss_patterns = self.detect_xss(content)
        if xss_detected:
            metadata["xss_detected"] = True
            metadata["detected_patterns"].extend(xss_patterns)
            metadata["threat_types"].append("XSS")
            threats.append("XSS")
        
        # Check for prompt injection
        prompt_detected, prompt_patterns = self.detect_prompt_injection(content)
        if prompt_detected:
            metadata["prompt_injection_detected"] = True
            metadata["detected_patterns"].extend(prompt_patterns)
            metadata["threat_types"].append("Prompt Injection")
            threats.append("Prompt Injection")
        
        # Check for SQL injection
        sql_detected, sql_patterns = self.detect_sql_injection(content)
        if sql_detected:
            metadata["sql_injection_detected"] = True
            metadata["detected_patterns"].extend(sql_patterns)
            metadata["threat_types"].append("SQL Injection")
            threats.append("SQL Injection")
        
        # If threats detected
        if threats:
            self.detected_threats.append({
                "content": content[:100] + "..." if len(content) > 100 else content,
                "threats": threats,
                "patterns": metadata["detected_patterns"]
            })
            
            if self.strict_mode:
                self.blocked_count += 1
                threat_list = ", ".join(threats)
                return False, f"Blocked: Cache poisoning detected. Threats: {threat_list}", metadata
            else:
                self.sanitized_count += 1
                threat_list = ", ".join(threats)
                return True, f"Warning: Potential cache poisoning detected. Threats: {threat_list}", metadata
        
        return True, "Content appears safe", metadata
    
    def sanitize_and_validate(self, content: str) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Validate and sanitize content.
        
        Args:
            content: Content to validate and sanitize
            
        Returns:
            Tuple of (is_allowed, sanitized_content, message, metadata)
            - is_allowed: True if content is safe, False if blocked
            - sanitized_content: Sanitized version of content (or original if blocked)
            - message: Explanation message
            - metadata: Additional information
        """
        is_allowed, message, metadata = self.validate_content(content)
        
        if is_allowed:
            # Sanitize content even if allowed (defense in depth)
            sanitized = self.sanitize_content(content)
            return True, sanitized, message, metadata
        else:
            # Content is blocked, return original (won't be used anyway)
            return False, content, message, metadata
    
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get a summary of security events.
        
        Returns:
            Dictionary with security statistics
        """
        return {
            "blocked_count": self.blocked_count,
            "sanitized_count": self.sanitized_count,
            "detected_threats": len(self.detected_threats),
            "strict_mode": self.strict_mode,
            "sanitize_output": self.sanitize_output,
        }
    
    def reset(self):
        """Reset the sanitizer state."""
        self.detected_threats = []
        self.blocked_count = 0
        self.sanitized_count = 0


def create_content_sanitizer(strict_mode: bool = True, sanitize_output: bool = True) -> ContentSanitizer:
    """
    Create a content sanitizer instance.
    
    Args:
        strict_mode: If True, blocks malicious content. If False, only logs warnings.
        sanitize_output: If True, sanitizes content by escaping HTML.
        
    Returns:
        ContentSanitizer instance
    """
    return ContentSanitizer(strict_mode=strict_mode, sanitize_output=sanitize_output)


