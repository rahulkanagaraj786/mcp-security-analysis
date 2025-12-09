"""
Content Sanitizer for Cache Poisoning Protection

This module sanitizes and validates content before it's stored in cache,
preventing session hijacking, data theft, and other malicious payloads from being
cached and later served to users or LLMs.

It detects and blocks:
- Session hijacking patterns (session tokens, session IDs, session keys)
- Data theft patterns (credential harvesting, data exfiltration)
- Phishing patterns (fake security alerts, verification requests)
- Sensitive data leakage patterns (API keys, passwords, internal data)
"""

import re
import html
from typing import Dict, Any, Tuple, List, Optional


class ContentSanitizer:
    """
    Sanitizes content to prevent cache poisoning attacks.
    
    Detects and sanitizes:
    - Session hijacking patterns (session tokens, session IDs)
    - Data theft patterns (credential harvesting, data exfiltration)
    - Phishing patterns (fake security alerts, verification requests)
    - Sensitive data leakage patterns (API keys, passwords)
    """
    
    # Session hijacking patterns
    SESSION_HIJACKING_PATTERNS = [
        r'session[_\s]?token',
        r'session[_\s]?id',
        r'session[_\s]?key',
        r'session[_\s]?secret',
        r'auth[_\s]?token',
        r'access[_\s]?token',
        r'bearer[_\s]?token',
    ]
    
    # Data theft patterns
    DATA_THEFT_PATTERNS = [
        r'password[:\s]+',
        r'credential[:\s]+',
        r'username[:\s]+',
        r'api[_\s]?key',
        r'secret[_\s]?key',
        r'database[_\s]?password',
        r'internal[_\s]?(?:key|password|secret)',
        r'http[s]?://[^\s]+attacker',
        r'http[s]?://[^\s]+collect',
        r'http[s]?://[^\s]+exfiltrate',
        r'http[s]?://[^\s]+steal',
        r'verify@[^\s]+',
        r'security@[^\s]+',
        r'admin@[^\s]+',
        r'send[_\s]?(?:your|the)[_\s]?(?:password|credential|token)',
        r'please[_\s]?(?:send|provide|enter)[_\s]?(?:your|the)[_\s]?(?:password|credential|token)',
    ]
    
    # Phishing patterns
    PHISHING_PATTERNS = [
        r'security[_\s]?alert',
        r'account[_\s]?(?:suspension|verification|required)',
        r'immediate[_\s]?(?:action|verification)',
        r'prevent[_\s]?(?:account|suspension|closure)',
        r'urgent[_\s]?(?:verification|action)',
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
        self.session_hijacking_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.SESSION_HIJACKING_PATTERNS]
        self.data_theft_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.DATA_THEFT_PATTERNS]
        self.phishing_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.PHISHING_PATTERNS]
    
    def detect_session_hijacking(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect session hijacking patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.session_hijacking_regex:
            if pattern.search(content):
                detected.append(pattern.pattern)
        
        return len(detected) > 0, detected
    
    def detect_data_theft(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect data theft patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.data_theft_regex:
            if pattern.search(content):
                detected.append(pattern.pattern)
        
        return len(detected) > 0, detected
    
    def detect_phishing(self, content: str) -> Tuple[bool, List[str]]:
        """
        Detect phishing patterns in content.
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_malicious, detected_patterns)
        """
        detected = []
        for pattern in self.phishing_regex:
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
            "session_hijacking_detected": False,
            "data_theft_detected": False,
            "phishing_detected": False,
            "detected_patterns": [],
            "threat_types": []
        }
        
        # Check for session hijacking
        session_detected, session_patterns = self.detect_session_hijacking(content)
        if session_detected:
            metadata["session_hijacking_detected"] = True
            metadata["detected_patterns"].extend(session_patterns)
            metadata["threat_types"].append("Session Hijacking")
            threats.append("Session Hijacking")
        
        # Check for data theft
        data_theft_detected, data_theft_patterns = self.detect_data_theft(content)
        if data_theft_detected:
            metadata["data_theft_detected"] = True
            metadata["detected_patterns"].extend(data_theft_patterns)
            metadata["threat_types"].append("Data Theft")
            threats.append("Data Theft")
        
        # Check for phishing
        phishing_detected, phishing_patterns = self.detect_phishing(content)
        if phishing_detected:
            metadata["phishing_detected"] = True
            metadata["detected_patterns"].extend(phishing_patterns)
            metadata["threat_types"].append("Phishing")
            threats.append("Phishing")
        
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


