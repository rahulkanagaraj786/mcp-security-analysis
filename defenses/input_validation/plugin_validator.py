"""
Plugin Validator

This module provides validation for plugin installation requests to prevent
backdoor/RCE attacks. It validates plugin URLs and can optionally validate
plugin content.

The validator blocks:
- Untrusted domains (unless whitelisted)
- Internal/localhost URLs
- Suspicious file extensions
- Malicious code patterns (optional content scanning)
"""

import re
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import ipaddress


class PluginValidator:
    """
    Validator for plugin installation requests.
    
    Prevents backdoor/RCE attacks by validating:
    - Plugin URLs (domain whitelist, internal IP blocking)
    - File extensions (only allow safe extensions)
    - Optional: Content scanning for malicious patterns
    """
    
    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
        allow_internal: bool = False,
        allowed_extensions: Optional[List[str]] = None,
        strict_mode: bool = True
    ):
        """
        Initialize the plugin validator.
        
        Args:
            allowed_domains: List of allowed domains (whitelist). 
                - If None: allows all public domains (no whitelist)
                - If [] (empty list): blocks all domains (strict mode)
                - If [list of domains]: only allows those domains
            blocked_domains: List of blocked domains (blacklist).
            allow_internal: If True, allows localhost/internal IPs. Default: False.
            allowed_extensions: List of allowed file extensions (e.g., ['.py', '.js']). If None, allows common safe extensions.
            strict_mode: If True, blocks suspicious URLs. If False, only logs warnings.
        """
        # Store None vs empty list distinction
        self.allowed_domains = allowed_domains  # Keep None if None, [] if []
        self.blocked_domains = blocked_domains or []
        self.allow_internal = allow_internal
        self.strict_mode = strict_mode
        
        # Default allowed extensions (Python scripts only for safety)
        self.allowed_extensions = allowed_extensions or ['.py']
        
        # Malicious patterns to detect in code (optional content scanning)
        self.malicious_patterns = [
            r'__import__\s*\(\s*["\']os["\']',
            r'__import__\s*\(\s*["\']subprocess["\']',
            r'eval\s*\(',
            r'exec\s*\(',
            r'compile\s*\(',
            r'open\s*\(\s*["\']/etc/',
            r'open\s*\(\s*["\']/proc/',
            r'open\s*\(\s*["\']/sys/',
            r'subprocess\.(run|call|Popen)',
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'\.popen\s*\(',
        ]
    
    def is_private_ip(self, host: str) -> bool:
        """Check if an IP address is private/internal"""
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def is_internal_host(self, host: str) -> bool:
        """Check if a hostname is internal/localhost"""
        if not host:
            return False
        
        # Check for localhost variations
        if host.lower() in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
            return True
        
        # Check for private IPs
        if self.is_private_ip(host):
            return True
        
        # Check for internal domain patterns
        internal_patterns = [
            r'^127\.',
            r'^192\.168\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'\.local$',
            r'\.internal$',
            r'^localhost',
        ]
        
        for pattern in internal_patterns:
            if re.match(pattern, host.lower()):
                return True
        
        return False
    
    def validate_url(self, url: str) -> Dict[str, Any]:
        """
        Validate a plugin URL.
        
        Args:
            url: The plugin URL to validate
            
        Returns:
            Dictionary with validation result:
            {
                "valid": bool,
                "reason": str (if invalid),
                "domain": str,
                "extension": str
            }
        """
        if not url:
            return {
                "valid": False,
                "reason": "URL is required",
                "domain": None,
                "extension": None
            }
        
        try:
            parsed = urlparse(url)
        except Exception as e:
            return {
                "valid": False,
                "reason": f"Invalid URL format: {str(e)}",
                "domain": None,
                "extension": None
            }
        
        # Check protocol (only allow http/https)
        if parsed.scheme not in ['http', 'https']:
            return {
                "valid": False,
                "reason": f"Unsupported protocol: {parsed.scheme}. Only http/https allowed.",
                "domain": parsed.netloc,
                "extension": None
            }
        
        # Extract domain/host
        host = parsed.netloc.split(':')[0]  # Remove port if present
        
        # Check for internal/localhost URLs
        if not self.allow_internal and self.is_internal_host(host):
            return {
                "valid": False,
                "reason": f"Internal/localhost URLs are not allowed: {host}",
                "domain": host,
                "extension": None
            }
        
        # Check blocked domains
        if host.lower() in [d.lower() for d in self.blocked_domains]:
            return {
                "valid": False,
                "reason": f"Domain is blocked: {host}",
                "domain": host,
                "extension": None
            }
        
        # Check allowed domains (whitelist check)
        # None = no whitelist (allow all public domains)
        # [] = empty whitelist (block all domains - strict mode)
        # [domains] = only allow listed domains
        if self.allowed_domains is not None:
            # Whitelist is set (could be empty list for strict mode)
            if len(self.allowed_domains) == 0:
                # Empty whitelist = block all domains (strict security)
                return {
                    "valid": False,
                    "reason": f"Domain whitelist is empty - all domains are blocked: {host}",
                    "domain": host,
                    "extension": None
                }
            elif host.lower() not in [d.lower() for d in self.allowed_domains]:
                # Domain not in whitelist
                return {
                    "valid": False,
                    "reason": f"Domain not in whitelist: {host}",
                    "domain": host,
                    "extension": None
                }
        
        # Check file extension
        path = parsed.path.lower()
        extension = None
        for ext in self.allowed_extensions:
            if path.endswith(ext.lower()):
                extension = ext
                break
        
        if not extension:
            return {
                "valid": False,
                "reason": f"File extension not allowed. Allowed extensions: {', '.join(self.allowed_extensions)}",
                "domain": host,
                "extension": None
            }
        
        # URL is valid
        return {
            "valid": True,
            "reason": None,
            "domain": host,
            "extension": extension
        }
    
    def validate_content(self, content: str) -> Dict[str, Any]:
        """
        Validate plugin content for malicious patterns.
        
        This is optional and can be used for additional security.
        
        Args:
            content: The plugin code content
            
        Returns:
            Dictionary with validation result:
            {
                "safe": bool,
                "suspicious_patterns": List[str],
                "risk_level": str
            }
        """
        if not content:
            return {
                "safe": False,
                "suspicious_patterns": ["Empty content"],
                "risk_level": "high"
            }
        
        suspicious_patterns = []
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                suspicious_patterns.append(f"Pattern: {pattern} (found {len(matches)} times)")
        
        # Determine risk level
        if len(suspicious_patterns) == 0:
            risk_level = "low"
        elif len(suspicious_patterns) < 3:
            risk_level = "medium"
        else:
            risk_level = "high"
        
        return {
            "safe": len(suspicious_patterns) == 0,
            "suspicious_patterns": suspicious_patterns,
            "risk_level": risk_level
        }


def create_plugin_validator(
    allowed_domains: Optional[List[str]] = None,
    blocked_domains: Optional[List[str]] = None,
    allow_internal: bool = False,
    allowed_extensions: Optional[List[str]] = None,
    strict_mode: bool = True
) -> PluginValidator:
    """
    Create a plugin validator with default security settings.
    
    Args:
        allowed_domains: Whitelist of allowed domains (None = allow all public domains)
        blocked_domains: Blacklist of blocked domains
        allow_internal: Allow localhost/internal IPs (default: False)
        allowed_extensions: Allowed file extensions (default: ['.py'])
        strict_mode: Strict validation mode (default: True)
    
    Returns:
        Configured PluginValidator instance
    """
    return PluginValidator(
        allowed_domains=allowed_domains,
        blocked_domains=blocked_domains,
        allow_internal=allow_internal,
        allowed_extensions=allowed_extensions,
        strict_mode=strict_mode
    )

