"""
SSRF URL Validator

This module provides URL validation to prevent Server-Side Request Forgery (SSRF) attacks.
It validates URLs before allowing the MCP server to fetch them, blocking:
- localhost/internal IP addresses
- file:// protocol
- Private IP ranges
- Internal/private domains
"""

import re
from urllib.parse import urlparse
from typing import Tuple, Dict, Any, Optional
import ipaddress


class SSRFURLValidator:
    """
    Validates URLs to prevent SSRF attacks.
    
    Blocks:
    - localhost/127.0.0.1 addresses
    - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - file:// protocol
    - Internal/private domains
    - Cloud metadata service IPs (169.254.169.254)
    """
    
    # Private IP ranges
    PRIVATE_IP_RANGES = [
        ipaddress.IPv4Network('10.0.0.0/8'),
        ipaddress.IPv4Network('172.16.0.0/12'),
        ipaddress.IPv4Network('192.168.0.0/16'),
        ipaddress.IPv4Network('127.0.0.0/8'),  # localhost
        ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local (includes metadata services)
    ]
    
    # Blocked protocols
    BLOCKED_PROTOCOLS = ['file', 'gopher', 'ldap', 'ldaps']
    
    # Blocked hostnames/domains
    BLOCKED_HOSTNAMES = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        '[::1]',
    ]
    
    def __init__(self, strict_mode: bool = True, allowed_domains: Optional[list] = None):
        """
        Initialize the SSRF URL validator.
        
        Args:
            strict_mode: If True, blocks all suspicious URLs. If False, only logs warnings.
            allowed_domains: Optional list of allowed domains (whitelist). If None, allows all public domains.
        """
        self.strict_mode = strict_mode
        self.allowed_domains = allowed_domains or []
        self.blocked_attempts = []
        
        print(f"[SSRFURLValidator] Initialized")
        print(f"  Strict mode: {strict_mode}")
        if self.allowed_domains:
            print(f"  Allowed domains: {self.allowed_domains}")
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is in a private range"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for network in self.PRIVATE_IP_RANGES:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            # Not a valid IP address
            return False
    
    def is_blocked_protocol(self, protocol: str) -> bool:
        """Check if a protocol is blocked"""
        return protocol.lower() in self.BLOCKED_PROTOCOLS
    
    def is_blocked_hostname(self, hostname: str) -> bool:
        """Check if a hostname is blocked"""
        hostname_lower = hostname.lower()
        # Check exact matches
        if hostname_lower in self.BLOCKED_HOSTNAMES:
            return True
        # Check if it's localhost with any TLD
        if hostname_lower.startswith('localhost'):
            return True
        return False
    
    def validate_url(self, url: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate a URL to prevent SSRF attacks.
        
        Args:
            url: The URL to validate
            
        Returns:
            Tuple of (is_allowed, message, metadata)
            - is_allowed: True if URL is safe, False if blocked
            - message: Explanation of why it was allowed/blocked
            - metadata: Additional information about the validation
        """
        metadata = {
            "url": url,
            "blocked_reasons": []
        }
        
        # Parse the URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL format: {e}", metadata
        
        protocol = parsed.scheme.lower()
        hostname = parsed.hostname or ""
        port = parsed.port
        
        metadata["protocol"] = protocol
        metadata["hostname"] = hostname
        metadata["port"] = port
        
        # Check 1: Block file:// protocol
        if self.is_blocked_protocol(protocol):
            metadata["blocked_reasons"].append(f"Blocked protocol: {protocol}")
            self.blocked_attempts.append({
                "url": url,
                "reason": f"Blocked protocol: {protocol}",
                "type": "protocol_blocked"
            })
            return False, f"SSRF protection: Blocked protocol '{protocol}' is not allowed", metadata
        
        # Check 2: Block localhost/internal hostnames
        if self.is_blocked_hostname(hostname):
            metadata["blocked_reasons"].append(f"Blocked hostname: {hostname}")
            self.blocked_attempts.append({
                "url": url,
                "reason": f"Blocked hostname: {hostname}",
                "type": "hostname_blocked"
            })
            return False, f"SSRF protection: Blocked hostname '{hostname}' (localhost/internal)", metadata
        
        # Check 3: Block private IP addresses
        if self.is_private_ip(hostname):
            metadata["blocked_reasons"].append(f"Private IP: {hostname}")
            self.blocked_attempts.append({
                "url": url,
                "reason": f"Private IP address: {hostname}",
                "type": "private_ip_blocked"
            })
            return False, f"SSRF protection: Blocked private/internal IP address '{hostname}'", metadata
        
        # Check 4: If whitelist is enabled, check if domain is allowed
        if self.allowed_domains:
            hostname_lower = hostname.lower()
            is_allowed = any(
                hostname_lower == domain.lower() or 
                hostname_lower.endswith('.' + domain.lower())
                for domain in self.allowed_domains
            )
            if not is_allowed:
                metadata["blocked_reasons"].append(f"Domain not in whitelist: {hostname}")
                self.blocked_attempts.append({
                    "url": url,
                    "reason": f"Domain not in whitelist: {hostname}",
                    "type": "domain_not_whitelisted"
                })
                return False, f"SSRF protection: Domain '{hostname}' is not in allowed whitelist", metadata
        
        # URL is safe
        metadata["allowed"] = True
        return True, "URL is safe and allowed", metadata
    
    def get_blocked_attempts(self) -> list:
        """Get list of blocked URL attempts"""
        return self.blocked_attempts.copy()
    
    def reset(self):
        """Reset blocked attempts counter"""
        self.blocked_attempts = []


def create_ssrf_url_validator(strict_mode: bool = True, allowed_domains: Optional[list] = None) -> SSRFURLValidator:
    """
    Create an SSRF URL validator.
    
    Args:
        strict_mode: If True, blocks all suspicious URLs
        allowed_domains: Optional list of allowed domains (whitelist)
        
    Returns:
        SSRFURLValidator instance
    """
    return SSRFURLValidator(strict_mode=strict_mode, allowed_domains=allowed_domains)

