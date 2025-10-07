#!/usr/bin/env python3
"""
ZowTiCheck Input Validation & Security
OWASP compliant input validation and sanitization
"""

import re
import ipaddress
import urllib.parse
from typing import Tuple, Optional, Dict, Any
from urllib.parse import urlparse
import tldextract

class SecurityValidator:
    """Security-focused input validation following OWASP guidelines"""
    
    # Blacklisted domains/IPs for security
    BLACKLISTED_DOMAINS = {
        'localhost', '127.0.0.1', '0.0.0.0', 
        'metadata.google.internal',  # AWS metadata
        '169.254.169.254'            # AWS metadata IP
    }
    
    # Allowed URL schemes
    ALLOWED_SCHEMES = {'http', 'https'}
    
    # Malicious patterns in URLs
    MALICIOUS_PATTERNS = [
        r'\.\./',           # Path traversal
        r'%2e%2e%2f',      # Encoded path traversal
        r'<script',        # XSS attempts
        r'javascript:',    # JavaScript protocol
        r'data:',          # Data URLs
        r'file:',          # File protocol
        r'ftp:',           # FTP protocol
    ]
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Comprehensive URL validation with security checks
        
        Returns:
            (is_valid, error_message, parsed_info)
        """
        if not url or not isinstance(url, str):
            return False, "URL is required and must be a string", None
        
        # Basic length check
        if len(url) > 2048:
            return False, "URL too long (max 2048 characters)", None
        
        # Remove whitespace and normalize
        url = url.strip()
        
        # Check for malicious patterns
        url_lower = url.lower()
        for pattern in cls.MALICIOUS_PATTERNS:
            if re.search(pattern, url_lower):
                return False, f"URL contains potentially malicious pattern: {pattern}", None
        
        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}", None
        
        # Validate scheme
        if parsed.scheme not in cls.ALLOWED_SCHEMES:
            return False, f"Unsupported scheme: {parsed.scheme}. Allowed: {', '.join(cls.ALLOWED_SCHEMES)}", None
        
        # Validate hostname
        if not parsed.hostname:
            return False, "URL must have a valid hostname", None
        
        # Check for private/internal IPs
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, "Private/internal IP addresses are not allowed", None
        except ValueError:
            # Not an IP address, check domain
            pass
        
        # Check blacklisted domains
        hostname_lower = parsed.hostname.lower()
        if hostname_lower in cls.BLACKLISTED_DOMAINS:
            return False, f"Domain {parsed.hostname} is not allowed", None
        
        # Extract and validate TLD
        try:
            extracted = tldextract.extract(url)
            if not extracted.domain or not extracted.suffix:
                return False, "Invalid domain structure", None
        except Exception:
            return False, "Failed to parse domain structure", None
        
        # Port validation
        if parsed.port:
            if parsed.port < 1 or parsed.port > 65535:
                return False, "Invalid port number", None
            # Block common internal service ports
            blocked_ports = {22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017}
            if parsed.port in blocked_ports:
                return False, f"Port {parsed.port} is not allowed", None
        
        # Return parsed info
        parsed_info = {
            'scheme': parsed.scheme,
            'hostname': parsed.hostname,
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path or '/',
            'domain': extracted.domain,
            'subdomain': extracted.subdomain,
            'suffix': extracted.suffix,
            'full_domain': f"{extracted.domain}.{extracted.suffix}"
        }
        
        return True, None, parsed_info
    
    @classmethod
    def sanitize_url(cls, url: str) -> str:
        """
        Sanitize URL for safe processing
        """
        if not url:
            return ""
        
        # Remove dangerous characters
        url = re.sub(r'[<>"\'\s]', '', url)
        
        # Ensure proper encoding
        try:
            parsed = urlparse(url)
            # Reconstruct URL with proper encoding
            sanitized = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                urllib.parse.quote(parsed.path),
                parsed.params,
                urllib.parse.quote(parsed.query, safe='&='),
                urllib.parse.quote(parsed.fragment)
            ))
            return sanitized
        except Exception:
            return url
    
    @classmethod
    def validate_scan_modules(cls, modules: list) -> Tuple[bool, Optional[str]]:
        """
        Validate requested scan modules
        """
        if not modules:
            return True, None
        
        if not isinstance(modules, list):
            return False, "Modules must be a list"
        
        if len(modules) > 20:
            return False, "Too many modules requested (max 20)"
        
        valid_modules = {
            'xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 
            'headers', 'info_disclosure', 'authentication', 'access_control', 
            'file_upload', 'tech_stack', 'directory_traversal', 'all'
        }
        
        for module in modules:
            if not isinstance(module, str):
                return False, "Module names must be strings"
            if module not in valid_modules:
                return False, f"Invalid module: {module}. Valid modules: {', '.join(valid_modules)}"
        
        return True, None

class RateLimiter:
    """Simple in-memory rate limiter for IP addresses"""
    
    def __init__(self):
        self.requests = {}  # {ip: [(timestamp, count), ...]}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = 0
    
    def is_allowed(self, ip: str, per_minute: int = 60, per_hour: int = 1000) -> Tuple[bool, str]:
        """
        Check if IP is within rate limits
        
        Returns:
            (allowed, message)
        """
        import time
        current_time = time.time()
        
        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        if ip not in self.requests:
            self.requests[ip] = []
        
        requests = self.requests[ip]
        
        # Count requests in last minute
        minute_ago = current_time - 60
        minute_requests = len([r for r in requests if r[0] > minute_ago])
        
        # Count requests in last hour
        hour_ago = current_time - 3600
        hour_requests = len([r for r in requests if r[0] > hour_ago])
        
        # Check limits
        if minute_requests >= per_minute:
            return False, f"Rate limit exceeded: {minute_requests}/{per_minute} requests per minute"
        
        if hour_requests >= per_hour:
            return False, f"Rate limit exceeded: {hour_requests}/{per_hour} requests per hour"
        
        # Add current request
        requests.append((current_time, 1))
        
        return True, "OK"
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove entries older than 1 hour"""
        hour_ago = current_time - 3600
        for ip in list(self.requests.keys()):
            self.requests[ip] = [r for r in self.requests[ip] if r[0] > hour_ago]
            if not self.requests[ip]:
                del self.requests[ip]

# Global rate limiter instance
rate_limiter = RateLimiter()