"""
URL validation and SSRF protection for ITS Compiler.
"""

import ipaddress
import socket
from typing import Any, Dict, List
from urllib.parse import urlparse

from ..core.exceptions import ITSSchemaError
from .config import SecurityConfig


class URLSecurityError(ITSSchemaError):
    """URL security validation error."""

    def __init__(self, message: str, url: str, reason: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.url = url
        self.reason = reason


class URLValidator:
    """Validates URLs against security policies."""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.network_config = config.network

        # Pre-compile blocked IP ranges
        self._blocked_networks = []
        for cidr in self.network_config.blocked_ip_ranges:
            try:
                self._blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"Warning: Invalid blocked IP range: {cidr}")

    def validate_url(self, url: str) -> None:
        """Validate URL against security policies."""
        try:
            parsed = urlparse(url)

            # Basic URL structure validation
            self._validate_url_structure(parsed, url)

            # Protocol validation
            self._validate_protocol(parsed, url)

            # Domain validation
            self._validate_domain(parsed, url)

            # SSRF protection
            self._validate_ssrf_protection(parsed, url)

        except URLSecurityError:
            raise
        except Exception as e:
            self._log_and_raise(url, f"URL validation error: {e}", "validation_error")

    def _validate_url_structure(self, parsed: Any, url: str) -> None:
        """Validate basic URL structure."""
        if not parsed.scheme:
            self._log_and_raise(url, "URL missing scheme", "missing_scheme")

        if not parsed.netloc and parsed.scheme not in ("file", "data"):
            self._log_and_raise(url, "URL missing network location", "missing_netloc")

        # Check for suspicious URL patterns
        if ".." in parsed.path:
            self._log_and_raise(url, "Path traversal detected", "path_traversal")

        # Check URL length
        if len(url) > 2048:
            self._log_and_raise(url, "URL too long", "url_too_long")

    def _validate_protocol(self, parsed: Any, url: str) -> None:
        """Validate URL protocol."""
        scheme = parsed.scheme.lower()

        # Check allowed protocols
        if scheme not in self.network_config.allowed_protocols:
            self._log_and_raise(url, f"Protocol '{scheme}' not allowed", "disallowed_protocol")

        # Block dangerous protocols
        dangerous_protocols = {"file", "ftp", "gopher", "ldap", "dict", "sftp"}
        if self.network_config.block_file_urls and scheme in dangerous_protocols:
            self._log_and_raise(url, f"Protocol '{scheme}' is blocked", "blocked_protocol")

        # Block data URLs
        if self.network_config.block_data_urls and scheme == "data":
            self._log_and_raise(url, "Data URLs are blocked", "data_url_blocked")

        # HTTP validation in production
        if scheme == "http":
            if not self.network_config.allow_http or self.config.is_production():
                self._log_and_raise(
                    url,
                    "HTTP not allowed in production environment",
                    "http_in_production",
                )

    def _validate_domain(self, parsed: Any, url: str) -> None:
        """Validate domain against allowlist."""
        if not parsed.netloc:
            return  # File URLs, etc.

        hostname = parsed.hostname
        if not hostname:
            self._log_and_raise(url, "Invalid hostname", "invalid_hostname")

        # Check domain allowlist
        if self.network_config.enforce_domain_allowlist:
            if not self._is_domain_allowed(hostname):
                self._log_and_raise(url, f"Domain '{hostname}' not in allowlist", "domain_not_allowed")

    def _validate_ssrf_protection(self, parsed: Any, url: str) -> None:
        """Validate against SSRF attacks."""
        if not parsed.hostname:
            return

        hostname = parsed.hostname.lower()

        # Check for localhost variants
        if self.network_config.block_localhost:
            localhost_variants = {
                "localhost",
                "127.0.0.1",
                # nosec B104: This is a validation check, not binding to all interfaces
                "0.0.0.0",  # nosec
                "::1",
                "0000:0000:0000:0000:0000:0000:0000:0001",
            }
            if hostname in localhost_variants:
                self._ssrf_blocked(url, f"Localhost access blocked: {hostname}")

        # Resolve hostname to IP and check ranges
        try:
            ip_addresses = self._resolve_hostname(hostname)
            for ip_str in ip_addresses:
                self._validate_ip_address(str(ip_str), url)
        except socket.gaierror:
            # DNS resolution failed - could be suspicious
            print(f"Warning: DNS resolution failed for {hostname}")

    def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses."""
        try:
            # Get all IP addresses for the hostname
            addr_info = socket.getaddrinfo(hostname, None)
            ip_addresses = list(set(info[4][0] for info in addr_info))
            return ip_addresses
        except socket.gaierror as e:
            raise URLSecurityError(
                f"DNS resolution failed for {hostname}: {e}",
                url=hostname,
                reason="dns_resolution_failed",
            )

    def _validate_ip_address(self, ip_str: str, url: str) -> None:
        """Validate individual IP address."""
        try:
            ip = ipaddress.ip_address(ip_str)

            # Check against blocked ranges
            for network in self._blocked_networks:
                if ip in network:
                    self._ssrf_blocked(url, f"IP {ip_str} in blocked range {network}")

            # Check specific IP properties
            if self.network_config.block_private_networks and ip.is_private:
                self._ssrf_blocked(url, f"Private IP address blocked: {ip_str}")

            if self.network_config.block_localhost and ip.is_loopback:
                self._ssrf_blocked(url, f"Loopback IP address blocked: {ip_str}")

            if self.network_config.block_link_local and ip.is_link_local:
                self._ssrf_blocked(url, f"Link-local IP address blocked: {ip_str}")

            # Additional checks for suspicious IPs
            if ip.is_multicast:
                self._ssrf_blocked(url, f"Multicast IP address blocked: {ip_str}")

            if ip.is_reserved:
                self._ssrf_blocked(url, f"Reserved IP address blocked: {ip_str}")

        except ValueError:
            # Invalid IP address format
            self._log_and_raise(url, f"Invalid IP address: {ip_str}", "invalid_ip")

    def _is_domain_allowed(self, hostname: str) -> bool:
        """Check if domain is in allowlist."""
        if not self.network_config.domain_allowlist:
            return True

        hostname = hostname.lower()

        for allowed_domain in self.network_config.domain_allowlist:
            allowed_domain = allowed_domain.lower()

            # Exact match
            if hostname == allowed_domain:
                return True

            # Subdomain match (if allowlist entry starts with .)
            if allowed_domain.startswith(".") and hostname.endswith(allowed_domain):
                return True

            # Subdomain match (implicit)
            if hostname.endswith("." + allowed_domain):
                return True

        return False

    def _ssrf_blocked(self, url: str, reason: str) -> None:
        """Log SSRF attempt and raise error."""
        print(f"SSRF protection: {reason}")
        raise URLSecurityError(f"SSRF protection: {reason}", url=url, reason="ssrf_blocked")

    def _log_and_raise(self, url: str, message: str, reason: str) -> None:
        """Log security violation and raise error."""
        print(f"URL validation failure: {message}")
        raise URLSecurityError(message, url=url, reason=reason)

    def get_url_info(self, url: str) -> Dict[str, Any]:
        """Get detailed information about a URL for analysis."""
        try:
            parsed = urlparse(url)
            info: Dict[str, Any] = {
                "url": url,
                "scheme": parsed.scheme,
                "hostname": parsed.hostname,
                "port": parsed.port,
                "path": parsed.path,
                "is_valid": False,
                "security_flags": [],
            }

            try:
                self.validate_url(url)
                info["is_valid"] = True
            except URLSecurityError as e:
                info["security_flags"].append(e.reason)

            # Add resolved IPs if possible
            if parsed.hostname:
                try:
                    info["resolved_ips"] = self._resolve_hostname(parsed.hostname)
                except Exception:
                    info["resolved_ips"] = []

            return info

        except Exception as e:
            return {"url": url, "is_valid": False, "error": str(e)}

    def is_url_safe(self, url: str) -> bool:
        """Quick check if URL is safe (no exceptions)."""
        try:
            self.validate_url(url)
            return True
        except URLSecurityError:
            return False

    def add_allowed_domain(self, domain: str) -> None:
        """Add domain to allowlist (runtime only)."""
        if domain not in self.network_config.domain_allowlist:
            self.network_config.domain_allowlist.append(domain)
            print(f"Added domain to allowlist: {domain}")

    def remove_allowed_domain(self, domain: str) -> bool:
        """Remove domain from allowlist (runtime only)."""
        if domain in self.network_config.domain_allowlist:
            self.network_config.domain_allowlist.remove(domain)
            print(f"Removed domain from allowlist: {domain}")
            return True
        return False
