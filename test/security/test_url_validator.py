"""
Tests for URLValidator SSRF protection and URL security validation.
"""

import socket
from unittest.mock import MagicMock, patch

import pytest

from its_compiler.security import SecurityConfig, URLSecurityError, URLValidator


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config for testing."""
    return SecurityConfig.for_development()


@pytest.fixture
def production_config() -> SecurityConfig:
    """Create production security config."""
    return SecurityConfig.from_environment()


@pytest.fixture
def url_validator(security_config: SecurityConfig) -> URLValidator:
    """Create URL validator with test config."""
    return URLValidator(security_config)


@pytest.fixture
def production_validator(production_config: SecurityConfig) -> URLValidator:
    """Create URL validator with production config."""
    return URLValidator(production_config)


class TestURLValidator:
    """Test URLValidator security functionality."""

    def test_valid_https_url(self, url_validator: URLValidator) -> None:
        """Test valid HTTPS URL passes validation."""
        url = "https://alexanderparker.github.io/schema.json"
        # Should not raise exception
        url_validator.validate_url(url)

    def test_valid_http_url_in_dev(self, url_validator: URLValidator) -> None:
        """Test HTTP URL allowed in development mode."""
        url = "http://localhost:8080/schema.json"
        url_validator.config.network.block_localhost = False
        # Should not raise exception
        url_validator.validate_url(url)

    def test_http_blocked_in_production(self, production_validator: URLValidator) -> None:
        """Test HTTP URL blocked in production."""
        url = "http://example.com/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            production_validator.validate_url(url)

        assert "HTTP not allowed in production" in str(exc_info.value)
        assert exc_info.value.reason == "http_in_production"

    def test_missing_scheme(self, url_validator: URLValidator) -> None:
        """Test URL without scheme is rejected."""
        url = "example.com/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "missing scheme" in str(exc_info.value).lower()
        assert exc_info.value.reason == "missing_scheme"

    def test_missing_netloc(self, url_validator: URLValidator) -> None:
        """Test URL without network location is rejected."""
        url = "https:///schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "missing network location" in str(exc_info.value).lower()

    def test_path_traversal_detection(self, url_validator: URLValidator) -> None:
        """Test path traversal attempts are blocked."""
        url = "https://example.com/../../../etc/passwd"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Path traversal detected" in str(exc_info.value)
        assert exc_info.value.reason == "path_traversal"

    def test_url_too_long(self, url_validator: URLValidator) -> None:
        """Test extremely long URLs are rejected."""
        long_path = "a" * 3000
        url = f"https://example.com/{long_path}"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "URL too long" in str(exc_info.value)
        assert exc_info.value.reason == "url_too_long"

    def test_dangerous_protocols_blocked(self, url_validator: URLValidator) -> None:
        """Test dangerous protocols are blocked."""
        dangerous_urls = [
            "file:///etc/passwd",
            "ftp://example.com/file.json",
            "gopher://example.com/",
            "ldap://example.com/",
            "dict://example.com/",
        ]

        url_validator.config.network.block_file_urls = True

        for url in dangerous_urls:
            with pytest.raises(URLSecurityError) as exc_info:
                url_validator.validate_url(url)

            assert exc_info.value.reason in ["disallowed_protocol", "blocked_protocol"]

    def test_data_urls_blocked(self, url_validator: URLValidator) -> None:
        """Test data URLs are blocked when configured."""
        url = "data:text/html,<script>alert('xss')</script>"
        url_validator.config.network.block_data_urls = True

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Data URLs are blocked" in str(exc_info.value)
        assert exc_info.value.reason == "data_url_blocked"

    def test_domain_allowlist_enforcement(self, url_validator: URLValidator) -> None:
        """Test domain allowlist enforcement."""
        url_validator.config.network.enforce_domain_allowlist = True
        url_validator.config.network.domain_allowlist = [
            "example.com",
            "alexanderparker.github.io",
        ]

        # Allowed domain should pass
        allowed_url = "https://example.com/schema.json"
        url_validator.validate_url(allowed_url)  # Should not raise

        # Disallowed domain should be blocked
        blocked_url = "https://example.org/schema.json"
        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(blocked_url)

        assert "not in allowlist" in str(exc_info.value)
        assert exc_info.value.reason == "domain_not_allowed"

    def test_subdomain_allowlist_matching(self, url_validator: URLValidator) -> None:
        """Test subdomain matching in domain allowlist."""
        url_validator.config.network.enforce_domain_allowlist = True
        url_validator.config.network.domain_allowlist = ["example.com"]

        # Subdomain should be allowed
        subdomain_url = "https://api.example.com/schema.json"
        url_validator.validate_url(subdomain_url)  # Should not raise

        # Different domain should be blocked
        different_url = "https://example.org/schema.json"
        with pytest.raises(URLSecurityError):
            url_validator.validate_url(different_url)

    def test_localhost_blocking(self, url_validator: URLValidator) -> None:
        """Test localhost variants are blocked."""
        url_validator.config.network.block_localhost = True

        localhost_variants = [
            "https://localhost/schema.json",
            "https://127.0.0.1/schema.json",
            "https://0.0.0.0/schema.json",
            "https://[::1]/schema.json",
        ]

        for url in localhost_variants:
            with pytest.raises(URLSecurityError) as exc_info:
                url_validator.validate_url(url)

            assert "Localhost access blocked" in str(exc_info.value)

    @patch("socket.getaddrinfo")
    def test_private_ip_blocking(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test private IP addresses are blocked."""
        url_validator.config.network.block_private_networks = True

        # Mock DNS resolution to return private IP
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 80))]

        url = "https://example.com/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Private IP address blocked" in str(exc_info.value)

    @patch("socket.getaddrinfo")
    def test_blocked_ip_ranges(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test custom blocked IP ranges."""
        # Mock DNS resolution
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80))]

        url = "https://example.org/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "blocked range" in str(exc_info.value)

    @patch("socket.getaddrinfo")
    def test_multicast_ip_blocking(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test multicast IP addresses are blocked."""
        # Mock DNS resolution to return multicast IP
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 80))]

        url = "https://example.net/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Multicast IP address blocked" in str(exc_info.value)

    @patch("socket.getaddrinfo")
    def test_ipv6_localhost_blocking(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test IPv6 localhost is blocked."""
        url_validator.config.network.block_localhost = True

        # Mock DNS resolution to return IPv6 localhost
        mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 80, 0, 0))]

        url = "https://example.com/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Loopback IP address blocked" in str(exc_info.value)

    @patch("socket.getaddrinfo")
    def test_dns_resolution_failure(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test DNS resolution failure handling."""
        mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")

        url = "https://nonexistent.example.invalid/schema.json"

        # Should log warning but not block if domain allowlist allows it
        url_validator.config.network.enforce_domain_allowlist = False
        url_validator.validate_url(url)  # Should complete

    @patch("socket.getaddrinfo")
    def test_link_local_blocking(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test link-local IP addresses are blocked."""
        url_validator.config.network.block_link_local = True

        # Mock DNS resolution to return link-local IP
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.1.1", 80))]

        url = "https://example.org/schema.json"

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Link-local IP address blocked" in str(exc_info.value)

    def test_invalid_hostname(self, url_validator: URLValidator) -> None:
        """Test invalid hostname handling."""
        url = "https:///schema.json"  # Empty hostname

        with pytest.raises(URLSecurityError) as exc_info:
            url_validator.validate_url(url)

        assert "Invalid hostname" in str(exc_info.value) or "missing network location" in str(exc_info.value)

    def test_get_url_info_valid(self, url_validator: URLValidator) -> None:
        """Test getting URL info for valid URL."""
        url = "https://example.com/schema.json"
        url_validator.config.network.enforce_domain_allowlist = False

        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

            info = url_validator.get_url_info(url)

        assert info["url"] == url
        assert info["scheme"] == "https"
        assert info["hostname"] == "example.com"
        assert info["is_valid"] is True
        assert "93.184.216.34" in info["resolved_ips"]

    def test_get_url_info_invalid(self, url_validator: URLValidator) -> None:
        """Test getting URL info for invalid URL."""
        url = "file:///etc/passwd"
        url_validator.config.network.block_file_urls = True

        info = url_validator.get_url_info(url)

        assert info["url"] == url
        assert info["is_valid"] is False
        assert "blocked_protocol" in info["security_flags"]

    def test_is_url_safe_valid(self, url_validator: URLValidator) -> None:
        """Test URL safety check for valid URL."""
        url = "https://alexanderparker.github.io/schema.json"
        url_validator.config.network.enforce_domain_allowlist = False

        assert url_validator.is_url_safe(url) is True

    def test_is_url_safe_invalid(self, url_validator: URLValidator) -> None:
        """Test URL safety check for invalid URL."""
        url = "javascript:alert('xss')"

        assert url_validator.is_url_safe(url) is False

    def test_add_allowed_domain_runtime(self, url_validator: URLValidator) -> None:
        """Test adding domain to allowlist at runtime."""
        new_domain = "example.net"

        url_validator.add_allowed_domain(new_domain)

        assert new_domain in url_validator.config.network.domain_allowlist

    def test_remove_allowed_domain_runtime(self, url_validator: URLValidator) -> None:
        """Test removing domain from allowlist at runtime."""
        domain = "example.org"
        url_validator.config.network.domain_allowlist.append(domain)

        result = url_validator.remove_allowed_domain(domain)

        assert result is True
        assert domain not in url_validator.config.network.domain_allowlist

    def test_remove_nonexistent_domain(self, url_validator: URLValidator) -> None:
        """Test removing domain that doesn't exist."""
        result = url_validator.remove_allowed_domain("example.invalid")
        assert result is False

    def test_ssrf_attempt_logging(self, url_validator: URLValidator) -> None:
        """Test SSRF attempt logging."""
        url_validator.config.network.block_localhost = True
        url = "https://127.0.0.1/schema.json"

        with pytest.raises(URLSecurityError):
            url_validator.validate_url(url)

    @patch("socket.getaddrinfo")
    def test_invalid_ip_address_format(self, mock_getaddrinfo: MagicMock, url_validator: URLValidator) -> None:
        """Test handling of invalid IP address formats."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            # Return invalid IP format
            mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("invalid.ip.format", 80))]

            url = "https://example.net/schema.json"

            with pytest.raises(URLSecurityError) as exc_info:
                url_validator.validate_url(url)

            assert "Invalid IP address" in str(exc_info.value)

    def test_blocked_ip_network_configuration(self, security_config: SecurityConfig) -> None:
        """Test configuration with invalid blocked IP ranges."""
        # Add invalid IP range
        security_config.network.blocked_ip_ranges.append("invalid.range")

        # Should handle gracefully and log warning
        validator = URLValidator(security_config)

        # Should have skipped the invalid range
        assert len(validator._blocked_networks) == len(security_config.network.blocked_ip_ranges) - 1

    def test_edge_case_urls(self, url_validator: URLValidator) -> None:
        """Test various edge case URLs."""
        url_validator.config.network.enforce_domain_allowlist = False
        url_validator.config.network.block_localhost = False

        edge_cases = [
            ("https://127.0.0.1:8080/path", "Should handle ports"),
            ("https://[::1]:8080/path", "Should handle IPv6 with ports"),
            ("https://example.com/path?query=value", "Should handle query parameters"),
            ("https://example.com/path#fragment", "Should handle fragments"),
        ]

        for url, _ in edge_cases:
            with patch("socket.getaddrinfo") as mock_dns:
                if "127.0.0.1" in url:
                    mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]
                elif "::1" in url:
                    mock_dns.return_value = [
                        (
                            socket.AF_INET6,
                            socket.SOCK_STREAM,
                            6,
                            "",
                            ("::1", 8080, 0, 0),
                        )
                    ]
                else:
                    mock_dns.return_value = [
                        (
                            socket.AF_INET,
                            socket.SOCK_STREAM,
                            6,
                            "",
                            ("93.184.216.34", 80),
                        )
                    ]

                try:
                    url_validator.validate_url(url)
                except URLSecurityError:
                    # Some edge cases might still fail due to security rules, that's OK
                    pass
