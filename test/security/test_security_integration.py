"""
End-to-end security integration tests and attack simulations.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from its_compiler import ITSCompiler
from its_compiler.exceptions import (
    ITSCompilationError,
    ITSSecurityError,
    ITSValidationError,
)
from its_compiler.models import ITSConfig
from its_compiler.security import SecurityConfig


@pytest.fixture
def temp_dir():
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def security_config(temp_dir):
    """Create security config for testing."""
    config = SecurityConfig.for_development()
    config.allowlist.allowlist_file = str(temp_dir / "test_allowlist.json")
    return config


@pytest.fixture
def production_config(temp_dir):
    """Create production security config."""
    config = SecurityConfig.from_environment()
    config.allowlist.allowlist_file = str(temp_dir / "prod_allowlist.json")
    return config


@pytest.fixture
def its_config():
    """Create ITS compiler config."""
    return ITSConfig(cache_enabled=False)


@pytest.fixture
def compiler(its_config, security_config):
    """Create compiler with security enabled."""
    return ITSCompiler(its_config, security_config)


@pytest.fixture
def production_compiler(its_config, production_config):
    """Create compiler with production security."""
    return ITSCompiler(its_config, production_config)


class TestSecurityIntegration:
    """Test end-to-end security integration."""

    def test_valid_template_compilation(self, compiler):
        """Test valid template compiles successfully."""
        template = {
            "version": "1.0.0",
            "content": [
                {"type": "text", "text": "Hello "},
                {
                    "type": "placeholder",
                    "instructionType": "name",
                    "config": {"description": "Generate a name"},
                },
            ],
        }

        # Should compile without issues
        result = compiler.compile(template)
        assert result.prompt is not None
        assert len(result.prompt) > 0

    def test_malicious_template_blocked(self, compiler):
        """Test malicious template content is blocked."""
        malicious_template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "<script>alert('xss')</script>"}],
        }

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            compiler.compile(malicious_template)

    def test_malicious_variables_blocked(self, compiler):
        """Test malicious variable content is blocked."""
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "Hello ${name}"}],
        }

        malicious_variables = {"name": "<script>alert('xss')</script>"}

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            compiler.compile(template, malicious_variables)

    def test_dangerous_expressions_blocked(self, compiler):
        """Test dangerous conditional expressions are blocked."""
        dangerous_template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "conditional",
                    "condition": "__import__('os').system('rm -rf /')",
                    "content": [{"type": "text", "text": "Dangerous"}],
                }
            ],
        }

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            compiler.compile(dangerous_template)

    @patch("socket.getaddrinfo")
    def test_ssrf_protection(self, mock_getaddrinfo, compiler):
        """Test SSRF protection blocks private networks."""
        # Mock DNS to return private IP
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("192.168.1.100", 80))]

        template = {
            "version": "1.0.0",
            "extends": ["https://internal.company.local/schema.json"],
            "content": [{"type": "text", "text": "test"}],
        }

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    def test_schema_allowlist_protection(self, compiler):
        """Test schema allowlist blocks unknown schemas."""
        template = {
            "version": "1.0.0",
            "extends": ["https://evil.example.com/malicious.json"],
            "content": [{"type": "text", "text": "test"}],
        }

        # Mock non-interactive mode
        compiler.schema_loader.allowlist_manager.config.allowlist.interactive_mode = (
            False
        )

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    @patch("builtins.input", return_value="3")  # Deny
    def test_interactive_allowlist_deny(self, mock_input, compiler):
        """Test interactive allowlist denial blocks compilation."""
        template = {
            "version": "1.0.0",
            "extends": ["https://unknown.example.com/schema.json"],
            "content": [{"type": "text", "text": "test"}],
        }

        # Enable interactive mode
        compiler.schema_loader.allowlist_manager.config.allowlist.interactive_mode = (
            True
        )

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    @patch("builtins.input", return_value="2")  # Session allow
    @patch("urllib.request.urlopen")
    def test_interactive_allowlist_allow(self, mock_urlopen, mock_input, compiler):
        """Test interactive allowlist approval allows compilation."""
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(
            {"instructionTypes": {"test": {"template": "Test template"}}}
        ).encode()
        mock_response.headers = {"content-type": "application/json"}
        mock_urlopen.return_value.__enter__.return_value = mock_response

        template = {
            "version": "1.0.0",
            "extends": ["https://trusted.example.com/schema.json"],
            "content": [
                {
                    "type": "placeholder",
                    "instructionType": "test",
                    "config": {"description": "test"},
                }
            ],
        }

        # Enable interactive mode
        compiler.schema_loader.allowlist_manager.config.allowlist.interactive_mode = (
            True
        )

        # Should compile successfully after approval
        result = compiler.compile(template)
        assert result.prompt is not None

    def test_template_size_limits(self, production_compiler):
        """Test template size limits in production."""
        # Create oversized template
        large_text = "x" * (2 * 1024 * 1024)  # 2MB
        large_template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": large_text}],
        }

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            production_compiler.compile(large_template)

    def test_variable_injection_prevention(self, compiler):
        """Test variable injection attacks are prevented."""
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "User: ${user.name}"}],
        }

        # Attempt to inject through deeply nested objects
        malicious_variables = {
            "user": {
                "name": "admin",
                "__proto__": {"isAdmin": True},
                "constructor": {"prototype": {"evil": "payload"}},
            }
        }

        # Should either block or sanitize
        try:
            result = compiler.compile(template, malicious_variables)
            # If it compiles, check that injection was sanitized
            assert "__proto__" not in result.prompt
            assert "constructor" not in result.prompt
        except (ITSValidationError, ITSSecurityError):
            # Blocking is also acceptable
            pass

    def test_expression_complexity_limits(self, production_compiler):
        """Test expression complexity limits prevent DoS."""
        # Create deeply nested expression
        deep_condition = "test"
        for i in range(20):  # Very deep nesting
            deep_condition = f"({deep_condition} and test)"

        complex_template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "conditional",
                    "condition": deep_condition,
                    "content": [{"type": "text", "text": "result"}],
                }
            ],
        }

        variables = {"test": True}

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            production_compiler.compile(complex_template, variables)

    def test_file_path_traversal_prevention(self, compiler, temp_dir):
        """Test file path traversal attacks are prevented."""
        # Create malicious template file path
        malicious_path = temp_dir / "subdir" / ".." / ".." / "etc" / "passwd"

        # Should block or sanitize path traversal
        with pytest.raises(
            (ITSValidationError, ITSCompilationError, FileNotFoundError)
        ):
            compiler.compile_file(str(malicious_path))

    def test_custom_instruction_type_security(self, compiler):
        """Test custom instruction types are validated for security."""
        malicious_template = {
            "version": "1.0.0",
            "customInstructionTypes": {
                "malicious": {"template": "<script>alert('xss')</script> {description}"}
            },
            "content": [
                {
                    "type": "placeholder",
                    "instructionType": "malicious",
                    "config": {"description": "test"},
                }
            ],
        }

        # Should detect malicious content in custom templates
        try:
            result = compiler.compile(malicious_template)
            # If compilation succeeds, malicious content should be sanitized
            assert "<script>" not in result.prompt
        except (ITSValidationError, ITSSecurityError):
            # Blocking is also acceptable
            pass

    def test_concurrent_request_limits(self, compiler):
        """Test concurrent request limits prevent resource exhaustion."""
        import threading
        import time

        # Set low concurrent limit
        compiler.rate_limiter.config.network.max_concurrent_requests = 1

        results = []

        def compile_template():
            try:
                with compiler.rate_limiter.track_concurrent_operation("test", "user"):
                    time.sleep(0.1)  # Hold the slot
                    results.append("success")
            except Exception as e:
                results.append(f"error: {type(e).__name__}")

        # Start concurrent threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=compile_template)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # At least one should be blocked
        assert any("error" in result for result in results)

    def test_security_status_reporting(self, compiler):
        """Test security status reporting works."""
        status = compiler.get_security_status()

        assert "security_enabled" in status
        assert "security_level" in status
        assert "features" in status
        assert "components" in status

    def test_audit_trail_generation(self, compiler):
        """Test security events generate audit trail."""
        template = {"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}

        # Compile template to generate audit events
        compiler.compile(template)

    def test_production_security_hardening(self, production_compiler):
        """Test production security settings are more restrictive."""
        # Production should have stricter limits
        prod_config = production_compiler.security_config
        dev_config = SecurityConfig.for_development()

        assert (
            prod_config.processing.max_template_size
            <= dev_config.processing.max_template_size
        )
        assert (
            prod_config.processing.max_expression_depth
            <= dev_config.processing.max_expression_depth
        )
        assert (
            prod_config.network.max_requests_per_minute
            <= dev_config.network.max_requests_per_minute
        )

    def test_error_information_disclosure(self, production_compiler):
        """Test error messages don't disclose sensitive information."""
        malicious_template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "<script>alert('xss')</script>"}],
        }

        try:
            production_compiler.compile(malicious_template)
        except Exception as e:
            error_msg = str(e)
            # Should not expose internal paths or sensitive details
            assert "/etc/passwd" not in error_msg
            assert "internal" not in error_msg.lower()
            assert "debug" not in error_msg.lower()

    def test_security_bypass_attempts(self, compiler):
        """Test various security bypass attempts are blocked."""
        bypass_attempts = [
            # Template with null bytes
            {
                "version": "1.0.0",
                "content": [{"type": "text", "text": "test\x00malicious"}],
            },
            # Unicode normalization attack
            {
                "version": "1.0.0",
                "content": [{"type": "text", "text": "test\u200e<script>\u200f"}],
            },
            # Nested object prototype pollution
            {
                "version": "1.0.0",
                "content": [{"type": "text", "text": "test"}],
                "variables": {"__proto__": {"polluted": True}},
            },
        ]

        for attempt in bypass_attempts:
            try:
                result = compiler.compile(attempt)
                # If compilation succeeds, verify malicious content was sanitized
                assert "\x00" not in result.prompt
                assert "polluted" not in result.prompt
            except (ITSValidationError, ITSSecurityError):
                # Blocking is the preferred outcome
                pass

    def test_dos_prevention(self, production_compiler):
        """Test denial of service prevention."""
        # Extremely complex template designed to consume resources
        dos_template = {"version": "1.0.0", "content": []}

        # Add many nested conditionals
        current_content = dos_template["content"]
        for i in range(100):  # Very deep nesting
            nested = {
                "type": "conditional",
                "condition": f"var{i} == True",
                "content": [],
            }
            current_content.append(nested)
            current_content = nested["content"]

        current_content.append({"type": "text", "text": "deep"})

        # Add many variables
        variables = {f"var{i}": True for i in range(1000)}

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            production_compiler.compile(dos_template, variables)

    def test_input_sanitization_integration(self, compiler):
        """Test input sanitization across all components."""
        # Template with various types of potentially dangerous input
        mixed_template = {
            "version": "1.0.0",
            "content": [
                {"type": "text", "text": "Normal text with ${variable}"},
                {
                    "type": "conditional",
                    "condition": 'safe_var == "clean_value"',
                    "content": [
                        {
                            "type": "placeholder",
                            "instructionType": "paragraph",
                            "config": {
                                "description": "Generate content about ${topic}"
                            },
                        }
                    ],
                },
            ],
        }

        # Variables with mixed safe and potentially unsafe content
        variables = {
            "variable": "safe_value",
            "safe_var": "clean_value",
            "topic": "technology",  # Safe topic
        }

        # Should compile successfully with safe input
        result = compiler.compile(mixed_template, variables)
        assert result.prompt is not None
        assert "safe_value" in result.prompt
        assert "technology" in result.prompt
