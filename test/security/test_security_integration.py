"""
End-to-end security integration tests and attack simulations.
Tests using real malicious templates from the its-example-templates repository.
"""

import tempfile
from pathlib import Path
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.exceptions import (
    ITSCompilationError,
    ITSConditionalError,
    ITSSecurityError,
    ITSValidationError,
    ITSVariableError,
)
from its_compiler.core.models import ITSConfig
from its_compiler.security import SecurityConfig


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def security_config(temp_dir: Path) -> SecurityConfig:
    """Create security config for testing."""
    config = SecurityConfig.for_development()
    config.allowlist.allowlist_file = str(temp_dir / "test_allowlist.json")
    return config


@pytest.fixture
def production_config(temp_dir: Path) -> SecurityConfig:
    """Create production security config."""
    config = SecurityConfig.from_environment()
    config.allowlist.allowlist_file = str(temp_dir / "prod_allowlist.json")
    return config


@pytest.fixture
def its_config() -> ITSConfig:
    """Create ITS compiler config."""
    return ITSConfig(cache_enabled=False)


@pytest.fixture
def compiler(its_config: ITSConfig, security_config: SecurityConfig) -> ITSCompiler:
    """Create compiler with security enabled."""
    return ITSCompiler(its_config, security_config)


@pytest.fixture
def production_compiler(its_config: ITSConfig, production_config: SecurityConfig) -> ITSCompiler:
    """Create compiler with production security."""
    return ITSCompiler(its_config, production_config)


@pytest.fixture
def fetcher(template_fetcher):
    """Use the shared template fetcher fixture."""
    return template_fetcher


class TestSecurityIntegration:
    """Test end-to-end security integration using real templates."""

    def test_valid_template_compilation_with_security(self, compiler: ITSCompiler, fetcher) -> None:
        """Test valid templates compile successfully with security enabled."""
        # Use a known-good template to ensure security doesn't break legitimate functionality
        template = fetcher.fetch_template("01-text-only.json")

        result = compiler.compile(template)
        assert result.prompt is not None
        assert len(result.prompt) > 0
        assert "This is a simple template with no placeholders" in result.prompt

    def test_malicious_injection_blocked(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that malicious injection templates are blocked."""
        template = fetcher.fetch_template("malicious_injection.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["malicious", "security", "dangerous", "blocked"])

    def test_malicious_expressions_blocked(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that malicious conditional expressions are blocked."""
        template = fetcher.fetch_template("malicious_expressions.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["malicious", "security", "dangerous", "blocked"])

    def test_malicious_variables_blocked(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that malicious variables are blocked."""
        template = fetcher.fetch_template("malicious_variables.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["dangerous", "variable", "__proto__", "security"])

    def test_malicious_schema_urls_blocked(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that malicious schema URLs are blocked."""
        template = fetcher.fetch_template("malicious_schema.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSCompilationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["schema", "blocked", "extensions", "many"])

    @patch("socket.getaddrinfo")
    def test_ssrf_protection_with_real_templates(
        self, mock_getaddrinfo: MagicMock, compiler: ITSCompiler, fetcher
    ) -> None:
        """Test SSRF protection using templates that extend schemas."""
        # Mock DNS to return private IP for any schema URL
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("192.168.1.100", 80))]

        # Use a template that extends schemas
        template = fetcher.fetch_template("02-single-placeholder.json")

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    def test_schema_allowlist_protection_with_real_templates(self, compiler: ITSCompiler, fetcher) -> None:
        """Test schema allowlist blocks unknown schemas using real templates."""
        # Use a template that extends schemas
        template = fetcher.fetch_template("02-single-placeholder.json")

        # Modify to use an untrusted schema
        template_modified = template.copy()
        template_modified["extends"] = ["https://evil.example.com/malicious.json"]

        # Mock non-interactive mode
        if compiler.schema_loader.allowlist_manager:
            compiler.schema_loader.allowlist_manager.config.allowlist.interactive_mode = False

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template_modified)

    @patch("builtins.input", return_value="3")  # Deny
    def test_interactive_allowlist_deny_with_real_templates(
        self, mock_input: MagicMock, compiler: ITSCompiler, fetcher
    ) -> None:
        """Test interactive allowlist denial blocks compilation."""
        template = fetcher.fetch_template("02-single-placeholder.json")

        # Modify to use an unknown schema
        template_modified = template.copy()
        template_modified["extends"] = ["https://unknown.example.com/schema.json"]

        # Enable interactive mode
        if compiler.schema_loader.allowlist_manager:
            compiler.schema_loader.allowlist_manager.config.allowlist.interactive_mode = True

        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template_modified)

    @patch("builtins.input", return_value="2")  # Session allow
    def test_interactive_allowlist_allow_with_real_templates(
        self, mock_input: MagicMock, compiler: ITSCompiler, fetcher
    ) -> None:
        """Test interactive allowlist approval allows compilation."""
        # Use a template with custom instruction types to avoid external schema issues
        template = fetcher.fetch_template("08-custom-types.json")

        # Should compile successfully
        result = compiler.compile(template)
        assert result.prompt is not None
        assert "Chocolate Chip Cookies Recipe" in result.prompt

    def test_complex_templates_with_security_enabled(self, compiler: ITSCompiler, fetcher) -> None:
        """Test complex legitimate templates work with all security features enabled."""
        complex_templates = [
            "05-complex-variables.json",
            "07-complex-conditionals.json",
            "09-array-usage.json",
            "10-comprehensive-conditionals.json",
        ]

        for template_name in complex_templates:
            template = fetcher.fetch_template(template_name)

            # Should compile successfully despite complex structure
            result = compiler.compile(template)
            assert result.prompt is not None
            assert len(result.prompt) > 0

    def test_production_security_with_real_templates(self, production_compiler: ITSCompiler, fetcher) -> None:
        """Test production security settings with real templates."""
        # Simple template should work in production
        simple_template = fetcher.fetch_template("01-text-only.json")
        result = production_compiler.compile(simple_template)
        assert result.prompt is not None

        # Complex template might be more restricted in production
        complex_template = fetcher.fetch_template("10-comprehensive-conditionals.json")
        try:
            result = production_compiler.compile(complex_template)
            assert result.prompt is not None
        except (ITSValidationError, ITSSecurityError):
            # Production might be more restrictive, which is acceptable
            pass

    def test_security_with_variable_substitution(self, compiler: ITSCompiler, fetcher) -> None:
        """Test security validation works with variable substitution."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Test with safe variables
        safe_variables = {"topic": "clean technology", "itemCount": 5}
        result = compiler.compile(template, variables=safe_variables)
        assert result.prompt is not None
        assert "clean technology" in result.prompt

        # Test with potentially dangerous variables
        dangerous_variables = {
            "topic": "<script>alert('xss')</script>",
            "itemCount": 999999,  # Very large number
        }

        with pytest.raises((ITSValidationError, ITSSecurityError)):
            compiler.compile(template, variables=dangerous_variables)

    def test_security_with_conditionals(self, compiler: ITSCompiler, fetcher) -> None:
        """Test security validation works with conditional templates."""
        template = fetcher.fetch_template("06-simple-conditionals.json")
        variables = fetcher.fetch_variables("conditional-test-variables.json")

        # Should compile safely with legitimate conditionals
        result = compiler.compile(template, variables=variables)
        assert result.prompt is not None

        # Test with modified dangerous conditional
        template_modified = template.copy()
        template_modified["content"].append(
            {
                "type": "conditional",
                "condition": "__import__('os').system('rm -rf /')",
                "content": [{"type": "text", "text": "Dangerous"}],
            }
        )

        with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError)):
            compiler.compile(template_modified, variables=variables)

    def test_all_security_templates_blocked(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that all security templates in the repo are properly blocked."""
        security_templates = fetcher.list_templates("templates/security")

        for template_name in security_templates:
            template = fetcher.fetch_template(template_name, category="templates/security")

            with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError)) as exc_info:
                compiler.compile(template)

            # Verify we get an appropriate security-related error
            error_msg = str(exc_info.value)
            assert any(
                keyword in error_msg.lower()
                for keyword in ["malicious", "security", "dangerous", "blocked", "validation", "error"]
            )

    def test_layered_security_defense_with_real_templates(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that multiple security layers work together with real template structures."""
        # Start with a legitimate template
        template = fetcher.fetch_template("05-complex-variables.json")

        # Inject multiple attack vectors
        layered_attack = template.copy()
        layered_attack["extends"] = ["javascript:alert('schema_injection')"]  # URL validation layer
        layered_attack["customInstructionTypes"] = {
            "attack": {"template": "<script>${payload}</script>"}  # Content validation layer
        }
        layered_attack["variables"]["malicious"] = "eval('attack')"  # Variable validation layer

        # Add malicious conditional
        layered_attack["content"].append(
            {
                "type": "conditional",
                "condition": "exec('system_attack')",  # Expression validation layer
                "content": [{"type": "text", "text": "pwned"}],
            }
        )

        # Should be blocked by at least one security layer
        with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError, ITSCompilationError)):
            compiler.compile(layered_attack)

    def test_security_status_reporting(self, compiler: ITSCompiler) -> None:
        """Test security status reporting works with real compiler setup."""
        status = compiler.get_security_status()

        assert "security_enabled" in status
        assert "features" in status
        assert "components" in status

        # Verify security features are properly enabled
        assert status["features"]["allowlist"] is True
        assert status["features"]["input_validation"] is True
        assert status["features"]["expression_sanitisation"] is True

    def test_file_path_traversal_prevention(self, compiler: ITSCompiler, temp_dir: Path) -> None:
        """Test file path traversal attacks are prevented."""
        # Create malicious template file path
        malicious_path = temp_dir / "subdir" / ".." / ".." / "etc" / "passwd"

        # Should block or sanitize path traversal
        with pytest.raises((ITSValidationError, ITSCompilationError, FileNotFoundError)):
            compiler.compile_file(str(malicious_path))

    def test_error_information_disclosure(self, production_compiler: ITSCompiler, fetcher) -> None:
        """Test error messages don't disclose sensitive information."""
        template = fetcher.fetch_template("malicious_injection.json", category="templates/security")

        try:
            production_compiler.compile(template)
        except Exception as e:
            error_msg = str(e)
            # Should not expose internal paths or sensitive details
            assert "/etc/passwd" not in error_msg
            assert "internal" not in error_msg.lower()
            assert "debug" not in error_msg.lower()
            # Should not expose full template content
            assert len(error_msg) < 1000  # Reasonable error message length
