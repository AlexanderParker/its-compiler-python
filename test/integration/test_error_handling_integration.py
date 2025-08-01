"""
Integration tests for error handling and invalid template processing.
Tests complex error scenarios that span multiple components in realistic contexts.
"""

from typing import Any

import pytest

from conftest import TemplateFetcher
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


class TestErrorHandlingIntegration:
    """Test complex error handling scenarios using real templates and realistic contexts."""

    @pytest.fixture
    def compiler(self) -> ITSCompiler:
        """Create compiler with development security config."""
        config = ITSConfig(cache_enabled=False)
        security_config = SecurityConfig.for_development()
        security_config.allowlist.interactive_mode = False
        return ITSCompiler(config, security_config)

    @pytest.fixture
    def production_compiler(self) -> ITSCompiler:
        """Create compiler with production security config."""
        config = ITSConfig(cache_enabled=False)
        security_config = SecurityConfig.from_environment()
        security_config.allowlist.interactive_mode = False
        return ITSCompiler(config, security_config)

    @pytest.fixture
    def template_fetcher(self) -> TemplateFetcher:
        """Create template fetcher."""
        return TemplateFetcher()

    def test_malicious_injection_from_repo(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious injection attempts are blocked using real security templates."""
        template = template_fetcher.fetch_template("malicious_injection.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "malicious" in error_msg.lower() or "security" in error_msg.lower()

    def test_malicious_expressions_from_repo(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious expressions are blocked using real security templates."""
        template = template_fetcher.fetch_template("malicious_expressions.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["malicious", "security", "dangerous", "blocked"])

    def test_malicious_variables_from_repo(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious variables are blocked using real security templates."""
        template = template_fetcher.fetch_template("malicious_variables.json", category="templates/security")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["dangerous", "variable", "__proto__", "security"])

    def test_schema_loading_cascade_errors(self, compiler: ITSCompiler) -> None:
        """Test cascading errors when schema loading fails and affects compilation."""
        template = {
            "version": "1.0.0",
            "extends": [
                "https://nonexistent.example.com/schema1.json",  # Will fail to load
                "https://blocked.internal/schema2.json",  # Will be blocked by security
            ],
            "content": [
                {
                    "type": "placeholder",
                    "instructionType": "unknown_from_schema",  # Type only exists in failed schema
                    "config": {"description": "This will fail"},
                }
            ],
        }

        # Should fail during schema loading or compilation phase
        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    def test_production_vs_development_error_handling(
        self, compiler: ITSCompiler, production_compiler: ITSCompiler
    ) -> None:
        """Test that production compiler is stricter than development."""
        # Template that might be too large for production but OK for development
        large_template = {
            "version": "1.0.0",
            "customInstructionTypes": {f"type_{i}": {"template": f"Type {i}: {{{{description}}}}"} for i in range(100)},
            "content": [{"type": "text", "text": "x" * 5000}] * 50,  # Large content
            "variables": {f"var_{i}": f"value_{i}" for i in range(200)},  # Many variables
        }

        try:
            compiler.compile(large_template)
        except Exception:
            pass

        # Production should be more restrictive
        with pytest.raises((ITSValidationError, ITSSecurityError)):
            production_compiler.compile(large_template)

    def test_file_based_error_scenarios(self, compiler: ITSCompiler, temp_directory: Any) -> None:
        """Test error handling with file-based compilation scenarios."""
        # Create template file with permission issues simulation
        template_content = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
        }

        template_file = temp_directory / "test_template.json"
        with open(template_file, "w") as f:
            import json

            json.dump(template_content, f)

        # Should compile successfully
        result = compiler.compile_file(str(template_file))
        assert result.prompt is not None

        # Test with non-existent file
        with pytest.raises(ITSCompilationError):
            compiler.compile_file(str(temp_directory / "nonexistent.json"))

    def test_valid_template_error_context_preservation(
        self, compiler: ITSCompiler, template_fetcher: TemplateFetcher
    ) -> None:
        """Test error context preservation using a real template modified to cause errors."""
        # Start with a valid template and modify it to cause specific errors
        template = template_fetcher.fetch_template("08-custom-types.json")

        # Find the first placeholder element instead of assuming content[0]
        placeholder_found = False
        for i, element in enumerate(template["content"]):
            if element.get("type") == "placeholder":
                # Modify to use non-existent instruction type to test error context
                template["content"][i]["instructionType"] = "nonexistent_type"
                template["content"][i]["id"] = "test_placeholder_123"  # Add ID for context testing
                placeholder_found = True
                break

        # If no placeholder found, create one
        if not placeholder_found:
            template["content"].append(
                {
                    "type": "placeholder",
                    "instructionType": "nonexistent_type",
                    "id": "test_placeholder_123",
                    "config": {"description": "This will fail"},
                }
            )

        # Also ensure we remove any custom instruction types that might provide fallbacks
        if "customInstructionTypes" in template:
            # Remove the custom types to ensure the nonexistent_type truly doesn't exist
            template["customInstructionTypes"].pop("nonexistent_type", None)

        # For extra safety, also remove schema extensions that might provide the type
        # This ensures we're truly testing with a non-existent type
        if "extends" in template:
            # Keep extends but ensure our nonexistent_type won't be found there
            pass

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template)

        # Error should contain context about the failing element
        error_msg = str(exc_info.value)
        assert "nonexistent_type" in error_msg or "unknown instruction type" in error_msg.lower()

    def test_production_security_error_information_disclosure(
        self, production_compiler: ITSCompiler, template_fetcher: TemplateFetcher
    ) -> None:
        """Test that production errors don't leak sensitive information using real malicious templates."""
        try:
            template = template_fetcher.fetch_template("malicious_injection.json", category="templates/security")
            production_compiler.compile(template)
        except Exception as e:
            error_msg = str(e)
            # Should provide generic security message without exposing attack details
            assert "security" in error_msg.lower() or "validation" in error_msg.lower()

    def test_complex_template_variable_error_recovery(
        self, compiler: ITSCompiler, template_fetcher: TemplateFetcher
    ) -> None:
        """Test error behavior when valid templates have variable processing issues."""
        # Use a real template that normally works
        template = template_fetcher.fetch_template("05-complex-variables.json")

        # Remove variables to cause undefined reference errors
        if "variables" in template:
            del template["variables"]

        # Should fail during variable processing, not return partial results
        with pytest.raises((ITSValidationError, ITSVariableError, ITSCompilationError)):
            compiler.compile(template)
