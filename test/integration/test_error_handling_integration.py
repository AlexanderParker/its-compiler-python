"""
Integration tests for error handling and invalid template processing.
Tests that invalid templates fail appropriately with correct error messages.
"""

from typing import Any, Dict

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

from .test_template_fetcher import TemplateFetcher


class TestErrorHandlingIntegration:
    """Test error handling for invalid templates and security violations."""

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

    def test_invalid_json_template(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that invalid JSON template raises appropriate error."""
        template = template_fetcher.fetch_template("invalid/01-invalid-json.json")

        with pytest.raises(ITSValidationError) as exc_info:
            compiler.compile(template)

        assert "Invalid JSON" in str(exc_info.value) or "Expecting property name" in str(exc_info.value)

    def test_missing_required_fields(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that templates missing required fields fail validation."""
        template = template_fetcher.fetch_template("invalid/02-missing-required-fields.json")

        with pytest.raises(ITSValidationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "Missing required field" in error_msg

    def test_undefined_variables(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that undefined variable references are caught."""
        template = template_fetcher.fetch_template("invalid/03-undefined-variables.json")

        with pytest.raises((ITSValidationError, ITSVariableError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "undefined" in error_msg.lower() or "not found" in error_msg.lower()

    def test_unknown_instruction_type(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that unknown instruction types are rejected."""
        template = template_fetcher.fetch_template("invalid/04-unknown-instruction-type.json")

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "Unknown instruction type" in error_msg or "nonExistentType" in error_msg

    def test_invalid_conditional_expression(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that invalid conditional expressions are rejected."""
        template = template_fetcher.fetch_template("invalid/05-invalid-conditional.json")

        with pytest.raises((ITSValidationError, ITSConditionalError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "syntax" in error_msg.lower() or "invalid" in error_msg.lower()

    def test_missing_placeholder_config(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that placeholders missing required config fail validation."""
        template = template_fetcher.fetch_template("invalid/06-missing-placeholder-config.json")

        with pytest.raises(ITSValidationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "description" in error_msg.lower() or "config" in error_msg.lower()

    def test_empty_content_array(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that empty content arrays are rejected."""
        template = template_fetcher.fetch_template("invalid/07-empty-content.json")

        with pytest.raises(ITSValidationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "empty" in error_msg.lower() or "content" in error_msg.lower()

    def test_malicious_injection_blocked(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious injection attempts are blocked."""
        template = template_fetcher.fetch_template("security/malicious_injection.json")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "malicious" in error_msg.lower() or "security" in error_msg.lower()

    def test_malicious_expressions_blocked(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious conditional expressions are blocked."""
        template = template_fetcher.fetch_template("security/malicious_expressions.json")

        with pytest.raises((ITSValidationError, ITSSecurityError, ITSConditionalError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["malicious", "security", "dangerous", "blocked"])

    def test_malicious_variables_blocked(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious variables are blocked."""
        template = template_fetcher.fetch_template("security/malicious_variables.json")

        with pytest.raises((ITSValidationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["dangerous", "variable", "__proto__", "security"])

    def test_malicious_schema_urls_blocked(self, compiler: ITSCompiler, template_fetcher: TemplateFetcher) -> None:
        """Test that malicious schema URLs are blocked."""
        template = template_fetcher.fetch_template("security/malicious_schema.json")

        with pytest.raises((ITSValidationError, ITSCompilationError, ITSSecurityError)) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert any(keyword in error_msg.lower() for keyword in ["schema", "blocked", "extensions", "many"])

    def test_validation_with_invalid_template_structure(self, compiler: ITSCompiler) -> None:
        """Test validation of templates with invalid structure."""
        invalid_templates = [
            # Template is not a dict
            "not a dict",
            # Content is not a list
            {"version": "1.0.0", "content": "not a list"},
            # Content element is not a dict
            {"version": "1.0.0", "content": ["not a dict"]},
            # Missing type in content element
            {"version": "1.0.0", "content": [{"no_type": "value"}]},
        ]

        for invalid_template in invalid_templates:
            with pytest.raises(ITSValidationError):
                compiler.compile(invalid_template)

    def test_variable_processing_errors(self, compiler: ITSCompiler) -> None:
        """Test various variable processing error conditions."""
        # Template with circular variable reference
        template = {
            "version": "1.0.0",
            "variables": {"a": "${b}", "b": "${a}"},
            "content": [{"type": "text", "text": "${a}"}],
        }

        # The current implementation raises ITSVariableError during variable processing
        # when it tries to resolve undefined variables in the circular reference
        with pytest.raises((ITSValidationError, ITSVariableError, ITSCompilationError)):
            compiler.compile(template)

    def test_conditional_expression_errors(self, compiler: ITSCompiler) -> None:
        """Test various conditional expression error conditions."""
        error_conditions = [
            # Syntax errors
            "invalid syntax &&",
            "missing quotes == test",
            "unbalanced ( parens",
            # Undefined variables
            "undefined_var == true",
            # Invalid operations
            '"string" + 123',
        ]

        for condition in error_conditions:
            template = {
                "version": "1.0.0",
                "content": [
                    {"type": "conditional", "condition": condition, "content": [{"type": "text", "text": "test"}]}
                ],
            }

            with pytest.raises((ITSValidationError, ITSConditionalError)):
                compiler.compile(template)

    def test_nested_error_propagation(self, compiler: ITSCompiler) -> None:
        """Test that errors in nested structures are properly propagated."""
        template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "conditional",
                    "condition": "true",
                    "content": [
                        {
                            "type": "conditional",
                            "condition": "invalid syntax here",
                            "content": [{"type": "text", "text": "nested"}],
                        }
                    ],
                }
            ],
        }

        with pytest.raises((ITSValidationError, ITSConditionalError)):
            compiler.compile(template)

    def test_production_security_stricter_than_development(
        self, compiler: ITSCompiler, production_compiler: ITSCompiler
    ) -> None:
        """Test that production security is stricter than development."""
        # Template that might pass in development but fail in production
        large_template = {"version": "1.0.0", "content": [{"type": "text", "text": "x" * 50000}]}  # Large content

        # Development might allow it
        try:
            compiler.compile(large_template)
        except ITSValidationError:
            pass  # Either way is fine for development

        # Production should be more restrictive
        # Note: This test might need adjustment based on actual limits
        with pytest.raises(ITSValidationError):
            production_compiler.compile(large_template)

    def test_error_message_quality(self, compiler: ITSCompiler) -> None:
        """Test that error messages are informative and helpful."""
        template = {
            "version": "1.0.0",
            "content": [{"type": "placeholder", "instructionType": "unknown_type", "config": {"description": "test"}}],
        }

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        # Error message should mention the unknown type
        assert "unknown_type" in error_msg
        # Error message should be specific about what went wrong
        assert "instruction type" in error_msg.lower()
