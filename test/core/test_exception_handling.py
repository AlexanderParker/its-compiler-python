"""
Tests for exception classes and error handling.
Tests exception methods, context generation, and error reporting.
"""

from datetime import datetime

from its_compiler.core.exceptions import (
    ITSCompilationError,
    ITSConditionalError,
    ITSConfigurationError,
    ITSError,
    ITSSchemaError,
    ITSSecurityError,
    ITSTimeoutError,
    ITSValidationError,
    ITSVariableError,
    create_security_error,
    create_validation_error,
)


class TestExceptionHandling:
    """Test exception classes and error handling functionality."""

    def test_its_error_base_functionality(self) -> None:
        """Test ITSError base class functionality."""
        error = ITSError(
            "Test error message",
            details={"key": "value", "number": 42},
            security_context={"threat_level": "low"},
            error_code="TEST_ERROR",
        )

        # Test basic properties
        assert error.message == "Test error message"
        assert error.details["key"] == "value"
        assert error.error_code == "TEST_ERROR"
        assert isinstance(error.timestamp, datetime)

        # Test to_dict method
        error_dict = error.to_dict()
        assert error_dict["error_type"] == "ITSError"
        assert error_dict["message"] == "Test error message"
        assert error_dict["error_code"] == "TEST_ERROR"
        assert "timestamp" in error_dict
        assert error_dict["details"]["key"] == "value"
        assert error_dict["security_context"]["threat_level"] == "low"

        # Test user message
        user_msg = error.get_user_message()
        assert user_msg == "Test error message"

    def test_its_error_sensitive_data_sanitisation(self) -> None:
        """Test that sensitive data is sanitised from error details."""
        error = ITSError(
            "Security error",
            details={
                "password": "secret123",
                "api_key": "key456",
                "token": "token789",
                "secret": "secret_value",
                "auth": "auth_string",
                "credential": "cred123",
                "safe_data": "this_is_safe",
                "user_name": "john_doe",  # Should not be sanitised
            },
        )

        # Check that sensitive keys are redacted
        assert error.details["password"] == "[REDACTED]"
        assert error.details["api_key"] == "[REDACTED]"
        assert error.details["token"] == "[REDACTED]"
        assert error.details["secret"] == "[REDACTED]"
        assert error.details["auth"] == "[REDACTED]"
        assert error.details["credential"] == "[REDACTED]"

        # Check that non-sensitive data is preserved
        assert error.details["safe_data"] == "this_is_safe"
        assert error.details["user_name"] == "john_doe"

    def test_its_error_security_context_user_message(self) -> None:
        """Test ITSError user message with security context."""
        security_error = ITSError("Detailed security error", security_context={"is_security_error": True})

        user_msg = security_error.get_user_message()
        assert "security validation error" in user_msg.lower()

    def test_validation_error_comprehensive(self) -> None:
        """Test ITSValidationError comprehensive functionality."""
        validation_error = ITSValidationError(
            "Template validation failed",
            path="template.json",
            validation_errors=["Missing field: version", "Invalid content type"],
            security_issues=["Dangerous script tag", "Suspicious encoding"],
            details={"line": 42},
            error_code="VALIDATION_FAILED",
        )

        # Test properties
        assert validation_error.path == "template.json"
        assert len(validation_error.validation_errors) == 2
        assert len(validation_error.security_issues) == 2
        assert validation_error.has_security_issues
        assert validation_error.total_issues == 4

        # Test detailed message
        detailed_msg = validation_error.get_detailed_message()
        assert "template.json" in detailed_msg
        assert "Missing field: version" in detailed_msg
        assert "Dangerous script tag" in detailed_msg
        assert "Validation errors:" in detailed_msg
        assert "Security issues:" in detailed_msg

    def test_compilation_error_context(self) -> None:
        """Test ITSCompilationError context information."""
        comp_error = ITSCompilationError(
            "Failed to compile placeholder",
            element_id="placeholder_1",
            element_type="placeholder",
            compilation_stage="variable_processing",
            details={"instruction_type": "paragraph"},
        )

        # Test context message
        context_msg = comp_error.get_context_message()
        assert "Failed to compile placeholder" in context_msg
        assert "variable_processing" in context_msg
        assert "placeholder (ID: placeholder_1)" in context_msg

        # Test that details include context
        assert comp_error.details["element_id"] == "placeholder_1"
        assert comp_error.details["element_type"] == "placeholder"
        assert comp_error.details["compilation_stage"] == "variable_processing"

    def test_schema_error_comprehensive(self) -> None:
        """Test ITSSchemaError comprehensive functionality."""
        schema_error = ITSSchemaError(
            "Failed to load schema",
            schema_url="https://example.com/schema.json?secret=abc123&token=xyz#fragment",
            http_status=404,
            schema_content_preview="Invalid JSON content...",
            error_code="SCHEMA_LOAD_FAILED",
        )

        # Test URL sanitisation
        sanitised_url = schema_error._sanitise_url(schema_error.schema_url)
        assert "secret=" not in sanitised_url
        assert "token=" not in sanitised_url
        assert "#fragment" not in sanitised_url
        assert "https://example.com/schema.json" in sanitised_url

        # Test error type detection
        assert schema_error.is_network_error()
        assert not schema_error.is_security_error()

        # Test details
        assert schema_error.details["http_status"] == 404

    def test_schema_error_security_detection(self) -> None:
        """Test ITSSchemaError security error detection."""
        security_schema_error = ITSSchemaError("Schema blocked by security", error_code="SCHEMA_BLOCKED")

        assert security_schema_error.is_security_error()
        assert not security_schema_error.is_network_error()

    def test_variable_error_suggestions(self) -> None:
        """Test ITSVariableError suggestion functionality."""
        var_error = ITSVariableError(
            "Variable not found",
            variable_path="user.missing_field",
            available_variables=["user", "product", "settings", "config", "data", "meta"],
            variable_value_preview="undefined",
        )

        # Test suggestion message with many variables
        suggestion_msg = var_error.get_suggestion_message()
        assert "user.missing_field" in suggestion_msg
        assert "Available variables include:" in suggestion_msg
        assert "6 total" in suggestion_msg

        # Test with few variables
        var_error_few = ITSVariableError(
            "Variable not found", variable_path="missing", available_variables=["user", "product"]
        )

        suggestion_msg_few = var_error_few.get_suggestion_message()
        assert "Available variables: user, product" in suggestion_msg_few

    def test_conditional_error_context(self) -> None:
        """Test ITSConditionalError context information."""
        cond_error = ITSConditionalError(
            "Invalid condition syntax",
            condition="user.age > 18 and invalid_syntax",
            condition_context="placeholder validation",
        )

        # Test that condition is truncated in details
        assert len(cond_error.details["condition_preview"]) <= 100
        assert cond_error.condition_context == "placeholder validation"

    def test_security_error_user_messages(self) -> None:
        """Test ITSSecurityError user message variants."""

        # SSRF threat
        ssrf_error = ITSSecurityError(
            "SSRF attempt detected",
            threat_type="SSRF",
            blocked_content="https://internal.server/",
            security_rule="block_private_networks",
        )
        user_msg = ssrf_error.get_user_message()
        assert "potentially unsafe content" in user_msg.lower()

        # Injection threat
        injection_error = ITSSecurityError(
            "Code injection detected", threat_type="INJECTION", blocked_content="<script>alert('xss')</script>"
        )
        user_msg = injection_error.get_user_message()
        assert "potentially unsafe content" in user_msg.lower()

        # Malicious content
        malicious_error = ITSSecurityError("Malicious content detected", threat_type="MALICIOUS_CONTENT")
        user_msg = malicious_error.get_user_message()
        assert "potentially unsafe content" in user_msg.lower()

        # Generic security error
        generic_error = ITSSecurityError("Security violation", threat_type="OTHER")
        user_msg = generic_error.get_user_message()
        assert "security policy violation" in user_msg.lower()

    def test_configuration_error_help(self) -> None:
        """Test ITSConfigurationError help functionality."""

        # Config error with few valid values
        config_error = ITSConfigurationError(
            "Invalid security level",
            config_key="security_level",
            config_value="invalid",
            valid_values=["development", "staging", "production"],
        )

        help_msg = config_error.get_help_message()
        assert "security_level" in help_msg
        assert "Valid values: development, staging, production" in help_msg

        # Config error with many valid values
        config_error_many = ITSConfigurationError(
            "Invalid option", config_key="option", valid_values=[f"option_{i}" for i in range(10)]
        )

        help_msg_many = config_error_many.get_help_message()
        assert "Valid values include: option_0, option_1, option_2..." in help_msg_many

    def test_timeout_error_details(self) -> None:
        """Test ITSTimeoutError detail tracking."""
        timeout_error = ITSTimeoutError(
            "Schema fetch timed out",
            operation="schema_fetch",
            timeout_seconds=30.0,
            elapsed_seconds=45.5,
            details={"url": "https://example.com/schema.json"},
        )

        assert timeout_error.operation == "schema_fetch"
        assert timeout_error.timeout_seconds == 30.0
        assert timeout_error.elapsed_seconds == 45.5

        # Check details include timeout info
        assert timeout_error.details["operation"] == "schema_fetch"
        assert timeout_error.details["timeout_seconds"] == 30.0
        assert timeout_error.details["elapsed_seconds"] == 45.5

    def test_exception_factory_functions(self) -> None:
        """Test exception factory functions."""

        # Test validation error factory
        val_error = create_validation_error(
            "Validation failed", path="test.json", errors=["Error 1", "Error 2"], security_issues=["Security issue"]
        )

        assert isinstance(val_error, ITSValidationError)
        assert val_error.path == "test.json"
        assert "Error 1" in val_error.validation_errors
        assert "Error 2" in val_error.validation_errors
        assert "Security issue" in val_error.security_issues

        # Test security error factory
        sec_error = create_security_error("Injection detected", "INJECTION", "<script>alert('xss')</script>")

        assert isinstance(sec_error, ITSSecurityError)
        assert sec_error.threat_type == "INJECTION"
        assert sec_error.blocked_content == "<script>alert('xss')</script>"

    def test_error_inheritance_and_catching(self) -> None:
        """Test that errors can be caught by their base classes."""

        # All ITS errors should be catchable as ITSError
        errors = [
            ITSValidationError("Validation error"),
            ITSCompilationError("Compilation error"),
            ITSSchemaError("Schema error"),
            ITSVariableError("Variable error"),
            ITSConditionalError("Conditional error"),
            ITSSecurityError("Security error"),
            ITSConfigurationError("Configuration error"),
            ITSTimeoutError("Timeout error"),
        ]

        for error in errors:
            assert isinstance(error, ITSError)

            # Test that they can be caught as ITSError
            try:
                raise error
            except ITSError as e:
                assert e is error

    def test_error_string_representation(self) -> None:
        """Test error string representation."""
        error = ITSValidationError("Template validation failed", validation_errors=["Missing version"])

        error_str = str(error)
        assert "Template validation failed" in error_str

    def test_schema_error_invalid_url_sanitisation(self) -> None:
        """Test schema error with invalid URL sanitisation."""
        schema_error = ITSSchemaError("Invalid URL")

        # Test with invalid URL
        sanitised = schema_error._sanitise_url("not a valid url")
        assert sanitised == "[INVALID_URL]"
