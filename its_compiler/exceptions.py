"""
Exception classes for ITS Compiler with security enhancements.
"""

from typing import Optional, List, Any, Dict
from datetime import datetime


class ITSError(Exception):
    """Base exception for all ITS compiler errors with security context."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        security_context: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.security_context = security_context or {}
        self.error_code = error_code
        self.timestamp = datetime.utcnow()

        # Sanitise sensitive information from error details
        self._sanitise_details()

    def _sanitise_details(self) -> None:
        """Remove sensitive information from error details."""
        sensitive_keys = {"password", "token", "key", "secret", "auth", "credential"}

        for key in list(self.details.keys()):
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                self.details[key] = "[REDACTED]"

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "security_context": self.security_context,
        }

    def get_user_message(self) -> str:
        """Get sanitised message safe for user display."""
        # In production, return generic message for security errors
        if self.security_context.get("is_security_error", False):
            return "A security validation error occurred. Please check your template and try again."
        return self.message


class ITSValidationError(ITSError):
    """Raised when template validation fails."""

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
        security_issues: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message, details, error_code=error_code or "VALIDATION_FAILED")
        self.path = path
        self.validation_errors = validation_errors or []
        self.security_issues = security_issues or []

        # Mark as security error if security issues found
        if self.security_issues:
            self.security_context["is_security_error"] = True
            self.security_context["security_issues_count"] = len(self.security_issues)

    @property
    def has_security_issues(self) -> bool:
        """Check if validation failed due to security issues."""
        return len(self.security_issues) > 0

    @property
    def total_issues(self) -> int:
        """Get total count of all validation issues."""
        return len(self.validation_errors) + len(self.security_issues)

    def get_detailed_message(self) -> str:
        """Get detailed validation error message."""
        parts = [self.message]

        if self.path:
            parts.append(f"Path: {self.path}")

        if self.validation_errors:
            parts.append("Validation errors:")
            for error in self.validation_errors:
                parts.append(f"  • {error}")

        if self.security_issues:
            parts.append("Security issues:")
            for issue in self.security_issues:
                parts.append(f"  • {issue}")

        return "\n".join(parts)


class ITSCompilationError(ITSError):
    """Raised when template compilation fails."""

    def __init__(
        self,
        message: str,
        element_id: Optional[str] = None,
        element_type: Optional[str] = None,
        compilation_stage: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(
            message, details, error_code=error_code or "COMPILATION_FAILED"
        )
        self.element_id = element_id
        self.element_type = element_type
        self.compilation_stage = compilation_stage

        # Add compilation context to details
        if element_id:
            self.details["element_id"] = element_id
        if element_type:
            self.details["element_type"] = element_type
        if compilation_stage:
            self.details["compilation_stage"] = compilation_stage

    def get_context_message(self) -> str:
        """Get error message with compilation context."""
        parts = [self.message]

        if self.compilation_stage:
            parts.append(f"Stage: {self.compilation_stage}")

        if self.element_type and self.element_id:
            parts.append(f"Element: {self.element_type} (ID: {self.element_id})")
        elif self.element_type:
            parts.append(f"Element type: {self.element_type}")
        elif self.element_id:
            parts.append(f"Element ID: {self.element_id}")

        return " | ".join(parts)


class ITSSchemaError(ITSError):
    """Raised when schema loading or processing fails."""

    def __init__(
        self,
        message: str,
        schema_url: Optional[str] = None,
        http_status: Optional[int] = None,
        schema_content_preview: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message, details, error_code=error_code or "SCHEMA_ERROR")
        self.schema_url = schema_url
        self.http_status = http_status
        self.schema_content_preview = schema_content_preview

        # Add schema context to details
        if schema_url:
            self.details["schema_url"] = self._sanitise_url(schema_url)
        if http_status:
            self.details["http_status"] = http_status

    def _sanitise_url(self, url: str) -> str:
        """Sanitise URL for logging (remove sensitive parameters)."""
        try:
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(url)
            # Remove query parameters and fragment
            sanitised = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    "",
                    "",  # Remove params, query, fragment
                )
            )
            return sanitised
        except Exception:
            return "[INVALID_URL]"

    def is_network_error(self) -> bool:
        """Check if this is a network-related error."""
        return self.http_status is not None

    def is_security_error(self) -> bool:
        """Check if this is a security-related schema error."""
        security_codes = {"SCHEMA_BLOCKED", "SSRF_BLOCKED", "ALLOWLIST_DENIED"}
        return self.error_code in security_codes


class ITSVariableError(ITSError):
    """Raised when variable resolution fails."""

    def __init__(
        self,
        message: str,
        variable_path: Optional[str] = None,
        available_variables: Optional[List[str]] = None,
        variable_value_preview: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message, details, error_code=error_code or "VARIABLE_ERROR")
        self.variable_path = variable_path
        self.available_variables = available_variables or []
        self.variable_value_preview = variable_value_preview

        # Add variable context to details
        if variable_path:
            self.details["variable_path"] = variable_path
        if available_variables:
            self.details["available_variables_count"] = len(available_variables)
            # Don't log all variable names for security
            self.details["available_variables_sample"] = available_variables[:5]

    def get_suggestion_message(self) -> str:
        """Get error message with variable suggestions."""
        parts = [self.message]

        if self.available_variables:
            if len(self.available_variables) <= 5:
                available = ", ".join(self.available_variables)
                parts.append(f"Available variables: {available}")
            else:
                sample = ", ".join(self.available_variables[:3])
                parts.append(
                    f"Available variables include: {sample}... ({len(self.available_variables)} total)"
                )

        return " | ".join(parts)


class ITSConditionalError(ITSError):
    """Raised when conditional evaluation fails."""

    def __init__(
        self,
        message: str,
        condition: Optional[str] = None,
        condition_context: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message, details, error_code=error_code or "CONDITIONAL_ERROR")
        self.condition = condition
        self.condition_context = condition_context

        # Add conditional context to details
        if condition:
            # Limit condition length in logs for security
            self.details["condition_preview"] = (
                condition[:100] if len(condition) > 100 else condition
            )
        if condition_context:
            self.details["condition_context"] = condition_context


class ITSSecurityError(ITSError):
    """Raised when security validation fails."""

    def __init__(
        self,
        message: str,
        security_rule: Optional[str] = None,
        threat_type: Optional[str] = None,
        blocked_content: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        security_context = {
            "is_security_error": True,
            "security_rule": security_rule,
            "threat_type": threat_type,
        }

        super().__init__(
            message,
            details,
            security_context=security_context,
            error_code=error_code or "SECURITY_VIOLATION",
        )
        self.security_rule = security_rule
        self.threat_type = threat_type
        self.blocked_content = blocked_content

        # Add security context to details (sanitised)
        if threat_type:
            self.details["threat_type"] = threat_type
        if security_rule:
            self.details["security_rule"] = security_rule
        if blocked_content:
            # Only log a preview for security
            self.details["blocked_content_preview"] = blocked_content[:50]

    def get_user_message(self) -> str:
        """Get user-safe security error message."""
        if self.threat_type in {"SSRF", "INJECTION", "MALICIOUS_CONTENT"}:
            return "Security validation failed. The template contains potentially unsafe content."
        return "A security policy violation was detected. Please review your template."


class ITSConfigurationError(ITSError):
    """Raised when configuration is invalid."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        valid_values: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(
            message, details, error_code=error_code or "CONFIGURATION_ERROR"
        )
        self.config_key = config_key
        self.config_value = config_value
        self.valid_values = valid_values or []

        # Add configuration context to details
        if config_key:
            self.details["config_key"] = config_key
        if valid_values:
            self.details["valid_values"] = valid_values

    def get_help_message(self) -> str:
        """Get error message with configuration help."""
        parts = [self.message]

        if self.config_key:
            parts.append(f"Configuration key: {self.config_key}")

        if self.valid_values:
            if len(self.valid_values) <= 5:
                valid = ", ".join(str(v) for v in self.valid_values)
                parts.append(f"Valid values: {valid}")
            else:
                sample = ", ".join(str(v) for v in self.valid_values[:3])
                parts.append(f"Valid values include: {sample}...")

        return " | ".join(parts)


class ITSTimeoutError(ITSError):
    """Raised when operations timeout."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        elapsed_seconds: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ):
        super().__init__(message, details, error_code=error_code or "OPERATION_TIMEOUT")
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds

        # Add timeout context to details
        if operation:
            self.details["operation"] = operation
        if timeout_seconds:
            self.details["timeout_seconds"] = timeout_seconds
        if elapsed_seconds:
            self.details["elapsed_seconds"] = elapsed_seconds


# Convenience functions for creating common exceptions


def create_validation_error(
    message: str,
    path: Optional[str] = None,
    errors: Optional[List[str]] = None,
    security_issues: Optional[List[str]] = None,
) -> ITSValidationError:
    """Create a validation error with common parameters."""
    return ITSValidationError(
        message=message,
        path=path,
        validation_errors=errors,
        security_issues=security_issues,
    )


def create_security_error(
    message: str, threat_type: str, blocked_content: Optional[str] = None
) -> ITSSecurityError:
    """Create a security error with threat classification."""
    return ITSSecurityError(
        message=message, threat_type=threat_type, blocked_content=blocked_content
    )
