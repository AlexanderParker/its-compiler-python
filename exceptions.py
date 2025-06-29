"""
Exception classes for ITS Compiler.
"""

from typing import Optional, List, Any


class ITSError(Exception):
    """Base exception for all ITS compiler errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ITSValidationError(ITSError):
    """Raised when template validation fails."""

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.path = path
        self.validation_errors = validation_errors or []


class ITSCompilationError(ITSError):
    """Raised when template compilation fails."""

    def __init__(
        self,
        message: str,
        element_id: Optional[str] = None,
        element_type: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.element_id = element_id
        self.element_type = element_type


class ITSSchemaError(ITSError):
    """Raised when schema loading or processing fails."""

    def __init__(
        self,
        message: str,
        schema_url: Optional[str] = None,
        http_status: Optional[int] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.schema_url = schema_url
        self.http_status = http_status


class ITSVariableError(ITSError):
    """Raised when variable resolution fails."""

    def __init__(
        self,
        message: str,
        variable_path: Optional[str] = None,
        available_variables: Optional[List[str]] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.variable_path = variable_path
        self.available_variables = available_variables or []


class ITSConditionalError(ITSError):
    """Raised when conditional evaluation fails."""

    def __init__(
        self,
        message: str,
        condition: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.condition = condition
