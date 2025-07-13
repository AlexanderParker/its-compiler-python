"""
Core ITS Compiler functionality.

This module contains the main compiler logic, data models, and core processing components.
"""

from .compiler import ITSCompiler
from .exceptions import (
    ITSCompilationError,
    ITSConditionalError,
    ITSConfigurationError,
    ITSError,
    ITSSchemaError,
    ITSSecurityError,
    ITSTimeoutError,
    ITSValidationError,
    ITSVariableError,
)
from .models import (
    CompilationResult,
    InstructionTypeDefinition,
    ITSConfig,
    SecurityMetrics,
    SecurityReport,
    TypeOverride,
    ValidationResult,
)

__all__ = [
    # Core compiler
    "ITSCompiler",
    # Configuration and models
    "ITSConfig",
    "CompilationResult",
    "ValidationResult",
    "TypeOverride",
    "InstructionTypeDefinition",
    "SecurityReport",
    "SecurityMetrics",
    # Exceptions
    "ITSError",
    "ITSValidationError",
    "ITSCompilationError",
    "ITSSchemaError",
    "ITSVariableError",
    "ITSConditionalError",
    "ITSSecurityError",
    "ITSConfigurationError",
    "ITSTimeoutError",
]
