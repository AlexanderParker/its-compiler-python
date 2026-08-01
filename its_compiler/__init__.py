"""
ITS Compiler Python

Reference Python library for Instruction Template Specification (ITS).
Converts content templates with placeholders into structured AI prompts.

Includes comprehensive security features for safe template processing.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version
from typing import Any, Dict

try:
    # Single source of truth: the installed distribution metadata, which
    # pyproject.toml populates. Keeps this from drifting out of step with
    # the version declared for packaging.
    __version__ = _package_version("its-compiler")
except PackageNotFoundError:  # pragma: no cover - uninstalled source tree
    __version__ = "0.0.0"

__author__ = "Alexander Parker"
__email__ = "pypi@parker.im"

# Supported ITS specification version
__supported_schema_version__ = "1.0"

# Core exports
from .core.compiler import ITSCompiler
from .core.exceptions import (
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
from .core.models import (
    CompilationResult,
    InstructionTypeDefinition,
    ITSConfig,
    SecurityMetrics,
    SecurityReport,
    TypeOverride,
    ValidationResult,
)

# Security components for advanced usage
from .security import AllowlistManager, ExpressionSanitiser, InputValidator, SecurityConfig, TrustLevel, URLValidator

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
    # Security components
    "SecurityConfig",
    "AllowlistManager",
    "TrustLevel",
    "URLValidator",
    "ExpressionSanitiser",
    "InputValidator",
]


# Version information
def get_version() -> str:
    """Get the current version of ITS Compiler Python."""
    return __version__


def get_supported_schema_version() -> str:
    """Get the supported ITS specification version."""
    return __supported_schema_version__


def get_security_info() -> Dict[str, Any]:
    """Get information about available security features."""
    return {
        "version": __version__,
        "supported_schema_version": __supported_schema_version__,
        "security_features": [
            "Interactive schema allowlist",
            "SSRF protection",
            "Expression sanitisation",
            "Input validation",
            "Rate limiting",
            "Security audit logging",
        ],
        "security_levels": ["development", "staging", "production"],
        "supported_protocols": ["https"],
        "audit_events": [
            "schema_access",
            "security_violations",
            "rate_limits",
            "allowlist_changes",
        ],
    }
