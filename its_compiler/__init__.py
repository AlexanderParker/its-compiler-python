"""
ITS Compiler Python

Reference Python compiler for Instruction Template Specification (ITS).
Converts content templates with placeholders into structured AI prompts.

Includes comprehensive security features for safe template processing.
"""

from typing import Dict, Any

__version__ = "0.1.0"
__author__ = "Alexander Parker"
__email__ = "your-email@example.com"

from .compiler import ITSCompiler
from .exceptions import (
    ITSError,
    ITSValidationError,
    ITSCompilationError,
    ITSSchemaError,
    ITSVariableError,
    ITSConditionalError,
    ITSSecurityError,
    ITSConfigurationError,
    ITSTimeoutError,
)
from .models import (
    CompilationResult,
    ValidationResult,
    TypeOverride,
    ITSConfig,
    InstructionTypeDefinition,
    SecurityReport,
    SecurityMetrics,
)

# Security components for advanced usage
from .security import (
    SecurityConfig,
    AllowlistManager,
    TrustLevel,
    URLValidator,
    ExpressionSanitiser,
    InputValidator,
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


def get_security_info() -> Dict[str, Any]:
    """Get information about available security features."""
    return {
        "version": __version__,
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
