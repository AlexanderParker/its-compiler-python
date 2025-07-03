"""
Security module for ITS Compiler.

This module provides core security controls including:
- Interactive schema allowlist management
- URL validation and SSRF protection
- Expression sanitisation for conditionals
- Input validation
"""

from .allowlist_manager import AllowlistManager, SchemaEntry, TrustLevel
from .config import SecurityConfig
from .expression_sanitiser import ExpressionSanitiser, ExpressionSecurityError
from .input_validator import InputSecurityError, InputValidator
from .url_validator import URLSecurityError, URLValidator

__all__ = [
    # Allowlist management
    "AllowlistManager",
    "TrustLevel",
    "SchemaEntry",
    # URL validation
    "URLValidator",
    "URLSecurityError",
    # Expression security
    "ExpressionSanitiser",
    "ExpressionSecurityError",
    # Input validation
    "InputValidator",
    "InputSecurityError",
    # Configuration
    "SecurityConfig",
]
