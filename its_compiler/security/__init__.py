"""
Security module for ITS Compiler.

This module provides core security controls including:
- Interactive schema allowlist management
- URL validation and SSRF protection
- Expression sanitisation for conditionals
- Input validation
"""

from .allowlist_manager import AllowlistManager, TrustLevel, SchemaEntry
from .url_validator import URLValidator, URLSecurityError
from .expression_sanitiser import ExpressionSanitiser, ExpressionSecurityError
from .input_validator import InputValidator, InputSecurityError
from .config import SecurityConfig

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
