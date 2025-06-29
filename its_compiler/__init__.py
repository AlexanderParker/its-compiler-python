"""
ITS Compiler Python

Reference Python compiler for Instruction Template Specification (ITS).
Converts content templates with placeholders into structured AI prompts.
"""

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
)
from .models import CompilationResult, ValidationResult, TypeOverride

__all__ = [
    "ITSCompiler",
    "ITSError",
    "ITSValidationError",
    "ITSCompilationError",
    "ITSSchemaError",
    "ITSVariableError",
    "CompilationResult",
    "ValidationResult",
    "TypeOverride",
]
