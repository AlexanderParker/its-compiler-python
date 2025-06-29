"""
Data models for ITS Compiler.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class OverrideType(Enum):
    """Type of instruction type override."""

    CUSTOM = "custom"  # Overridden by customInstructionTypes
    SCHEMA_EXTENSION = "schema"  # Overridden by extended schema
    STANDARD = "standard"  # From standard types (no override)


@dataclass
class TypeOverride:
    """Information about an instruction type override."""

    type_name: str
    override_source: str  # Source that overrode (e.g., "marketing-types.json")
    overridden_source: str  # Source that was overridden (e.g., "company-types.json")
    override_type: OverrideType


@dataclass
class ValidationResult:
    """Result of template validation."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]

    def __bool__(self) -> bool:
        return self.is_valid


@dataclass
class CompilationResult:
    """Result of template compilation."""

    prompt: str
    template: Dict[str, Any]
    variables: Dict[str, Any]
    overrides: List[TypeOverride]
    warnings: List[str]

    @property
    def has_overrides(self) -> bool:
        """Check if any type overrides occurred."""
        return len(self.overrides) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were generated."""
        return len(self.warnings) > 0


@dataclass
class ITSConfig:
    """Configuration for ITS Compiler."""

    # Schema caching
    cache_enabled: bool = True
    cache_directory: Optional[str] = None
    cache_ttl: int = 3600  # seconds

    # Network settings
    request_timeout: int = 30
    max_retries: int = 3
    allow_http: bool = False
    domain_allowlist: Optional[List[str]] = None
    max_schema_size: int = 10 * 1024 * 1024  # 10MB

    # Compiler settings
    strict_mode: bool = True
    report_overrides: bool = True
    validate_variables: bool = True
    preserve_formatting: bool = True

    # Default compiler configuration
    default_system_prompt: str = (
        "You are an AI assistant that fills in content templates. "
        "Follow the instructions exactly and replace each placeholder with "
        "appropriate content based on the user prompts provided. "
        "Respond only with the transformed content."
    )
    default_instruction_wrapper: str = "<<{instruction}>>"
    default_user_content_wrapper: str = "([{<{content}>}])"
    default_processing_instructions: List[str] = None

    def __post_init__(self):
        if self.default_processing_instructions is None:
            self.default_processing_instructions = [
                "Replace each placeholder marked with << >> with generated content",
                "The user's content request is wrapped in ([{< >}]) to distinguish it from instructions",
                "Follow the format requirements specified after each user prompt",
                "Maintain the existing structure and formatting of the template",
                "Only replace the placeholders - do not modify any other text",
                "Generate content that matches the tone and style requested",
                "Respond only with the transformed content - do not include any explanations or additional text",
            ]


@dataclass
class InstructionTypeDefinition:
    """Definition of an instruction type."""

    name: str
    template: str
    description: Optional[str] = None
    config_schema: Optional[Dict[str, Any]] = None
    source: Optional[str] = None  # Source schema or "custom"


    def format_instruction(self, config: Dict[str, Any], user_content_wrapper: str) -> str:
        """Format the instruction template with config values."""
        description = config.get("description", "")

        # Start with the template
        formatted_template = self.template

        # The templates from the standard schema already contain the user content wrapper
        # pattern ([{<{description}>}]), so we just substitute the description directly
        formatted_template = formatted_template.replace("{description}", description)

        # Replace other config placeholders
        for key, value in config.items():
            if key != "description":
                placeholder = "{" + key + "}"
                formatted_template = formatted_template.replace(placeholder, str(value))

        return formatted_template
