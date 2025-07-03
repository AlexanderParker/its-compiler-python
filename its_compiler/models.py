"""
Data models for ITS Compiler with security enhancements.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


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
    """Result of template validation with security details."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]
    security_issues: List[str] = field(default_factory=list)
    validation_time: Optional[float] = None

    def __bool__(self) -> bool:
        return self.is_valid

    @property
    def has_security_issues(self) -> bool:
        """Check if any security issues were found."""
        return len(self.security_issues) > 0

    @property
    def total_issues(self) -> int:
        """Get total count of all issues."""
        return len(self.errors) + len(self.warnings) + len(self.security_issues)


@dataclass
class SecurityMetrics:
    """Security metrics for compilation process."""

    schemas_fetched: int = 0
    allowlist_checks: int = 0
    rate_limit_hits: int = 0
    security_violations: int = 0
    expressions_sanitised: int = 0
    variables_validated: int = 0

    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary for logging."""
        return {
            "schemas_fetched": self.schemas_fetched,
            "allowlist_checks": self.allowlist_checks,
            "rate_limit_hits": self.rate_limit_hits,
            "security_violations": self.security_violations,
            "expressions_sanitised": self.expressions_sanitised,
            "variables_validated": self.variables_validated,
        }


@dataclass
class CompilationResult:
    """Result of template compilation with security information."""

    prompt: str
    template: Dict[str, Any]
    variables: Dict[str, Any]
    overrides: List[TypeOverride]
    warnings: List[str]
    security_metrics: SecurityMetrics = field(default_factory=SecurityMetrics)
    compilation_time: Optional[float] = None
    security_events: List[str] = field(default_factory=list)

    @property
    def has_overrides(self) -> bool:
        """Check if any type overrides occurred."""
        return len(self.overrides) > 0

    @property
    def has_warnings(self) -> bool:
        """Check if any warnings were generated."""
        return len(self.warnings) > 0

    @property
    def has_security_events(self) -> bool:
        """Check if any security events occurred."""
        return len(self.security_events) > 0

    @property
    def prompt_size(self) -> int:
        """Get prompt size in bytes."""
        return len(self.prompt.encode("utf-8"))

    def get_summary(self) -> Dict[str, Any]:
        """Get compilation summary."""
        return {
            "success": True,
            "prompt_length": len(self.prompt),
            "prompt_size_bytes": self.prompt_size,
            "variables_count": len(self.variables),
            "overrides_count": len(self.overrides),
            "warnings_count": len(self.warnings),
            "security_events_count": len(self.security_events),
            "compilation_time": self.compilation_time,
            "security_metrics": self.security_metrics.to_dict(),
        }


@dataclass
class ITSConfig:
    """Configuration for ITS Compiler with security awareness."""

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

    # Security integration
    enable_security_features: bool = True
    security_config_path: Optional[str] = None

    # Performance monitoring
    enable_performance_monitoring: bool = False
    max_compilation_time: int = 300  # 5 minutes
    memory_limit_mb: int = 512

    # Default compiler configuration
    default_system_prompt: str = (
        "You are an AI assistant that fills in content templates. "
        "Follow the instructions exactly and replace each placeholder with "
        "appropriate content based on the user prompts provided. "
        "Respond only with the transformed content."
    )
    default_instruction_wrapper: str = "<<{instruction}>>"
    default_user_content_wrapper: str = "([{<{content}>}])"
    default_processing_instructions: Optional[List[str]] = None

    def __post_init__(self) -> None:
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

    def validate_config(self) -> List[str]:
        """Validate configuration and return warnings."""
        warnings: List[str] = []

        if self.allow_http and self.enable_security_features:
            warnings.append("HTTP is enabled while security features are active")

        if self.request_timeout > 60:
            warnings.append("Request timeout is very high")

        if self.max_schema_size > 50 * 1024 * 1024:  # 50MB
            warnings.append("Schema size limit is very high")

        if not self.cache_enabled:
            warnings.append("Schema caching is disabled - may impact performance")

        if self.max_compilation_time > 600:  # 10 minutes
            warnings.append("Compilation timeout is very high")

        return warnings


@dataclass
class InstructionTypeDefinition:
    """Definition of an instruction type with security metadata."""

    name: str
    template: str
    description: Optional[str] = None
    config_schema: Optional[Dict[str, Any]] = None
    source: Optional[str] = None  # Source schema or "custom"
    security_validated: bool = False
    validation_time: Optional[datetime] = None

    def format_instruction(
        self, config: Dict[str, Any], user_content_wrapper: str
    ) -> str:
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

    def validate_template_security(self) -> List[str]:
        """Validate template for security issues."""
        issues: List[str] = []

        # Check for dangerous patterns
        dangerous_patterns = [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"data\s*:\s*text/html",
            r"eval\s*\(",
            r"Function\s*\(",
        ]

        import re

        for pattern in dangerous_patterns:
            if re.search(pattern, self.template, re.IGNORECASE):
                issues.append(f"Dangerous pattern detected: {pattern}")

        return issues

    def get_metadata(self) -> Dict[str, Any]:
        """Get instruction type metadata."""
        return {
            "name": self.name,
            "source": self.source,
            "has_description": self.description is not None,
            "has_config_schema": self.config_schema is not None,
            "template_length": len(self.template),
            "security_validated": self.security_validated,
            "validation_time": (
                self.validation_time.isoformat() if self.validation_time else None
            ),
        }


@dataclass
class CompilationContext:
    """Context information for compilation process."""

    template_path: Optional[str] = None
    base_url: Optional[str] = None
    start_time: Optional[datetime] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    # Security context
    security_level: str = "production"
    allowed_schemas: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)

    # Performance tracking
    schema_fetch_time: float = 0.0
    variable_processing_time: float = 0.0
    conditional_evaluation_time: float = 0.0
    prompt_generation_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for logging."""
        return {
            "template_path": self.template_path,
            "base_url": self.base_url,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "security_level": self.security_level,
            "allowed_schemas_count": len(self.allowed_schemas),
            "blocked_patterns_count": len(self.blocked_patterns),
            "performance": {
                "schema_fetch_time": self.schema_fetch_time,
                "variable_processing_time": self.variable_processing_time,
                "conditional_evaluation_time": self.conditional_evaluation_time,
                "prompt_generation_time": self.prompt_generation_time,
            },
        }


@dataclass
class SecurityReport:
    """Security analysis report for templates."""

    template_path: Optional[str]
    analysis_time: datetime
    security_level: str

    # Findings
    vulnerabilities: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # Schema analysis
    schemas_analyzed: int = 0
    trusted_schemas: int = 0
    untrusted_schemas: int = 0

    # Content analysis
    variables_analyzed: int = 0
    expressions_analyzed: int = 0
    dangerous_patterns_found: int = 0

    # Risk assessment
    risk_score: float = 0.0  # 0.0 (low) to 10.0 (critical)
    risk_level: str = "low"  # low, medium, high, critical

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score."""
        score = 0.0

        # Vulnerabilities have high impact
        score += len(self.vulnerabilities) * 3.0

        # Warnings have medium impact
        score += len(self.warnings) * 1.0

        # Untrusted schemas increase risk
        score += self.untrusted_schemas * 2.0

        # Dangerous patterns increase risk
        score += self.dangerous_patterns_found * 1.5

        # Cap at 10.0
        self.risk_score = min(score, 10.0)

        # Determine risk level
        if self.risk_score >= 7.0:
            self.risk_level = "critical"
        elif self.risk_score >= 5.0:
            self.risk_level = "high"
        elif self.risk_score >= 2.0:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"

        return self.risk_score

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "template_path": self.template_path,
            "analysis_time": self.analysis_time.isoformat(),
            "security_level": self.security_level,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": {
                "vulnerabilities": self.vulnerabilities,
                "warnings": self.warnings,
                "recommendations": self.recommendations,
            },
            "analysis": {
                "schemas_analyzed": self.schemas_analyzed,
                "trusted_schemas": self.trusted_schemas,
                "untrusted_schemas": self.untrusted_schemas,
                "variables_analyzed": self.variables_analyzed,
                "expressions_analyzed": self.expressions_analyzed,
                "dangerous_patterns_found": self.dangerous_patterns_found,
            },
        }


@dataclass
class AuditTrail:
    """Audit trail for compilation operations."""

    operation_id: str
    operation_type: str  # compile, validate, analyze
    timestamp: datetime
    user_id: Optional[str] = None
    template_path: Optional[str] = None

    # Operation details
    success: bool = True
    error_message: Optional[str] = None
    duration_seconds: float = 0.0

    # Security events
    security_events: List[str] = field(default_factory=list)
    schemas_accessed: List[str] = field(default_factory=list)
    variables_processed: List[str] = field(default_factory=list)

    # Result metadata
    result_size_bytes: int = 0
    warnings_count: int = 0
    overrides_count: int = 0

    def add_security_event(self, event: str) -> None:
        """Add a security event to the audit trail."""
        self.security_events.append(event)

    def to_dict(self) -> Dict[str, Any]:
        """Convert audit trail to dictionary for storage."""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "template_path": self.template_path,
            "success": self.success,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "security_events_count": len(self.security_events),
            "schemas_accessed_count": len(self.schemas_accessed),
            "variables_processed_count": len(self.variables_processed),
            "result_size_bytes": self.result_size_bytes,
            "warnings_count": self.warnings_count,
            "overrides_count": self.overrides_count,
        }
