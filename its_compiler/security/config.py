"""
Security configuration for ITS Compiler.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from pathlib import Path


@dataclass
class NetworkSecurityConfig:
    """Network-related security configuration."""

    # Protocol restrictions
    allowed_protocols: Set[str] = field(default_factory=lambda: {"https"})
    allow_http: bool = False
    block_file_urls: bool = True
    block_data_urls: bool = True

    # Domain controls
    domain_allowlist: List[str] = field(
        default_factory=lambda: ["alexanderparker.github.io"]
    )
    enforce_domain_allowlist: bool = True

    # SSRF protection
    block_private_networks: bool = True
    block_localhost: bool = True
    block_link_local: bool = True
    blocked_ip_ranges: List[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8",  # Loopback
            "10.0.0.0/8",  # Private Class A
            "172.16.0.0/12",  # Private Class B
            "192.168.0.0/16",  # Private Class C
            "169.254.0.0/16",  # Link-local
            "224.0.0.0/4",  # Multicast
            "::1/128",  # IPv6 loopback
            "fc00::/7",  # IPv6 private
            "fe80::/10",  # IPv6 link-local
        ]
    )

    # Request limits
    request_timeout: int = 10
    max_retries: int = 2
    max_redirects: int = 3
    max_response_size: int = 10 * 1024 * 1024  # 10MB


@dataclass
class ProcessingSecurityConfig:
    """Processing-related security configuration."""

    # Template limits
    max_template_size: int = 1024 * 1024  # 1MB
    max_content_elements: int = 1000
    max_nesting_depth: int = 10
    max_variable_references: int = 100

    # Variable processing
    max_variable_name_length: int = 100
    max_property_chain_depth: int = 10
    max_array_index: int = 1000
    allowed_variable_chars: str = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    )

    # Conditional expressions
    max_expression_length: int = 500
    max_expression_depth: int = 10
    max_expression_nodes: int = 100
    blocked_ast_nodes: Set[str] = field(
        default_factory=lambda: {
            "Import",
            "ImportFrom",
            "FunctionDef",
            "AsyncFunctionDef",
            "ClassDef",
            "Global",
            "Nonlocal",
            "Exec",
            "Eval",
            "Call",
            "Lambda",
            "Yield",
            "YieldFrom",
            "Await",
            "GeneratorExp",
            "ListComp",
            "SetComp",
            "DictComp",
        }
    )

    # Processing limits
    max_processing_time: int = 30  # seconds
    max_memory_usage: int = 100 * 1024 * 1024  # 100MB


@dataclass
class AllowlistConfig:
    """Schema allowlist configuration."""

    # Storage
    allowlist_file: Optional[str] = None  # Auto-detected if None
    auto_save: bool = True
    backup_on_change: bool = True

    # Interactive behaviour
    interactive_mode: bool = True
    auto_approve_in_ci: bool = False
    require_confirmation: bool = True

    # Trust levels
    default_trust_level: str = "session"  # session, permanent, never
    allow_downgrades: bool = False

    # Validation
    verify_schema_signatures: bool = False
    cache_schema_metadata: bool = True
    check_schema_changes: bool = True


@dataclass
class SecurityConfig:
    """Main security configuration class."""

    # Component configurations
    network: NetworkSecurityConfig = field(default_factory=NetworkSecurityConfig)
    processing: ProcessingSecurityConfig = field(
        default_factory=ProcessingSecurityConfig
    )
    allowlist: AllowlistConfig = field(default_factory=AllowlistConfig)

    # Feature toggles
    enable_allowlist: bool = True
    enable_input_validation: bool = True
    enable_expression_sanitisation: bool = True

    @classmethod
    def from_environment(cls) -> "SecurityConfig":
        """Create security config from environment variables."""
        config = cls()

        # Network configuration
        if os.getenv("ITS_ALLOW_HTTP") == "true":
            config.network.allowed_protocols.add("http")
            config.network.allow_http = True

        if os.getenv("ITS_BLOCK_PRIVATE_NETWORKS") == "false":
            config.network.block_private_networks = False

        if os.getenv("ITS_BLOCK_LOCALHOST") == "false":
            config.network.block_localhost = False

        if timeout := os.getenv("ITS_REQUEST_TIMEOUT"):
            config.network.request_timeout = int(timeout)

        if max_size := os.getenv("ITS_MAX_RESPONSE_SIZE"):
            config.network.max_response_size = int(max_size)

        # Domain allowlist
        if domains := os.getenv("ITS_DOMAIN_ALLOWLIST"):
            config.network.domain_allowlist = domains.split(",")

        # Allowlist configuration
        if allowlist_file := os.getenv("ITS_ALLOWLIST_FILE"):
            config.allowlist.allowlist_file = allowlist_file

        if os.getenv("ITS_INTERACTIVE_ALLOWLIST") == "false":
            config.allowlist.interactive_mode = False

        if os.getenv("ITS_AUTO_APPROVE_CI") == "true":
            config.allowlist.auto_approve_in_ci = True

        # Processing limits
        if max_template_size := os.getenv("ITS_MAX_TEMPLATE_SIZE"):
            config.processing.max_template_size = int(max_template_size)

        if max_elements := os.getenv("ITS_MAX_CONTENT_ELEMENTS"):
            config.processing.max_content_elements = int(max_elements)

        if max_depth := os.getenv("ITS_MAX_NESTING_DEPTH"):
            config.processing.max_nesting_depth = int(max_depth)

        # Feature toggles
        if os.getenv("ITS_DISABLE_ALLOWLIST") == "true":
            config.enable_allowlist = False

        if os.getenv("ITS_DISABLE_INPUT_VALIDATION") == "true":
            config.enable_input_validation = False

        if os.getenv("ITS_DISABLE_EXPRESSION_SANITISATION") == "true":
            config.enable_expression_sanitisation = False

        return config

    @classmethod
    def for_development(cls) -> "SecurityConfig":
        """Create development-friendly security config."""
        config = cls()
        config.network.allowed_protocols = {"http", "https"}
        config.network.allow_http = True
        config.network.block_localhost = False
        config.network.block_private_networks = False
        config.allowlist.interactive_mode = True
        config.processing.max_template_size = 5 * 1024 * 1024  # 5MB
        config.processing.max_content_elements = 2000
        config.processing.max_nesting_depth = 15
        return config

    @classmethod
    def for_ci(cls) -> "SecurityConfig":
        """Create CI/CD-friendly security config."""
        config = cls()
        config.allowlist.interactive_mode = False
        config.allowlist.auto_approve_in_ci = True
        config.allowlist.require_confirmation = False
        return config

    def get_allowlist_path(self) -> Path:
        """Get the path to the allowlist file."""
        if self.allowlist.allowlist_file:
            return Path(self.allowlist.allowlist_file).expanduser()

        # Default location
        config_dir = Path.home() / ".its-compiler"
        config_dir.mkdir(exist_ok=True)
        return config_dir / "schema_allowlist.json"

    def is_development(self) -> bool:
        """Check if running in development mode based on settings."""
        return (
            self.network.allow_http
            and not self.network.block_localhost
            and self.allowlist.interactive_mode
        )

    def is_production(self) -> bool:
        """Check if running in production mode based on settings."""
        return (
            not self.network.allow_http
            and self.network.block_private_networks
            and not self.allowlist.interactive_mode
        )

    def validate(self) -> List[str]:
        """Validate configuration and return any warnings."""
        warnings = []

        if self.network.allow_http and not self.is_development():
            warnings.append("HTTP is enabled - not recommended for production")

        if not self.network.block_private_networks:
            warnings.append("Private network access is allowed - security risk")

        if self.allowlist.interactive_mode and self.is_production():
            warnings.append("Interactive allowlist mode is enabled in production")

        if self.network.request_timeout > 30:
            warnings.append("Request timeout is very high, may cause hanging")

        if self.processing.max_template_size > 10 * 1024 * 1024:  # 10MB
            warnings.append("Template size limit is very high")

        if not self.enable_allowlist:
            warnings.append("Schema allowlist is disabled - security risk")

        return warnings
