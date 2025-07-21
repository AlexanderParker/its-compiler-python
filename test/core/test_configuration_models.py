"""
Tests for configuration and model classes.
Tests model functionality, configuration validation, and data structures.
"""

from datetime import datetime

from its_compiler.core.models import (
    AuditTrail,
    CompilationContext,
    CompilationResult,
    InstructionTypeDefinition,
    ITSConfig,
    OverrideType,
    SecurityMetrics,
    SecurityReport,
    TypeOverride,
    ValidationResult,
)


class TestConfigurationModels:
    """Test configuration and model classes."""

    def test_its_config_initialization_and_defaults(self) -> None:
        """Test ITSConfig initialization and default values."""
        config = ITSConfig()

        # Test default values
        assert config.cache_enabled is True
        assert config.cache_ttl == 3600
        assert config.request_timeout == 30
        assert config.max_retries == 3
        assert config.allow_http is False
        assert config.strict_mode is True

        # Test default processing instructions are set
        assert config.default_processing_instructions is not None
        assert len(config.default_processing_instructions) > 0
        assert "Replace each placeholder" in config.default_processing_instructions[0]

    def test_its_config_custom_values(self) -> None:
        """Test ITSConfig with custom values."""
        config = ITSConfig(
            cache_enabled=False,
            request_timeout=60,
            max_retries=5,
            allow_http=True,
            strict_mode=False,
            max_schema_size=20 * 1024 * 1024,
        )

        assert config.cache_enabled is False
        assert config.request_timeout == 60
        assert config.max_retries == 5
        assert config.allow_http is True
        assert config.strict_mode is False
        assert config.max_schema_size == 20 * 1024 * 1024

    def test_its_config_validation_warnings(self) -> None:
        """Test ITSConfig validation warnings."""
        config = ITSConfig()

        # Configure settings that should trigger warnings
        config.allow_http = True
        config.enable_security_features = True
        config.request_timeout = 120
        config.max_schema_size = 100 * 1024 * 1024  # 100MB
        config.cache_enabled = False
        config.max_compilation_time = 1200  # 20 minutes

        warnings = config.validate_config()

        expected_warnings = [
            "HTTP is enabled while security features are active",
            "Request timeout is very high",
            "Schema size limit is very high",
            "Schema caching is disabled",
            "Compilation timeout is very high",
        ]

        for expected in expected_warnings:
            assert any(expected in warning for warning in warnings)

    def test_validation_result_properties(self) -> None:
        """Test ValidationResult properties and methods."""

        # Test valid result
        valid_result = ValidationResult(is_valid=True, errors=[], warnings=["Minor warning"])
        assert bool(valid_result) is True
        assert valid_result.total_issues == 1
        assert not valid_result.has_security_issues

        # Test invalid result with all issue types
        invalid_result = ValidationResult(
            is_valid=False,
            errors=["Error 1", "Error 2"],
            warnings=["Warning 1"],
            security_issues=["Security issue 1", "Security issue 2"],
        )
        assert bool(invalid_result) is False
        assert invalid_result.total_issues == 5
        assert invalid_result.has_security_issues

    def test_compilation_result_properties(self) -> None:
        """Test CompilationResult properties and methods."""

        # Create type override for testing
        override = TypeOverride(
            type_name="paragraph",
            override_source="custom",
            overridden_source="schema.json",
            override_type=OverrideType.CUSTOM,
        )

        # Create compilation result
        result = CompilationResult(
            prompt="Test prompt with unicode: 🚀 and more content",
            template={"version": "1.0.0", "content": []},
            variables={"var1": "value1", "var2": "value2", "var3": "value3"},
            overrides=[override],
            warnings=["Warning 1", "Warning 2"],
            security_events=["Schema access", "Variable validation"],
            compilation_time=2.5,
        )

        # Test properties
        assert result.has_overrides
        assert result.has_warnings
        assert result.has_security_events
        assert result.prompt_size > len(result.prompt)  # UTF-8 encoding

        # Test summary
        summary = result.get_summary()
        assert summary["success"] is True
        assert summary["variables_count"] == 3
        assert summary["overrides_count"] == 1
        assert summary["warnings_count"] == 2
        assert summary["security_events_count"] == 2
        assert summary["compilation_time"] == 2.5
        assert summary["prompt_size_bytes"] == result.prompt_size

    def test_security_metrics_operations(self) -> None:
        """Test SecurityMetrics operations and methods."""
        metrics = SecurityMetrics()

        # Set various metrics
        metrics.schemas_fetched = 3
        metrics.allowlist_checks = 7
        metrics.rate_limit_hits = 1
        metrics.security_violations = 2
        metrics.expressions_sanitised = 5
        metrics.variables_validated = 12

        # Test to_dict conversion
        metrics_dict = metrics.to_dict()
        expected_keys = [
            "schemas_fetched",
            "allowlist_checks",
            "rate_limit_hits",
            "security_violations",
            "expressions_sanitised",
            "variables_validated",
        ]

        for key in expected_keys:
            assert key in metrics_dict
            assert isinstance(metrics_dict[key], int)

        assert metrics_dict["schemas_fetched"] == 3
        assert metrics_dict["security_violations"] == 2

    def test_instruction_type_definition_comprehensive(self) -> None:
        """Test InstructionTypeDefinition comprehensive functionality."""

        # Test basic instruction type
        inst_type = InstructionTypeDefinition(
            name="paragraph",
            template="Write a paragraph: ([{<{description}>}])",
            description="Generates a paragraph of text",
            source="test-schema.json",
        )

        # Test instruction formatting
        config = {"description": "About sustainable technology"}
        formatted = inst_type.format_instruction(config, "([{<{content}>}])")
        assert "About sustainable technology" in formatted
        assert "Write a paragraph:" in formatted

        # Test with complex config
        complex_type = InstructionTypeDefinition(
            name="complex", template="Write a {style} text of {length} length: ([{<{description}>}])"
        )

        complex_config = {"description": "Complex instruction", "style": "formal", "length": "medium"}

        complex_formatted = complex_type.format_instruction(complex_config, "([{<{content}>}])")
        assert "formal" in complex_formatted
        assert "medium" in complex_formatted
        assert "Complex instruction" in complex_formatted

        # Test security validation
        safe_security_issues = inst_type.validate_template_security()
        assert len(safe_security_issues) == 0

        # Test dangerous template
        dangerous_type = InstructionTypeDefinition(
            name="dangerous", template="<script>alert('xss')</script> ([{<{description}>}])"
        )

        dangerous_issues = dangerous_type.validate_template_security()
        assert len(dangerous_issues) > 0
        assert any("script" in issue.lower() for issue in dangerous_issues)

        # Test metadata
        metadata = inst_type.get_metadata()
        assert metadata["name"] == "paragraph"
        assert metadata["source"] == "test-schema.json"
        assert metadata["has_description"] is True
        assert metadata["has_config_schema"] is False
        assert metadata["template_length"] > 0
        assert metadata["security_validated"] is False

    def test_type_override_functionality(self) -> None:
        """Test TypeOverride functionality."""

        # Test custom override
        custom_override = TypeOverride(
            type_name="paragraph",
            override_source="customInstructionTypes",
            overridden_source="standard-schema.json",
            override_type=OverrideType.CUSTOM,
        )

        assert custom_override.type_name == "paragraph"
        assert custom_override.override_type == OverrideType.CUSTOM

        # Test schema override
        schema_override = TypeOverride(
            type_name="list",
            override_source="company-schema.json",
            overridden_source="base-schema.json",
            override_type=OverrideType.SCHEMA_EXTENSION,
        )

        assert schema_override.override_type == OverrideType.SCHEMA_EXTENSION

    def test_compilation_context_comprehensive(self) -> None:
        """Test CompilationContext comprehensive functionality."""

        context = CompilationContext(
            template_path="/path/to/template.json",
            base_url="https://example.com/base/",
            start_time=datetime.now(),
            user_id="user123",
            session_id="session456",
            request_id="req789",
        )

        # Set additional context
        context.security_level = "production"
        context.allowed_schemas = ["schema1.json", "schema2.json", "schema3.json"]
        context.blocked_patterns = ["pattern1", "pattern2"]
        context.schema_fetch_time = 1.5
        context.variable_processing_time = 0.8
        context.conditional_evaluation_time = 0.3
        context.prompt_generation_time = 0.2

        # Test to_dict conversion
        context_dict = context.to_dict()
        assert context_dict["template_path"] == "/path/to/template.json"
        assert context_dict["base_url"] == "https://example.com/base/"
        assert context_dict["user_id"] == "user123"
        assert context_dict["security_level"] == "production"
        assert context_dict["allowed_schemas_count"] == 3
        assert context_dict["blocked_patterns_count"] == 2
        assert context_dict["performance"]["schema_fetch_time"] == 1.5
        assert context_dict["performance"]["variable_processing_time"] == 0.8

    def test_security_report_risk_calculation(self) -> None:
        """Test SecurityReport risk calculation and reporting."""

        report = SecurityReport(
            template_path="test-template.json", analysis_time=datetime.now(), security_level="production"
        )

        # Test low risk scenario
        report.vulnerabilities = []
        report.warnings = ["Minor warning"]
        report.untrusted_schemas = 0
        report.dangerous_patterns_found = 0

        risk_score = report.calculate_risk_score()
        assert report.risk_level == "low"
        assert risk_score < 2.0

        # Test medium risk scenario
        report.vulnerabilities = []
        report.warnings = ["Warning 1", "Warning 2"]
        report.untrusted_schemas = 1
        report.dangerous_patterns_found = 0

        risk_score = report.calculate_risk_score()
        assert report.risk_level == "medium"
        assert 2.0 <= risk_score < 5.0

        # Test high risk scenario
        report.vulnerabilities = ["High vulnerability"]
        report.warnings = ["Warning 1"]
        report.untrusted_schemas = 1
        report.dangerous_patterns_found = 0

        risk_score = report.calculate_risk_score()
        assert report.risk_level == "high"
        assert 5.0 <= risk_score < 7.0

        # Test critical risk scenario
        report.vulnerabilities = ["Critical 1", "Critical 2", "Critical 3"]
        report.warnings = ["Warning 1"]
        report.untrusted_schemas = 0
        report.dangerous_patterns_found = 0

        risk_score = report.calculate_risk_score()
        assert report.risk_level == "critical"
        assert risk_score >= 7.0

        # Test report dictionary conversion
        report_dict = report.to_dict()
        assert "template_path" in report_dict
        assert "risk_score" in report_dict
        assert "risk_level" in report_dict
        assert "findings" in report_dict
        assert "analysis" in report_dict
        assert len(report_dict["findings"]["vulnerabilities"]) == 3

    def test_audit_trail_operations(self) -> None:
        """Test AuditTrail operations and functionality."""

        audit = AuditTrail(
            operation_id="compile_001",
            operation_type="compile",
            timestamp=datetime.now(),
            user_id="user456",
            template_path="template.json",
        )

        # Set operation details
        audit.success = True
        audit.duration_seconds = 2.5
        audit.result_size_bytes = 2048
        audit.warnings_count = 1
        audit.overrides_count = 2

        # Add security events
        audit.add_security_event("Schema validation completed")
        audit.add_security_event("Variable sanitisation applied")
        audit.add_security_event("Expression validation passed")

        # Add accessed resources
        audit.schemas_accessed = ["schema1.json", "schema2.json"]
        audit.variables_processed = ["user", "product", "settings"]

        # Test to_dict conversion
        audit_dict = audit.to_dict()
        assert audit_dict["operation_id"] == "compile_001"
        assert audit_dict["operation_type"] == "compile"
        assert audit_dict["success"] is True
        assert audit_dict["duration_seconds"] == 2.5
        assert audit_dict["security_events_count"] == 3
        assert audit_dict["schemas_accessed_count"] == 2
        assert audit_dict["variables_processed_count"] == 3
        assert audit_dict["result_size_bytes"] == 2048
        assert audit_dict["warnings_count"] == 1
        assert audit_dict["overrides_count"] == 2

    def test_audit_trail_error_scenario(self) -> None:
        """Test AuditTrail with error scenario."""

        audit = AuditTrail(operation_id="validate_001", operation_type="validate", timestamp=datetime.now())

        # Set error details
        audit.success = False
        audit.error_message = "Template validation failed"
        audit.duration_seconds = 0.5

        audit.add_security_event("Security violation detected")

        audit_dict = audit.to_dict()
        assert audit_dict["success"] is False
        assert audit_dict["error_message"] == "Template validation failed"
        assert audit_dict["security_events_count"] == 1

    def test_instruction_type_with_config_schema(self) -> None:
        """Test InstructionTypeDefinition with config schema."""

        inst_type = InstructionTypeDefinition(
            name="styled_text",
            template="Write {style} text: ([{<{description}>}])",
            description="Generates styled text",
            config_schema={
                "type": "object",
                "properties": {
                    "style": {"type": "string", "enum": ["formal", "casual", "technical"]},
                    "length": {"type": "string", "enum": ["short", "medium", "long"]},
                },
                "required": ["style"],
            },
        )

        metadata = inst_type.get_metadata()
        assert metadata["has_config_schema"] is True

        # Test with valid config
        valid_config = {"description": "Test description", "style": "formal"}
        formatted = inst_type.format_instruction(valid_config, "([{<{content}>}])")
        assert "formal" in formatted

    def test_security_metrics_default_values(self) -> None:
        """Test SecurityMetrics default values."""

        metrics = SecurityMetrics()

        # Test all default values are zero
        assert metrics.schemas_fetched == 0
        assert metrics.allowlist_checks == 0
        assert metrics.rate_limit_hits == 0
        assert metrics.security_violations == 0
        assert metrics.expressions_sanitised == 0
        assert metrics.variables_validated == 0

        # Test to_dict with defaults
        metrics_dict = metrics.to_dict()
        for value in metrics_dict.values():
            assert value == 0

    def test_compilation_result_empty_collections(self) -> None:
        """Test CompilationResult with empty collections."""

        result = CompilationResult(
            prompt="Simple prompt", template={"version": "1.0.0"}, variables={}, overrides=[], warnings=[]
        )

        assert not result.has_overrides
        assert not result.has_warnings
        assert not result.has_security_events

        summary = result.get_summary()
        assert summary["variables_count"] == 0
        assert summary["overrides_count"] == 0
        assert summary["warnings_count"] == 0

    def test_validation_result_timing(self) -> None:
        """Test ValidationResult with timing information."""

        result = ValidationResult(is_valid=True, errors=[], warnings=[], validation_time=0.125)

        assert result.validation_time == 0.125

    def test_compilation_context_minimal(self) -> None:
        """Test CompilationContext with minimal information."""

        context = CompilationContext()

        # Test defaults
        assert context.template_path is None
        assert context.security_level == "production"
        assert len(context.allowed_schemas) == 0
        assert len(context.blocked_patterns) == 0

        # Test to_dict with minimal data
        context_dict = context.to_dict()
        assert context_dict["template_path"] is None
        assert context_dict["security_level"] == "production"
        assert context_dict["allowed_schemas_count"] == 0
