"""
Tests for edge cases and error scenarios in the ITSCompiler.
Tests scenarios that are difficult to trigger through normal integration tests.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from its_compiler import ITSCompiler, ITSConfig
from its_compiler.core.exceptions import ITSCompilationError, ITSValidationError
from its_compiler.security import SecurityConfig


class TestCompilerEdgeCases:
    """Test edge cases and error scenarios in the compiler."""

    @pytest.fixture
    def temp_directory(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    @pytest.fixture
    def compiler(self) -> ITSCompiler:
        """Create compiler instance."""
        return ITSCompiler()

    def test_compiler_initialization_variants(self) -> None:
        """Test different compiler initialization scenarios."""
        # Default initialization
        compiler1 = ITSCompiler()
        assert compiler1.config is not None
        assert compiler1.security_config is not None

        # With custom config
        config = ITSConfig(cache_enabled=False, strict_mode=False)
        compiler2 = ITSCompiler(config=config)
        assert compiler2.config.cache_enabled is False
        assert compiler2.config.strict_mode is False

        # With custom security config
        security_config = SecurityConfig.for_development()
        compiler3 = ITSCompiler(security_config=security_config)
        assert compiler3.security_config.is_development()

        # With both configs
        compiler4 = ITSCompiler(config, security_config)
        assert compiler4.config.cache_enabled is False
        assert compiler4.security_config.is_development()

    def test_file_not_found_error(self, compiler: ITSCompiler) -> None:
        """Test compilation of non-existent file."""
        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile_file("nonexistent.json")
        assert "not found" in str(exc_info.value)

    def test_invalid_json_file(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test compilation of file with invalid JSON."""
        invalid_json_file = temp_directory / "invalid.json"
        invalid_json_file.write_text("invalid json content")

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile_file(str(invalid_json_file))
        assert "Invalid JSON" in str(exc_info.value)

    def test_file_validation_edge_cases(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test file validation edge cases."""
        # Test validation of non-existent file
        validation_result = compiler.validate_file("nonexistent.json")
        assert not validation_result.is_valid
        assert "not found" in validation_result.errors[0]

        # Test validation of invalid JSON file
        invalid_json_file = temp_directory / "invalid.json"
        invalid_json_file.write_text("invalid json content")

        validation_result = compiler.validate_file(str(invalid_json_file))
        assert not validation_result.is_valid
        assert "Invalid JSON" in validation_result.errors[0]

    def test_file_path_resolution_error(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test file path resolution error handling."""
        template_file = temp_directory / "test.json"
        template_file.write_text('{"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}')

        # Mock path resolution to fail
        with patch("pathlib.Path.resolve", side_effect=ValueError("Cannot resolve")):
            # Should handle the resolution error gracefully
            result = compiler.compile_file(str(template_file))
            assert result.prompt is not None

    def test_file_security_validation_warnings(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test file security validation warning scenarios."""
        # Test unusual file extension
        unusual_file = temp_directory / "template.unusual"
        unusual_file.write_text('{"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}')

        with patch("builtins.print") as mock_print:
            compiler.compile_file(str(unusual_file))
            # Should warn about unusual extension
            print_calls = [str(call) for call in mock_print.call_args_list]
            warning_found = any("unusual" in call.lower() for call in print_calls)
            assert warning_found

        # Test suspicious filename pattern
        suspicious_file = temp_directory / "test..suspicious.json"
        suspicious_file.write_text('{"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}')

        with patch("builtins.print") as mock_print:
            compiler.compile_file(str(suspicious_file))
            print_calls = [str(call) for call in mock_print.call_args_list]
            warning_found = any("suspicious" in call.lower() for call in print_calls)
            assert warning_found

    def test_unknown_instruction_type_error(self, compiler: ITSCompiler) -> None:
        """Test error when instruction type is not found."""
        template = {
            "version": "1.0.0",
            "content": [
                {"type": "placeholder", "instructionType": "nonExistentType", "config": {"description": "test"}}
            ],
        }

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template)

        error_msg = str(exc_info.value)
        assert "unknown instruction type" in error_msg.lower()
        assert "nonExistentType" in error_msg

    def test_instruction_type_missing_config(self, compiler: ITSCompiler) -> None:
        """Test instruction type with missing required config."""
        template = {
            "version": "1.0.0",
            "customInstructionTypes": {"test": {"template": "Test: {required_field}"}},
            "content": [
                {
                    "type": "placeholder",
                    "instructionType": "test",
                    "config": {"description": "test"},  # Missing required_field
                }
            ],
        }

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template)

        assert "Missing required configuration" in str(exc_info.value)

    def test_template_validation_comprehensive(self, compiler: ITSCompiler) -> None:
        """Test comprehensive template validation scenarios."""

        # Valid template
        valid_template = {"version": "1.0.0", "content": [{"type": "text", "text": "Hello world"}]}
        result = compiler.validate(valid_template)
        assert result.is_valid
        assert len(result.errors) == 0

        # Test validation with base URL
        result_with_base = compiler.validate(valid_template, "https://example.com/")
        assert result_with_base.is_valid

        # Invalid templates
        invalid_templates = [
            # Missing version
            ({"content": [{"type": "text", "text": "test"}]}, "Missing required field: version"),
            # Missing content
            ({"version": "1.0.0"}, "Missing required field: content"),
            # Empty content
            ({"version": "1.0.0", "content": []}, "cannot be empty"),
            # Invalid content type
            ({"version": "1.0.0", "content": "not a list"}, "must be an array"),
            # Invalid content element
            ({"version": "1.0.0", "content": ["not a dict"]}, "must be an object"),
            # Missing element type
            ({"version": "1.0.0", "content": [{"no_type": "value"}]}, "missing required field: type"),
        ]

        for invalid_template, expected_error in invalid_templates:
            result = compiler.validate(invalid_template)
            assert not result.is_valid
            assert len(result.errors) > 0
            assert any(expected_error in error for error in result.errors)

    def test_placeholder_config_validation(self, compiler: ITSCompiler) -> None:
        """Test placeholder config validation edge cases."""

        # Placeholder with invalid config type
        template = {
            "version": "1.0.0",
            "content": [
                {"type": "placeholder", "instructionType": "test", "config": "not an object"}  # Should be object
            ],
        }

        result = compiler.validate(template)
        assert not result.is_valid
        assert any("config must be an object" in error for error in result.errors)

    def test_custom_instruction_types_with_overrides(self, compiler: ITSCompiler) -> None:
        """Test custom instruction types that override schema types."""

        template = {
            "version": "1.0.0",
            "customInstructionTypes": {
                "paragraph": {  # Override standard paragraph type
                    "template": "CUSTOM PARAGRAPH: ([{<{description}>}])",
                    "description": "Custom paragraph that overrides standard",
                }
            },
            "content": [
                {"type": "placeholder", "instructionType": "paragraph", "config": {"description": "Test paragraph"}}
            ],
        }

        result = compiler.compile(template)
        assert "CUSTOM PARAGRAPH:" in result.prompt
        assert "Test paragraph" in result.prompt

        # Check that override was reported
        assert len(result.overrides) > 0
        override = result.overrides[0]
        assert override.type_name == "paragraph"
        assert override.override_source == "customInstructionTypes"

    def test_base_url_resolution(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test base URL resolution for file compilation."""

        template = {"version": "1.0.0", "content": [{"type": "text", "text": "Test with base URL"}]}

        template_file = temp_directory / "test.json"
        template_file.write_text(json.dumps(template))

        result = compiler.compile_file(str(template_file))
        assert result.prompt is not None
        assert "Test with base URL" in result.prompt

    def test_final_prompt_security_validation(self, compiler: ITSCompiler) -> None:
        """Test final prompt security validation."""

        # Test with content that generates large prompt
        large_content = "x" * 1000
        template = {"version": "1.0.0", "content": [{"type": "text", "text": large_content}] * 50}

        # Should handle large prompts without issue
        result = compiler.compile(template)
        assert result.prompt is not None
        assert len(result.prompt) > 50000  # Should be substantial

    def test_compiler_with_disabled_security_components(self) -> None:
        """Test compiler with various security components disabled."""

        config = ITSConfig()
        security_config = SecurityConfig.for_development()
        security_config.enable_input_validation = False
        security_config.enable_expression_sanitisation = False
        security_config.enable_allowlist = False

        compiler = ITSCompiler(config, security_config)

        template = {"version": "1.0.0", "content": [{"type": "text", "text": "Test with disabled security"}]}

        result = compiler.compile(template)
        assert result.prompt is not None

        # Security status should reflect disabled components
        status = compiler.get_security_status()
        assert not status["features"]["input_validation"]
        assert not status["features"]["expression_sanitisation"]
        assert not status["features"]["allowlist"]
