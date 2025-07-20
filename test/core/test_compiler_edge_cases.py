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

    def test_file_path_resolution_error(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test file path resolution error handling."""
        template_file = temp_directory / "test.json"
        template_file.write_text('{"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}')

        # Mock path resolution to fail
        with patch("pathlib.Path.resolve", side_effect=ValueError("Cannot resolve")):
            # Should handle the resolution error gracefully
            result = compiler.compile_file(str(template_file))
            assert result.prompt is not None

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

    def test_schema_loading_failure_graceful_degradation(self, compiler: ITSCompiler) -> None:
        """Test that compilation fails gracefully when schema loading fails and no custom types exist."""
        template = {
            "version": "1.0.0",
            "extends": ["https://nonexistent.example.com/fake-schema.json"],
            "content": [{"type": "placeholder", "instructionType": "unknownType", "config": {"description": "test"}}],
        }

        # Should fail because it can't load the schema and doesn't have custom types
        with pytest.raises(ITSCompilationError):
            compiler.compile(template)

    def test_circular_variable_reference_handling(self, compiler: ITSCompiler) -> None:
        """Test handling of circular variable references."""
        template = {
            "version": "1.0.0",
            "variables": {"a": "${b}", "b": "${a}"},
            "content": [{"type": "text", "text": "${a}"}],
        }

        # Should handle circular references gracefully
        with pytest.raises((ITSValidationError, ITSCompilationError)):
            compiler.compile(template)

    def test_deeply_nested_conditional_processing(self, compiler: ITSCompiler) -> None:
        """Test processing of deeply nested conditional structures."""
        # Create deeply nested conditionals
        template = {"version": "1.0.0", "content": []}
        current_content = template["content"]

        # Create 10 levels of nesting
        for i in range(10):
            conditional = {"type": "conditional", "condition": f"level{i} == true", "content": []}
            current_content.append(conditional)
            current_content = conditional["content"]

        # Add final content
        current_content.append({"type": "text", "text": "deeply nested"})

        # Create variables for all levels
        variables = {f"level{i}": True for i in range(10)}

        # Should either process successfully or hit nesting limits
        try:
            result = compiler.compile(template, variables)
            assert "deeply nested" in result.prompt
        except (ITSValidationError, ITSCompilationError):
            # Acceptable if nesting limits are hit
            pass

    def test_large_variable_object_processing(self, compiler: ITSCompiler) -> None:
        """Test processing of large variable objects."""
        # Create large variable structure
        large_vars = {}
        for i in range(100):
            large_vars[f"var{i}"] = {"name": f"item{i}", "value": i, "data": [j for j in range(10)]}

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "Processing ${var0.name} and ${var99.name}"}],
        }

        # Should either process successfully or hit variable limits
        try:
            result = compiler.compile(template, large_vars)
            assert "item0" in result.prompt
            assert "item99" in result.prompt
        except (ITSValidationError, ITSCompilationError):
            # Acceptable if variable limits are hit
            pass

    def test_malformed_template_structure_edge_cases(self, compiler: ITSCompiler) -> None:
        """Test various malformed template structures that could cause issues."""
        malformed_templates = [
            # Template with null values
            {"version": "1.0.0", "content": [None]},
            # Template with mixed content types
            {"version": "1.0.0", "content": [{"type": "text", "text": "ok"}, "invalid"]},
            # Template with recursive references
            {"version": "1.0.0", "content": [{"type": "conditional", "condition": "true", "content": "self"}]},
        ]

        for template in malformed_templates:
            with pytest.raises((ITSValidationError, ITSCompilationError, TypeError)):
                compiler.compile(template)

    def test_extreme_edge_case_file_operations(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test extreme edge cases in file operations."""
        # Test with file that exists but becomes inaccessible
        test_file = temp_directory / "test.json"
        test_file.write_text('{"version": "1.0.0", "content": [{"type": "text", "text": "test"}]}')

        # Mock file stat to simulate permission error
        with patch("pathlib.Path.stat", side_effect=OSError("Permission denied")):
            with pytest.raises(ITSCompilationError):
                compiler.compile_file(str(test_file))

    def test_memory_intensive_template_processing(self, compiler: ITSCompiler) -> None:
        """Test templates that could consume excessive memory."""
        # Template with many large text elements
        large_elements = [{"type": "text", "text": "x" * 1000} for _ in range(100)]

        template = {"version": "1.0.0", "content": large_elements}

        # Should either process or hit memory/size limits
        try:
            result = compiler.compile(template)
            assert len(result.prompt) > 100000  # Should be substantial
        except (ITSValidationError, ITSCompilationError):
            # Acceptable if size limits are hit
            pass
