"""
Tests for edge cases and error scenarios in the ITSCompiler.
Tests scenarios that are difficult to trigger through normal integration tests.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Generator, List, Sequence
from unittest.mock import patch

import pytest

from its_compiler import ITSCompiler, ITSConfig
from its_compiler.core.exceptions import ITSCompilationError, ITSValidationError, ITSVariableError
from its_compiler.security import SecurityConfig


class TestCompilerEdgeCases:
    """Test edge cases and error scenarios in the compiler."""

    @pytest.fixture
    def temp_directory(self) -> Generator[Path, None, None]:
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
        template_content = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
        }

        template_file = temp_directory / "test.json"
        with open(template_file, "w") as f:
            json.dump(template_content, f)

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

    def test_custom_instruction_types_with_overrides(self, compiler: ITSCompiler, template_fetcher: Any) -> None:
        """Test custom instruction types that override schema types."""

        # Fetch the new template that demonstrates type overrides
        template = template_fetcher.fetch_template("11-override-types.json")

        result = compiler.compile(template)
        assert "CUSTOM LIST FORMAT:" in result.prompt
        assert "Create a custom formatted list" in result.prompt
        assert "Style: bullet_points" in result.prompt

        # Check that override was reported
        assert len(result.overrides) > 0
        override = result.overrides[0]
        assert override.type_name == "list"
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

    def test_deeply_nested_conditional_processing(self, compiler: ITSCompiler) -> None:
        """Test processing of deeply nested conditional structures."""
        # Create deeply nested conditionals
        template: Dict[str, Any] = {"version": "1.0.0", "content": []}
        current_content: List[Dict[str, Any]] = template["content"]

        # Create 10 levels of nesting
        for i in range(10):
            conditional: Dict[str, Any] = {"type": "conditional", "condition": f"level{i} == true", "content": []}
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
        except (ITSValidationError, ITSCompilationError, ITSVariableError):
            # Acceptable if variable limits are hit
            pass

    def test_extreme_edge_case_file_operations(self, compiler: ITSCompiler, temp_directory: Path) -> None:
        """Test extreme edge cases in file operations."""
        # Create a file that will cause issues during security validation
        test_file = temp_directory / "test.json"

        # First, let's patch the security config to have a very small limit
        original_max_size = compiler.security_config.processing.max_template_size
        compiler.security_config.processing.max_template_size = 10  # Very small limit

        try:
            # Create a file that's larger than the limit
            large_content = '{"version": "1.0.0", "content": [{"type": "text", "text": "' + "x" * 1000 + '"}]}'
            test_file.write_text(large_content)

            with pytest.raises(ITSCompilationError) as exc_info:
                compiler.compile_file(str(test_file))

            assert "Template file too large" in str(exc_info.value)

        finally:
            # Restore original limit
            compiler.security_config.processing.max_template_size = original_max_size

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

    def test_schema_loading_with_comprehensive_error_scenarios(
        self, compiler: ITSCompiler, temp_directory: Path
    ) -> None:
        """Test schema loading with comprehensive error scenarios to cover validation and error paths."""

        # Test template that extends multiple schemas with various error conditions
        template = {
            "version": "1.0.0",
            "extends": [
                "https://nonexistent.example.com/schema1.json",  # Will fail DNS/HTTP
                "https://evil.internal.local/schema2.json",  # Will be blocked by SSRF
                "https://alexanderparker.github.io/valid-schema.json",  # Valid but will also fail
            ],
            "variables": {"testVar": "value", "nested": {"prop": "test"}},
            "content": [
                {"type": "text", "text": "Test content"},
                {
                    "type": "placeholder",
                    "instructionType": "unknownType",  # Type that won't exist
                    "config": {"description": "This will fail after schema loading fails"},
                },
            ],
        }

        # This should trigger:
        # 1. Schema loading error handling (lines 263-312 in compiler.py)
        # 2. Variable validation paths (lines 171-211)
        # 3. Error recovery and graceful degradation
        # 4. Multiple exception handling paths

        with pytest.raises((ITSCompilationError, ITSValidationError)) as exc_info:
            compiler.compile(template)

        # Should fail due to schema loading issues or unknown instruction type
        error_msg = str(exc_info.value)
        assert any(
            keyword in error_msg.lower() for keyword in ["schema", "unknown", "instruction", "type", "failed", "load"]
        )

    def test_schema_loader_comprehensive_error_scenarios(self, compiler: ITSCompiler) -> None:
        """Test schema loader with comprehensive HTTP and cache error scenarios."""
        import gzip
        import json
        from unittest.mock import MagicMock, patch
        from urllib.error import HTTPError, URLError

        # Test template that tries to load an external schema
        template = {
            "version": "1.0.0",
            "extends": ["https://example.com/test-schema.json"],
            "content": [{"type": "text", "text": "test"}],
        }

        # Test 1: HTTP Error scenarios (covers lines 205-225)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_urlopen.side_effect = HTTPError(
                url="https://example.com/test-schema.json", code=404, msg="Not Found", hdrs={}, fp=None
            )

            with pytest.raises((ITSCompilationError, ITSValidationError)):
                compiler.compile(template)

        # Test 2: URL Error scenarios
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")

            with pytest.raises((ITSCompilationError, ITSValidationError)):
                compiler.compile(template)

        # Test 3: Invalid content type response (covers lines 143-153)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.headers = {"content-type": "text/html"}  # Invalid type
            mock_response.read.return_value = b"<html>Not JSON</html>"
            mock_urlopen.return_value.__enter__.return_value = mock_response

            with pytest.raises((ITSCompilationError, ITSValidationError)):
                compiler.compile(template)

        # Test 4: Gzip decompression error (covers lines 234, 239, 244)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.headers = {"content-type": "application/json", "content-encoding": "gzip"}
            mock_response.read.return_value = b"invalid gzip data"  # Bad gzip
            mock_urlopen.return_value.__enter__.return_value = mock_response

            with pytest.raises((ITSCompilationError, ITSValidationError)):
                compiler.compile(template)

        # Test 5: Large response size error (covers lines 163-164, 171)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.headers = {
                "content-type": "application/json",
                "content-length": str(50 * 1024 * 1024),  # 50MB - too large
            }
            mock_urlopen.return_value.__enter__.return_value = mock_response

            with pytest.raises((ITSCompilationError, ITSValidationError)):
                compiler.compile(template)

        # Test 6: Cache corruption scenarios (covers lines 331-343, 347-353)
        if compiler.config.cache_enabled:
            with patch("pathlib.Path.exists", return_value=True), patch(
                "builtins.open", side_effect=json.JSONDecodeError("Invalid JSON", "", 0)
            ):
                # This should handle corrupted cache gracefully and try to load from URL
                with patch("urllib.request.urlopen") as mock_urlopen:
                    mock_urlopen.side_effect = URLError("Network error")
                    with pytest.raises((ITSCompilationError, ITSValidationError)):
                        compiler.compile(template)
