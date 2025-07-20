"""
Tests for variable resolution and processing edge cases.
Tests complex variable scenarios, error conditions, and security validation.
"""

from typing import Any, Dict

import pytest

from its_compiler.core.exceptions import ITSVariableError
from its_compiler.core.variable_processor import VariableProcessor
from its_compiler.security import SecurityConfig


class TestVariableResolution:
    """Test variable resolution and processing edge cases."""

    @pytest.fixture
    def processor(self) -> VariableProcessor:
        """Create variable processor with test config."""
        security_config = SecurityConfig.for_development()
        return VariableProcessor(security_config)

    @pytest.fixture
    def strict_processor(self) -> VariableProcessor:
        """Create variable processor with strict security config."""
        security_config = SecurityConfig.from_environment()
        return VariableProcessor(security_config)

    def test_array_length_property(self, processor: VariableProcessor) -> None:
        """Test array length property access."""
        variables = {"items": [1, 2, 3, 4, 5]}

        result = processor.resolve_variable_reference("items.length", variables)
        assert result == 5

    def test_string_length_property(self, processor: VariableProcessor) -> None:
        """Test string length property access."""
        variables = {"text": "hello world"}

        result = processor.resolve_variable_reference("text.length", variables)
        assert result == 11

    def test_array_indexing(self, processor: VariableProcessor) -> None:
        """Test array indexing with various scenarios."""
        variables = {"items": ["first", "second", "third"]}

        # Test positive indexing
        assert processor.resolve_variable_reference("items[0]", variables) == "first"
        assert processor.resolve_variable_reference("items[1]", variables) == "second"
        assert processor.resolve_variable_reference("items[2]", variables) == "third"

    def test_negative_array_indexing(self, processor: VariableProcessor) -> None:
        """Test negative array indexing."""
        variables = {"items": ["first", "second", "third"]}

        # Test negative indexing (should work if within bounds)
        result = processor.resolve_variable_reference("items[-1]", variables)
        assert result == "third"

    def test_deep_object_property_access(self, processor: VariableProcessor) -> None:
        """Test deep object property access."""
        variables = {"user": {"profile": {"details": {"name": "John Doe", "age": 30}}}}

        result = processor.resolve_variable_reference("user.profile.details.name", variables)
        assert result == "John Doe"

        result = processor.resolve_variable_reference("user.profile.details.age", variables)
        assert result == 30

    def test_variable_reference_syntax_validation(self, processor: VariableProcessor) -> None:
        """Test variable reference syntax validation."""
        variables = {"test": "value"}

        # Invalid syntax should raise errors
        invalid_references = [
            "123invalid",  # Starts with number
            "invalid-name",  # Contains hyphen
            "invalid name",  # Contains space
            "invalid..double.dot",  # Double dots
            "_private",  # Starts with underscore
            "test.__proto__",  # Contains dangerous pattern
        ]

        for invalid_ref in invalid_references:
            with pytest.raises(ITSVariableError):
                processor.resolve_variable_reference(invalid_ref, variables)

    def test_array_index_bounds_checking(self, processor: VariableProcessor) -> None:
        """Test array index bounds checking."""
        variables = {"items": ["first", "second"]}

        # Out of bounds access should raise error
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("items[5]", variables)
        assert "out of bounds" in str(exc_info.value)

    def test_array_index_size_limits(self, strict_processor: VariableProcessor) -> None:
        """Test array index size limits with strict config."""
        variables = {"items": list(range(100))}

        # Very large index should be rejected
        with pytest.raises(ITSVariableError) as exc_info:
            strict_processor.resolve_variable_reference("items[50000]", variables)
        assert "index too large" in str(exc_info.value)

    def test_property_chain_depth_limits(self, strict_processor: VariableProcessor) -> None:
        """Test property chain depth limits."""
        # Create deeply nested object
        variables = {"root": {}}
        current = variables["root"]
        for i in range(20):  # Create very deep nesting
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        current["value"] = "deep_value"

        # Very deep access should be rejected
        deep_ref = "root." + ".".join(f"level{i}" for i in range(15)) + ".value"
        with pytest.raises(ITSVariableError) as exc_info:
            strict_processor.resolve_variable_reference(deep_ref, variables)
        assert "too deep" in str(exc_info.value)

    def test_variable_not_found_error(self, processor: VariableProcessor) -> None:
        """Test variable not found error with suggestions."""
        variables = {"user": {"name": "John"}, "product": {"title": "Test"}}

        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("missing", variables)

        error = exc_info.value
        assert error.variable_path == "missing"
        assert "user" in error.available_variables
        assert "product" in error.available_variables

    def test_property_not_found_error(self, processor: VariableProcessor) -> None:
        """Test property not found error."""
        variables = {"user": {"name": "John", "age": 30}}

        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("user.missing", variables)

        error = exc_info.value
        assert "missing" in str(error)
        assert "name" in error.available_variables
        assert "age" in error.available_variables

    def test_non_object_property_access(self, processor: VariableProcessor) -> None:
        """Test property access on non-object values."""
        variables = {"number": 42, "text": "hello"}

        # Should not be able to access properties on primitives (except length)
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("number.property", variables)
        assert "Cannot access property" in str(exc_info.value)

    def test_non_array_indexing(self, processor: VariableProcessor) -> None:
        """Test indexing on non-array values."""
        variables = {"text": "hello", "number": 42}

        # Should not be able to index non-arrays
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("text[0]", variables)
        assert "is not an array" in str(exc_info.value)

    def test_invalid_array_syntax(self, processor: VariableProcessor) -> None:
        """Test invalid array syntax."""
        variables = {"items": [1, 2, 3]}

        invalid_syntax = [
            "items[",  # Unclosed bracket
            "items[abc]",  # Non-numeric index
            "items[]",  # Empty brackets
            "items[1.5]",  # Float index
        ]

        for invalid in invalid_syntax:
            with pytest.raises(ITSVariableError):
                processor.resolve_variable_reference(invalid, variables)

    def test_sanitised_resolved_value(self, processor: VariableProcessor) -> None:
        """Test sanitised resolved value formatting."""
        variables = {
            "array": [1, 2, 3],
            "object": {"key": "value", "count": 5},
            "string": "hello",
            "number": 42,
            "boolean": True,
        }

        # Test different value type formatting
        content = [{"type": "text", "text": "Array: ${array}, Object: ${object}, String: ${string}"}]
        result = processor.process_content(content, variables)

        processed_text = result[0]["text"]
        assert "1, 2, 3" in processed_text  # Array becomes comma-separated
        assert "[Object with 2 properties]" in processed_text  # Object summary
        assert "hello" in processed_text  # String as-is

    def test_variable_reference_length_limit(self, processor: VariableProcessor) -> None:
        """Test variable reference length limits."""
        variables = {"test": "value"}

        # Very long variable reference should be rejected
        long_ref = "test." + ".".join(f"prop{i}" for i in range(50))

        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference(long_ref, variables)
        assert "too long" in str(exc_info.value)

    def test_find_variable_references(self, processor: VariableProcessor) -> None:
        """Test finding all variable references in content."""
        content = [
            {"type": "text", "text": "Hello ${user.name}, you have ${count} items"},
            {
                "type": "conditional",
                "condition": "active == true",
                "content": [{"type": "text", "text": "Status: ${status}"}],
            },
        ]

        references = processor.find_variable_references(content)

        # Should find all references
        assert "user.name" in references
        assert "count" in references
        assert "status" in references

    def test_validate_variables_comprehensive(self, processor: VariableProcessor) -> None:
        """Test comprehensive variable validation."""
        content = [
            {"type": "text", "text": "User: ${user.name}, Count: ${items.length}"},
            {"type": "text", "text": "First: ${items[0]}"},
        ]

        # Valid variables
        valid_variables = {"user": {"name": "John"}, "items": ["apple", "banana"]}

        errors = processor.validate_variables(content, valid_variables)
        assert len(errors) == 0

        # Missing variables
        incomplete_variables = {"user": {"name": "John"}}

        errors = processor.validate_variables(content, incomplete_variables)
        assert len(errors) > 0
        assert any("items" in error for error in errors)

    def test_process_content_with_nested_structures(self, processor: VariableProcessor) -> None:
        """Test processing content with nested conditional structures."""
        variables = {"show": True, "user": {"name": "Alice"}}

        content = [
            {
                "type": "conditional",
                "condition": "show == true",
                "content": [
                    {"type": "text", "text": "Hello ${user.name}"},
                    {
                        "type": "conditional",
                        "condition": "user.name == 'Alice'",
                        "content": [{"type": "text", "text": "Welcome back!"}],
                    },
                ],
            }
        ]

        result = processor.process_content(content, variables)

        # Should process variables in nested structures
        conditional = result[0]
        inner_text = conditional["content"][0]["text"]
        assert "Hello Alice" in inner_text

    def test_security_status(self, processor: VariableProcessor) -> None:
        """Test variable processor security status reporting."""
        status = processor.get_security_status()

        assert "input_validation_enabled" in status
        assert "max_variable_references" in status
        assert "max_variable_name_length" in status
        assert "max_recursion_depth" in status

        assert isinstance(status["max_variable_references"], int)
        assert isinstance(status["max_variable_name_length"], int)
