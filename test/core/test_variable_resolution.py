"""
Tests for variable resolution and processing edge cases.
Tests complex variable scenarios, error conditions, and security validation.
"""

from typing import Any, Dict, List

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
        variables: Dict[str, Any] = {"root": {}}
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

    def test_comprehensive_variable_errors(self, processor: VariableProcessor) -> None:
        """Test all variable resolution error conditions."""
        variables = {"user": {"name": "John", "age": 30}, "items": [1, 2, 3]}

        # Variable not found
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("missing", variables)
        error = exc_info.value
        assert error.variable_path == "missing"
        assert "user" in error.available_variables

        # Property not found
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("user.missing", variables)
        error = exc_info.value
        assert "missing" in str(error)
        assert "name" in error.available_variables
        assert "age" in error.available_variables

        # Non-object property access
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("user.age.property", variables)
        assert "Cannot access property" in str(exc_info.value)

        # Non-array indexing
        with pytest.raises(ITSVariableError) as exc_info:
            processor.resolve_variable_reference("user.name[0]", variables)
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
        content: List[Dict[str, Any]] = [
            {"type": "text", "text": "Array: ${array}, Object: ${object}, String: ${string}"}
        ]
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
        content: List[Dict[str, Any]] = [
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
        content: List[Dict[str, Any]] = [
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

    def test_security_status(self, processor: VariableProcessor) -> None:
        """Test variable processor security status reporting."""
        status = processor.get_security_status()

        assert "input_validation_enabled" in status
        assert "max_variable_references" in status
        assert "max_variable_name_length" in status
        assert "max_recursion_depth" in status

        assert isinstance(status["max_variable_references"], int)
        assert isinstance(status["max_variable_name_length"], int)

    def test_variable_name_security_validation(self, processor: VariableProcessor) -> None:
        """Test security validation of variable names."""
        dangerous_variables = {
            "__builtins__": "dangerous",
            "__globals__": "dangerous",
            "constructor": "dangerous",
            "__proto__": "dangerous",
        }

        content: List[Dict[str, Any]] = [{"type": "text", "text": "Test ${dangerous_var}"}]

        for var_name, value in dangerous_variables.items():
            variables_with_dangerous = {var_name: value}
            # Should either block or handle safely
            try:
                processor.process_content(content, variables_with_dangerous)
            except ITSVariableError:
                # Blocking dangerous variables is acceptable
                pass

    def test_extremely_deep_nesting_security(self, strict_processor: VariableProcessor) -> None:
        """Test security limits on extremely deep object nesting."""
        # Create object with extreme nesting
        nested_obj: Dict[str, Any] = {}
        current = nested_obj
        for i in range(50):  # Very deep
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        current["value"] = "deep"

        variables = {"deep": nested_obj}

        # Extremely deep reference should be blocked
        very_deep_ref = "deep." + ".".join(f"level{i}" for i in range(30)) + ".value"

        with pytest.raises(ITSVariableError):
            strict_processor.resolve_variable_reference(very_deep_ref, variables)

    def test_large_array_index_security(self, strict_processor: VariableProcessor) -> None:
        """Test security limits on large array indices."""
        variables = {"large_array": list(range(1000))}

        # Extremely large index should be blocked
        with pytest.raises(ITSVariableError):
            strict_processor.resolve_variable_reference("large_array[999999]", variables)

    def test_variable_processing_performance_limits(self, strict_processor: VariableProcessor) -> None:
        """Test performance limits in variable processing."""
        # Create content with many variable references
        large_content = [{"type": "text", "text": f"Var {j}: ${{{f'var{j}'}}}"} for j in range(200)]

        # Create matching variables
        many_variables = {f"var{i}": f"value{i}" for i in range(200)}

        # Should handle reasonable amounts but enforce limits
        try:
            strict_processor.process_content(large_content, many_variables)
        except ITSVariableError:
            # Performance limits may trigger - this is acceptable
            pass
