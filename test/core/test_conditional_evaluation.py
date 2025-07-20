"""
Tests for conditional expression evaluation and validation.
Tests functional expression evaluation logic - security validation is handled in test_expression_sanitiser.py.
"""

from typing import Any, Dict

import pytest

from its_compiler.core.conditional_evaluator import ConditionalEvaluator
from its_compiler.core.exceptions import ITSConditionalError
from its_compiler.security import SecurityConfig


class TestConditionalEvaluation:
    """Test conditional expression evaluation functionality."""

    @pytest.fixture
    def evaluator(self) -> ConditionalEvaluator:
        """Create conditional evaluator with test config."""
        security_config = SecurityConfig.for_development()
        return ConditionalEvaluator(security_config)

    def test_boolean_literals(self, evaluator: ConditionalEvaluator) -> None:
        """Test boolean literal evaluation."""
        variables: Dict[str, Any] = {}

        # Test true/false literals
        assert evaluator.evaluate_condition("true", variables) is True
        assert evaluator.evaluate_condition("false", variables) is False
        assert evaluator.evaluate_condition("True", variables) is True  # Python style
        assert evaluator.evaluate_condition("False", variables) is False

    def test_comparison_operators(self, evaluator: ConditionalEvaluator) -> None:
        """Test all comparison operators."""
        variables = {"num": 5, "text": "hello", "other": 10}

        # Equality
        assert evaluator.evaluate_condition("num == 5", variables) is True
        assert evaluator.evaluate_condition("num == 10", variables) is False
        assert evaluator.evaluate_condition("num != 10", variables) is True
        assert evaluator.evaluate_condition("num != 5", variables) is False

        # Numeric comparisons
        assert evaluator.evaluate_condition("num < 10", variables) is True
        assert evaluator.evaluate_condition("num <= 5", variables) is True
        assert evaluator.evaluate_condition("num > 3", variables) is True
        assert evaluator.evaluate_condition("num >= 5", variables) is True

        # String comparisons
        assert evaluator.evaluate_condition('text == "hello"', variables) is True
        assert evaluator.evaluate_condition('text != "world"', variables) is True

    def test_boolean_operators(self, evaluator: ConditionalEvaluator) -> None:
        """Test boolean operators (and, or, not)."""
        variables = {"a": True, "b": False, "num": 5}

        # AND operator
        assert evaluator.evaluate_condition("a and true", variables) is True
        assert evaluator.evaluate_condition("a and b", variables) is False
        assert evaluator.evaluate_condition("a and num > 3", variables) is True

        # OR operator
        assert evaluator.evaluate_condition("a or b", variables) is True
        assert evaluator.evaluate_condition("b or false", variables) is False
        assert evaluator.evaluate_condition("b or num > 3", variables) is True

        # NOT operator
        assert evaluator.evaluate_condition("not b", variables) is True
        assert evaluator.evaluate_condition("not a", variables) is False
        assert evaluator.evaluate_condition("not (num < 3)", variables) is True

    def test_membership_operators(self, evaluator: ConditionalEvaluator) -> None:
        """Test membership operators (in, not in)."""
        variables = {"items": ["apple", "banana", "cherry"], "text": "hello world", "value": "banana"}

        # IN operator with lists
        assert evaluator.evaluate_condition("value in items", variables) is True
        assert evaluator.evaluate_condition('"orange" in items', variables) is False

        # IN operator with strings
        assert evaluator.evaluate_condition('"hello" in text', variables) is True
        assert evaluator.evaluate_condition('"goodbye" in text', variables) is False

        # NOT IN operator
        assert evaluator.evaluate_condition('"orange" not in items', variables) is True
        assert evaluator.evaluate_condition("value not in items", variables) is False

    def test_list_and_tuple_literals(self, evaluator: ConditionalEvaluator) -> None:
        """Test list and tuple literals in expressions."""
        variables = {"item": "apple"}

        # List literals
        assert evaluator.evaluate_condition('item in ["apple", "banana"]', variables) is True
        assert evaluator.evaluate_condition('item in ["orange", "grape"]', variables) is False

        # Tuple literals (treated as tuples in Python)
        assert evaluator.evaluate_condition('item in ("apple", "banana")', variables) is True

    def test_object_property_access(self, evaluator: ConditionalEvaluator) -> None:
        """Test object property access in conditions."""
        variables = {"user": {"name": "John", "age": 30, "active": True}, "settings": {"debug": False, "level": 2}}

        # Property access
        assert evaluator.evaluate_condition('user.name == "John"', variables) is True
        assert evaluator.evaluate_condition("user.age > 25", variables) is True
        assert evaluator.evaluate_condition("user.active == true", variables) is True

        # Nested property access
        assert evaluator.evaluate_condition("settings.level > 1", variables) is True
        assert evaluator.evaluate_condition("settings.debug == false", variables) is True

    def test_array_subscript_access(self, evaluator: ConditionalEvaluator) -> None:
        """Test array subscript access in conditions."""
        variables = {"items": ["first", "second", "third"], "numbers": [1, 2, 3, 4, 5]}

        # Array indexing
        assert evaluator.evaluate_condition('items[0] == "first"', variables) is True
        assert evaluator.evaluate_condition('items[1] == "second"', variables) is True
        assert evaluator.evaluate_condition("numbers[2] == 3", variables) is True

        # Negative indexing
        assert evaluator.evaluate_condition('items[-1] == "third"', variables) is True

    def test_length_property_access(self, evaluator: ConditionalEvaluator) -> None:
        """Test special length property access."""
        variables = {"items": ["a", "b", "c", "d"], "text": "hello"}

        # Array length
        assert evaluator.evaluate_condition("items.length == 4", variables) is True
        assert evaluator.evaluate_condition("items.length > 3", variables) is True

        # String length
        assert evaluator.evaluate_condition("text.length == 5", variables) is True

    def test_chained_comparisons(self, evaluator: ConditionalEvaluator) -> None:
        """Test chained comparison operations."""
        variables = {"num": 5}

        # Chained comparisons
        assert evaluator.evaluate_condition("1 < num < 10", variables) is True
        assert evaluator.evaluate_condition("1 < num < 3", variables) is False
        assert evaluator.evaluate_condition("5 <= num <= 5", variables) is True

    def test_complex_expressions(self, evaluator: ConditionalEvaluator) -> None:
        """Test complex nested expressions."""
        variables = {"user": {"age": 25, "active": True}, "settings": {"level": 3}, "items": ["a", "b", "c"]}

        # Complex boolean logic
        complex_expr = "user.age > 18 and user.active == true and settings.level >= 2"
        assert evaluator.evaluate_condition(complex_expr, variables) is True

        # Parentheses for precedence
        parentheses_expr = "(user.age > 30 or settings.level > 2) and user.active"
        assert evaluator.evaluate_condition(parentheses_expr, variables) is True

        # Mixed operators
        mixed_expr = 'items.length > 2 and "a" in items and user.age != 30'
        assert evaluator.evaluate_condition(mixed_expr, variables) is True

    def test_unary_operators(self, evaluator: ConditionalEvaluator) -> None:
        """Test unary operators."""
        variables = {"positive": 5, "negative": -3, "flag": True}

        # Unary minus
        assert evaluator.evaluate_condition("-positive == -5", variables) is True
        assert evaluator.evaluate_condition("-negative == 3", variables) is True

        # Unary plus
        assert evaluator.evaluate_condition("+positive == 5", variables) is True

        # Unary not
        assert evaluator.evaluate_condition("not flag == false", variables) is True

    def test_evaluate_content_with_conditionals(self, evaluator: ConditionalEvaluator) -> None:
        """Test evaluating content with conditional elements."""
        variables = {"show": True, "hide": False}

        content = [
            {"type": "text", "text": "Always visible"},
            {
                "type": "conditional",
                "condition": "show == true",
                "content": [{"type": "text", "text": "Conditionally visible"}],
            },
            {
                "type": "conditional",
                "condition": "hide == true",
                "content": [{"type": "text", "text": "Hidden"}],
                "else": [{"type": "text", "text": "Shown instead"}],
            },
        ]

        result = evaluator.evaluate_content(content, variables)

        # Should have 3 elements: always visible, conditionally visible, else content
        assert len(result) == 3
        assert result[0]["text"] == "Always visible"
        assert result[1]["text"] == "Conditionally visible"
        assert result[2]["text"] == "Shown instead"

    def test_nested_conditional_content(self, evaluator: ConditionalEvaluator) -> None:
        """Test nested conditional content evaluation."""
        variables = {"outer": True, "inner": False}

        content = [
            {
                "type": "conditional",
                "condition": "outer == true",
                "content": [
                    {"type": "text", "text": "Outer true"},
                    {
                        "type": "conditional",
                        "condition": "inner == true",
                        "content": [{"type": "text", "text": "Inner true"}],
                        "else": [{"type": "text", "text": "Inner false"}],
                    },
                ],
            }
        ]

        result = evaluator.evaluate_content(content, variables)

        # Should have 2 elements from the outer conditional
        assert len(result) == 2
        assert result[0]["text"] == "Outer true"
        assert result[1]["text"] == "Inner false"

    def test_expression_validation(self, evaluator: ConditionalEvaluator) -> None:
        """Test expression validation without evaluation."""
        variables = {"test": True}

        # Valid expression
        errors = evaluator.validate_condition("test == true", variables)
        assert len(errors) == 0

        # Invalid syntax
        errors = evaluator.validate_condition("test ==", variables)
        assert len(errors) > 0
        assert any("syntax" in error.lower() for error in errors)

    def test_syntax_error_handling(self, evaluator: ConditionalEvaluator) -> None:
        """Test syntax error handling in expressions."""
        variables = {"test": True}

        syntax_errors = [
            "test ==",
            "== test",
            "test and and test",
            "test == True ==",
            "test = True",  # Assignment instead of comparison
            "invalid syntax &&",
        ]

        for invalid_expr in syntax_errors:
            with pytest.raises(ITSConditionalError) as exc_info:
                evaluator.evaluate_condition(invalid_expr, variables)
            assert "syntax" in str(exc_info.value).lower() or "error" in str(exc_info.value).lower()

    def test_get_security_status(self, evaluator: ConditionalEvaluator) -> None:
        """Test conditional evaluator security status."""
        status = evaluator.get_security_status()

        assert "expression_sanitisation_enabled" in status
        assert "max_expression_length" in status
        assert "max_expression_depth" in status

        assert isinstance(status["max_expression_length"], int)
        assert isinstance(status["max_expression_depth"], int)
