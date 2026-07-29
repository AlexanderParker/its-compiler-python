"""Tests for condition operator translation."""

from its_compiler.core.conditional_evaluator import ConditionalEvaluator
from its_compiler.core.expression_utils import translate_condition_operators


class TestTranslateConditionOperators:
    def test_translates_logical_and(self) -> None:
        assert translate_condition_operators("a == true && b > 3") == "a == true  and  b > 3"

    def test_translates_logical_or(self) -> None:
        assert translate_condition_operators("a || b") == "a  or  b"

    def test_translates_unary_not(self) -> None:
        assert translate_condition_operators("!includeSpecs") == "not includeSpecs"

    def test_preserves_not_equals(self) -> None:
        assert translate_condition_operators("a != 'x'") == "a != 'x'"

    def test_preserves_string_literals(self) -> None:
        assert translate_condition_operators("name == 'a && b'") == "name == 'a && b'"

    def test_idempotent_on_python_operators(self) -> None:
        expression = "a == True and not b or c in ['x']"
        assert translate_condition_operators(expression) == expression


class TestSpecOperatorEvaluation:
    """The spec's documented operators evaluate end to end."""

    def test_compound_and(self) -> None:
        evaluator = ConditionalEvaluator()
        assert evaluator.evaluate_condition("a == true && b > 3", {"a": True, "b": 5}) is True
        assert evaluator.evaluate_condition("a == true && b > 3", {"a": True, "b": 1}) is False

    def test_compound_or_and_negation(self) -> None:
        evaluator = ConditionalEvaluator()
        assert evaluator.evaluate_condition("!a || b == 'x'", {"a": False, "b": "y"}) is True
        assert evaluator.evaluate_condition("!a || b == 'x'", {"a": True, "b": "y"}) is False
