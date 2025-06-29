"""
Conditional expression evaluation for ITS Compiler.
"""

import re
import ast
import operator
from typing import Dict, List, Any, Union

from exceptions import ITSConditionalError


class ConditionalEvaluator:
    """Evaluates conditional expressions for content inclusion."""

    def __init__(self):
        # Supported operators
        self.operators = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.And: operator.and_,
            ast.Or: operator.or_,
            ast.Not: operator.not_,
            ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b,
        }

    def evaluate_content(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate conditionals in content and return filtered content."""
        result = []

        for element in content:
            if element["type"] == "conditional":
                # Evaluate the condition
                condition_result = self.evaluate_condition(
                    element["condition"], variables
                )

                if condition_result:
                    # Include content from the 'content' array
                    nested_content = self.evaluate_content(
                        element["content"], variables
                    )
                    result.extend(nested_content)
                elif "else" in element:
                    # Include content from the 'else' array
                    nested_content = self.evaluate_content(element["else"], variables)
                    result.extend(nested_content)
            else:
                # Non-conditional element, include as-is
                result.append(element)

        return result

    def evaluate_condition(self, condition: str, variables: Dict[str, Any]) -> bool:
        """Evaluate a conditional expression."""
        try:
            # Parse the expression
            parsed = ast.parse(condition, mode="eval")

            # Evaluate the expression
            result = self._evaluate_node(parsed.body, variables)

            # Ensure result is boolean
            return bool(result)

        except Exception as e:
            raise ITSConditionalError(
                f"Error evaluating condition '{condition}': {e}", condition=condition
            )

    def _evaluate_node(self, node: ast.AST, variables: Dict[str, Any]) -> Any:
        """Recursively evaluate an AST node."""

        if isinstance(node, ast.Constant):  # Python 3.8+
            return node.value
        elif isinstance(node, ast.Num):  # Python < 3.8
            return node.n
        elif isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        elif isinstance(node, ast.NameConstant):  # Python < 3.8
            return node.value

        elif isinstance(node, ast.Name):
            # Variable reference
            var_name = node.id
            if var_name not in variables:
                raise ITSConditionalError(
                    f"Undefined variable '{var_name}' in condition",
                    condition=f"variable: {var_name}",
                )
            return variables[var_name]

        elif isinstance(node, ast.Attribute):
            # Object property access (e.g., user.name)
            obj = self._evaluate_node(node.value, variables)
            if not isinstance(obj, dict):
                raise ITSConditionalError(
                    f"Cannot access property '{node.attr}' on non-object value",
                    condition=f"property access: {node.attr}",
                )
            if node.attr not in obj:
                raise ITSConditionalError(
                    f"Property '{node.attr}' not found",
                    condition=f"property access: {node.attr}",
                )
            return obj[node.attr]

        elif isinstance(node, ast.Subscript):
            # Array/dict subscript access (e.g., items[0])
            obj = self._evaluate_node(node.value, variables)
            index = self._evaluate_node(node.slice, variables)

            try:
                return obj[index]
            except (KeyError, IndexError, TypeError) as e:
                raise ITSConditionalError(
                    f"Subscript access error: {e}", condition=f"subscript: {index}"
                )

        elif isinstance(node, ast.List):
            # List literal
            return [self._evaluate_node(item, variables) for item in node.elts]

        elif isinstance(node, ast.Tuple):
            # Tuple literal
            return tuple(self._evaluate_node(item, variables) for item in node.elts)

        elif isinstance(node, ast.Compare):
            # Comparison operations
            left = self._evaluate_node(node.left, variables)

            for op, comparator in zip(node.ops, node.comparators):
                right = self._evaluate_node(comparator, variables)

                if type(op) not in self.operators:
                    raise ITSConditionalError(
                        f"Unsupported operator: {type(op).__name__}",
                        condition=f"operator: {type(op).__name__}",
                    )

                op_func = self.operators[type(op)]

                # Handle special case for 'in' operator with strings
                if isinstance(op, (ast.In, ast.NotIn)):
                    result = op_func(left, right)
                else:
                    result = op_func(left, right)

                if not result:
                    return False

                left = right  # For chained comparisons

            return True

        elif isinstance(node, ast.BoolOp):
            # Boolean operations (and, or)
            op_func = self.operators[type(node.op)]

            if isinstance(node.op, ast.And):
                # All values must be truthy
                for value in node.values:
                    if not self._evaluate_node(value, variables):
                        return False
                return True

            elif isinstance(node.op, ast.Or):
                # Any value must be truthy
                for value in node.values:
                    if self._evaluate_node(value, variables):
                        return True
                return False

        elif isinstance(node, ast.UnaryOp):
            # Unary operations (not, -, +)
            operand = self._evaluate_node(node.operand, variables)

            if isinstance(node.op, ast.Not):
                return not operand
            elif isinstance(node.op, ast.USub):
                return -operand
            elif isinstance(node.op, ast.UAdd):
                return +operand
            else:
                raise ITSConditionalError(
                    f"Unsupported unary operator: {type(node.op).__name__}",
                    condition=f"unary operator: {type(node.op).__name__}",
                )

        else:
            raise ITSConditionalError(
                f"Unsupported expression type: {type(node).__name__}",
                condition=f"expression type: {type(node).__name__}",
            )

    def validate_condition(
        self, condition: str, variables: Dict[str, Any]
    ) -> List[str]:
        """Validate a condition expression and return any errors."""
        errors = []

        try:
            # Try to parse the condition
            ast.parse(condition, mode="eval")
        except SyntaxError as e:
            errors.append(f"Syntax error in condition '{condition}': {e}")
            return errors

        try:
            # Try to evaluate with current variables
            self.evaluate_condition(condition, variables)
        except ITSConditionalError as e:
            errors.append(str(e))

        return errors
