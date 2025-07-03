"""
Conditional expression evaluation for ITS Compiler with security enhancements.
"""

import re
import ast
import operator
from typing import Callable, Dict, List, Any, Optional

from .exceptions import ITSConditionalError
from .security import SecurityConfig, ExpressionSanitiser


class ConditionalEvaluator:
    """Evaluates conditional expressions for content inclusion with security controls."""

    def __init__(self, security_config: Optional[SecurityConfig] = None):
        # Security components
        self.security_config = security_config or SecurityConfig.from_environment()

        self.expression_sanitiser = (
            ExpressionSanitiser(self.security_config)
            if self.security_config.enable_expression_sanitisation
            else None
        )

        # Allowed binary operators
        self.binary_operators: Dict[type, Callable[[Any, Any], Any]] = {
            ast.Eq: operator.eq,
            ast.NotEq: operator.ne,
            ast.Lt: operator.lt,
            ast.LtE: operator.le,
            ast.Gt: operator.gt,
            ast.GtE: operator.ge,
            ast.And: operator.and_,
            ast.Or: operator.or_,
            ast.In: lambda a, b: a in b,
            ast.NotIn: lambda a, b: a not in b,
        }

        # Allowed unary operators
        self.unary_operators: Dict[type, Callable[[Any], Any]] = {
            ast.Not: operator.not_,
            ast.USub: operator.neg,
            ast.UAdd: operator.pos,
        }

    def evaluate_content(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate conditionals in content and return filtered content."""
        result = []

        for element in content:
            if element["type"] == "conditional":
                # Evaluate the condition with security validation
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
        """Evaluate a conditional expression with security validation."""

        # Security validation
        if self.expression_sanitiser:
            try:
                sanitised_condition = self.expression_sanitiser.sanitise_expression(
                    condition, variables
                )
            except Exception as e:
                raise ITSConditionalError(
                    f"Security validation failed for condition '{condition}': {e}",
                    condition=condition,
                )
        else:
            sanitised_condition = condition

        try:
            # Convert single quotes to double quotes for proper Python parsing
            processed_condition = sanitised_condition.replace("'", '"')

            # Parse the expression
            parsed = ast.parse(processed_condition, mode="eval")

            # Additional security check if sanitiser is disabled
            if not self.expression_sanitiser:
                self._basic_security_check(parsed.body, condition)

            # Evaluate the expression
            result = self._evaluate_node(parsed.body, variables)

            # Ensure result is boolean
            return bool(result)

        except ITSConditionalError:
            raise
        except Exception as e:
            raise ITSConditionalError(
                f"Error evaluating condition '{condition}': {e}", condition=condition
            )

    def _basic_security_check(self, node: ast.AST, condition: str) -> None:
        """Basic security check when full sanitiser is disabled."""

        # Check for dangerous node types (removed ast.Exec as it doesn't exist in Python 3)
        dangerous_nodes = {
            ast.Call,
            ast.FunctionDef,
            ast.ClassDef,
            ast.Import,
            ast.ImportFrom,
            ast.Global,
            ast.Nonlocal,
            ast.Lambda,
            ast.GeneratorExp,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
        }

        for node_obj in ast.walk(node):
            if type(node_obj) in dangerous_nodes:
                raise ITSConditionalError(
                    f"Dangerous expression detected in condition: {type(node_obj).__name__}",
                    condition=condition,
                )

    def _evaluate_node(self, node: ast.AST, variables: Dict[str, Any]) -> Any:
        """Recursively evaluate an AST node with enhanced security."""

        if isinstance(node, ast.Constant):  # Python 3.8+
            return node.value
        elif isinstance(node, ast.Num):  # Python < 3.8
            return node.n
        elif isinstance(node, ast.Str):  # Python < 3.8
            return node.s
        elif isinstance(node, ast.NameConstant):  # Python < 3.8
            return node.value

        elif isinstance(node, ast.Name):
            # Variable reference or boolean literal
            var_name = node.id

            # Handle boolean literals
            if var_name == "true":
                return True
            elif var_name == "false":
                return False

            # Security check for variable names
            if self._is_dangerous_variable_name(var_name):
                raise ITSConditionalError(
                    f"Access to dangerous variable '{var_name}' is not allowed",
                    condition=f"variable: {var_name}",
                )

            if var_name not in variables:
                raise ITSConditionalError(
                    f"Undefined variable '{var_name}' in condition",
                    condition=f"variable: {var_name}",
                )
            return variables[var_name]

        elif isinstance(node, ast.Attribute):
            # Object property access (e.g., user.name)
            obj = self._evaluate_node(node.value, variables)

            # Security check for attribute access
            if self._is_dangerous_attribute(node.attr):
                raise ITSConditionalError(
                    f"Access to attribute '{node.attr}' is not allowed",
                    condition=f"attribute: {node.attr}",
                )

            # Special handling for 'length' property on lists and strings
            if node.attr == "length":
                if isinstance(obj, (list, str)):
                    return len(obj)
                else:
                    raise ITSConditionalError(
                        f"Property 'length' is only available on lists and strings, got {type(obj).__name__}",
                        condition=f"property access: {node.attr}",
                    )

            # Regular dictionary property access
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

            # Handle Python version differences for slice
            if hasattr(node.slice, "value"):  # Python < 3.9
                index = self._evaluate_node(node.slice.value, variables)
            else:  # Python 3.9+
                index = self._evaluate_node(node.slice, variables)

            # Security check for large indices
            if (
                isinstance(index, int)
                and abs(index) > self.security_config.processing.max_array_index
            ):
                raise ITSConditionalError(
                    f"Array index too large: {index}", condition=f"subscript: {index}"
                )

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

                if type(op) not in self.binary_operators:
                    raise ITSConditionalError(
                        f"Unsupported operator: {type(op).__name__}",
                        condition=f"operator: {type(op).__name__}",
                    )

                binary_op_func = self.binary_operators[type(op)]

                result = binary_op_func(left, right)

                if not result:
                    return False

                left = right  # For chained comparisons

            return True

        elif isinstance(node, ast.BoolOp):
            # Boolean operations (and, or)
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

            if type(node.op) not in self.unary_operators:
                raise ITSConditionalError(
                    f"Unsupported unary operator: {type(node.op).__name__}",
                    condition=f"unary operator: {type(node.op).__name__}",
                )

            unary_op_func = self.unary_operators[type(node.op)]
            return unary_op_func(operand)

        else:
            raise ITSConditionalError(
                f"Unsupported expression type: {type(node).__name__}",
                condition=f"expression type: {type(node).__name__}",
            )

    def _is_dangerous_variable_name(self, name: str) -> bool:
        """Check if variable name is dangerous."""
        dangerous_names = {
            "__builtins__",
            "__globals__",
            "__locals__",
            "__import__",
            "exec",
            "eval",
            "compile",
            "open",
            "input",
            "raw_input",
            "globals",
            "locals",
            "vars",
            "dir",
            "getattr",
            "setattr",
            "hasattr",
            "delattr",
            "callable",
            "isinstance",
            "issubclass",
        }
        return name in dangerous_names or name.startswith("__")

    def _is_dangerous_attribute(self, attr: str) -> bool:
        """Check if attribute access is dangerous."""
        dangerous_attrs = {
            "__class__",
            "__bases__",
            "__subclasses__",
            "__mro__",
            "__dict__",
            "__globals__",
            "__locals__",
            "__code__",
            "__import__",
            "__builtins__",
            "func_globals",
            "gi_frame",
            "cr_frame",
            "f_globals",
            "f_locals",
        }
        return attr in dangerous_attrs or attr.startswith("_")

    def validate_condition(
        self, condition: str, variables: Dict[str, Any]
    ) -> List[str]:
        """Validate a condition expression and return any errors."""
        errors = []

        try:
            # Security validation first
            if self.expression_sanitiser:
                self.expression_sanitiser.sanitise_expression(condition, variables)

            # Try to parse the condition
            ast.parse(condition, mode="eval")
        except SyntaxError as e:
            errors.append(f"Syntax error in condition '{condition}': {e}")
            return errors
        except Exception as e:
            errors.append(f"Security validation failed: {e}")
            return errors

        try:
            # Try to evaluate with current variables
            self.evaluate_condition(condition, variables)
        except ITSConditionalError as e:
            errors.append(str(e))

        return errors

    def get_security_status(self) -> Dict[str, Any]:
        """Get security status for conditionals."""
        return {
            "expression_sanitisation_enabled": self.expression_sanitiser is not None,
            "max_expression_length": self.security_config.processing.max_expression_length,
            "max_expression_depth": self.security_config.processing.max_expression_depth,
        }
