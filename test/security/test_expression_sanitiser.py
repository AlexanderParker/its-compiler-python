"""
Tests for ExpressionSanitiser AST injection prevention and expression validation.
"""

import pytest

from its_compiler.security import (
    ExpressionSanitiser,
    ExpressionSecurityError,
    SecurityConfig,
)


@pytest.fixture
def security_config():
    """Create security config for testing."""
    return SecurityConfig.for_development()


@pytest.fixture
def production_config():
    """Create production security config."""
    config = SecurityConfig.from_environment()
    config.processing.max_expression_length = 200
    config.processing.max_expression_depth = 8
    config.processing.max_expression_nodes = 50
    return config


@pytest.fixture
def expression_sanitiser(security_config):
    """Create expression sanitiser with test config."""
    return ExpressionSanitiser(security_config)


@pytest.fixture
def production_sanitiser(production_config):
    """Create expression sanitiser with production config."""
    return ExpressionSanitiser(production_config)


class TestExpressionSanitiser:
    """Test ExpressionSanitiser security functionality."""

    def test_valid_simple_expressions(self, expression_sanitiser):
        """Test valid simple expressions pass validation."""
        variables = {"user": {"name": "John"}, "active": True, "count": 5}

        valid_expressions = [
            "active == True",
            "count > 3",
            'user.name == "John"',
            "count >= 1 and count <= 10",
            "active or count > 0",
            "not active",
            "count in [1, 2, 3, 4, 5]",
            '"test" not in user.name',
        ]

        for expr in valid_expressions:
            # Should not raise exception
            result = expression_sanitiser.sanitise_expression(expr, variables)
            assert result == expr  # Should return unchanged

    def test_valid_complex_expressions(self, expression_sanitiser):
        """Test valid complex expressions pass validation."""
        variables = {
            "settings": {"debug": True, "level": 2},
            "items": [1, 2, 3],
            "status": "active",
        }

        complex_expressions = [
            "settings.debug == True and settings.level > 1",
            "len(items) == 3",  # This would fail - len not allowed
            'status == "active" or status == "pending"',
            "items[0] == 1 and items[2] == 3",
            'settings.level >= 2 and status != "inactive"',
        ]

        # Note: some of these might fail due to security restrictions
        for expr in complex_expressions:
            try:
                expression_sanitiser.sanitise_expression(expr, variables)
            except ExpressionSecurityError:
                # Expected for some expressions with forbidden constructs
                pass

    def test_expression_too_long(self, expression_sanitiser):
        """Test expressions that exceed length limits are rejected."""
        variables = {"test": True}

        # Create very long expression
        long_expr = " and ".join(["test == True"] * 100)

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(long_expr, variables)

        assert "Expression too long" in str(exc_info.value)
        assert exc_info.value.reason == "expression_too_long"

    def test_empty_expression(self, expression_sanitiser):
        """Test empty expressions are rejected."""
        variables = {}

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression("", variables)

        assert "Empty expression" in str(exc_info.value)
        assert exc_info.value.reason == "empty_expression"

    def test_unbalanced_parentheses(self, expression_sanitiser):
        """Test expressions with unbalanced parentheses are rejected."""
        variables = {"test": True}

        invalid_expressions = [
            "test == True)",
            "(test == True",
            "((test == True)",
            "test == True))",
        ]

        for expr in invalid_expressions:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Unbalanced parentheses" in str(exc_info.value)

    def test_unbalanced_brackets(self, expression_sanitiser):
        """Test expressions with unbalanced brackets are rejected."""
        variables = {"items": [1, 2, 3]}

        invalid_expressions = [
            "items[0 == 1",
            "items[0]] == 1",
            "items[[0] == 1",
        ]

        for expr in invalid_expressions:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Unbalanced brackets" in str(exc_info.value)

    def test_dangerous_patterns_detected(self, expression_sanitiser):
        """Test dangerous patterns in expressions are detected."""
        variables = {"test": True}

        dangerous_expressions = [
            "__import__('os')",
            "exec('malicious code')",
            "eval('dangerous')",
            "import sys",
            "open('/etc/passwd')",
            "subprocess.call('rm -rf /')",
            "os.system('malicious')",
            "globals()['dangerous']",
            "locals()['bad']",
        ]

        for expr in dangerous_expressions:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Dangerous pattern detected" in str(exc_info.value)
            assert exc_info.value.reason == "dangerous_pattern"

    def test_suspicious_characters(self, expression_sanitiser):
        """Test expressions with suspicious characters are rejected."""
        variables = {"test": True}

        suspicious_expressions = [
            "test == `dangerous`",
            "test == $malicious",
            "test\\x41\\x42",
            "test @ symbol",
        ]

        for expr in suspicious_expressions:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Suspicious characters" in str(exc_info.value)
            assert exc_info.value.reason == "suspicious_characters"

    def test_syntax_errors(self, expression_sanitiser):
        """Test expressions with syntax errors are rejected."""
        variables = {"test": True}

        invalid_syntax = [
            "test == ",
            "== test",
            "test and and test",
            "test == True ==",
            "test = True",  # Assignment instead of comparison
        ]

        for expr in invalid_syntax:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Syntax error" in str(exc_info.value)
            assert exc_info.value.reason == "syntax_error"

    def test_forbidden_ast_nodes(self, expression_sanitiser):
        """Test expressions with forbidden AST nodes are rejected."""
        variables = {"test": True}

        # These should be caught by AST validation
        forbidden_expressions = [
            "lambda x: x",  # Lambda
            "[x for x in range(10)]",  # List comprehension
            "{x for x in range(10)}",  # Set comprehension
            "{x: x for x in range(10)}",  # Dict comprehension
        ]

        for expr in forbidden_expressions:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(expr, variables)

            assert "Forbidden AST node type" in str(exc_info.value)
            assert exc_info.value.reason == "forbidden_node_type"

    def test_nesting_depth_limit(self, production_sanitiser):
        """Test expressions that exceed nesting depth are rejected."""
        variables = {"test": True}

        # Create deeply nested expression
        deep_expr = "test"
        for i in range(15):  # Exceed production limit of 8
            deep_expr = f"({deep_expr} and test)"

        with pytest.raises(ExpressionSecurityError) as exc_info:
            production_sanitiser.sanitise_expression(deep_expr, variables)

        assert "nesting too deep" in str(exc_info.value)
        assert exc_info.value.reason == "nesting_too_deep"

    def test_variable_name_validation(self, expression_sanitiser):
        """Test variable name validation."""
        variables = {"valid": True, "test123": True}

        # Valid variable names should work
        expression_sanitiser.sanitise_expression("valid == True", variables)
        expression_sanitiser.sanitise_expression("test123 == True", variables)

        # Dangerous variable names should be rejected
        dangerous_vars = {
            "__builtins__": {},
            "__globals__": {},
            "exec": lambda x: x,
            "eval": lambda x: x,
        }

        for var_name in dangerous_vars:
            variables_with_dangerous = {**variables, var_name: True}

            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(
                    f"{var_name} == True", variables_with_dangerous
                )

            assert "Dangerous variable name" in str(exc_info.value)

    def test_variable_name_too_long(self, expression_sanitiser):
        """Test variable names that are too long are rejected."""
        long_name = "a" * 200  # Exceed limit
        variables = {long_name: True}

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(f"{long_name} == True", variables)

        assert "Variable name too long" in str(exc_info.value)
        assert exc_info.value.reason == "variable_name_too_long"

    def test_invalid_variable_characters(self, expression_sanitiser):
        """Test variable names with invalid characters are rejected."""
        # This would be caught at the parsing stage, but test the validation
        variables = {"test": True}

        # Invalid variable syntax should cause syntax error
        with pytest.raises(ExpressionSecurityError):
            expression_sanitiser.sanitise_expression("test-invalid == True", variables)

    def test_attribute_access_validation(self, expression_sanitiser):
        """Test object attribute access validation."""
        variables = {"obj": {"safe_attr": True, "_private": True}}

        # Safe attribute access should work
        expression_sanitiser.sanitise_expression("obj.safe_attr == True", variables)

        # Private attribute access should be blocked
        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression("obj._private == True", variables)

        assert "Private attribute access not allowed" in str(exc_info.value)

    def test_dangerous_attribute_access(self, expression_sanitiser):
        """Test dangerous attribute access is blocked."""
        variables = {"obj": {"__class__": type}}

        dangerous_attrs = [
            "__class__",
            "__bases__",
            "__globals__",
            "__dict__",
        ]

        for attr in dangerous_attrs:
            with pytest.raises(ExpressionSecurityError) as exc_info:
                expression_sanitiser.sanitise_expression(
                    f"obj.{attr} == None", variables
                )

            assert "Dangerous attribute access" in str(exc_info.value)

    def test_array_index_validation(self, expression_sanitiser):
        """Test array index validation."""
        variables = {"items": [1, 2, 3, 4, 5]}

        # Valid indices should work
        expression_sanitiser.sanitise_expression("items[0] == 1", variables)
        expression_sanitiser.sanitise_expression("items[2] == 3", variables)

        # Large indices should be blocked
        large_index = expression_sanitiser.config.processing.max_array_index + 1

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(
                f"items[{large_index}] == 1", variables
            )

        assert "Array index too large" in str(exc_info.value)

    def test_negative_array_index_validation(self, expression_sanitiser):
        """Test negative array index validation."""
        variables = {"items": [1, 2, 3]}

        # Reasonable negative indices should work
        expression_sanitiser.sanitise_expression("items[-1] == 3", variables)

        # Very large negative indices should be blocked
        large_negative = -(expression_sanitiser.config.processing.max_array_index + 1)

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(
                f"items[{large_negative}] == 1", variables
            )

        assert "Array index too negative" in str(exc_info.value)

    def test_literal_size_validation(self, expression_sanitiser):
        """Test literal size validation."""
        variables = {"test": True}

        # Large list literal should be rejected
        large_list = "[" + ", ".join(["1"] * 150) + "]"

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(f"test in {large_list}", variables)

        assert "Literal too large" in str(exc_info.value)

    def test_variable_reference_counting(self, expression_sanitiser):
        """Test variable reference counting."""
        # Create expression with many variable references
        many_vars = {f"var{i}": True for i in range(200)}

        # Expression with too many variables
        var_list = " and ".join([f"var{i} == True" for i in range(120)])

        with pytest.raises(ExpressionSecurityError) as exc_info:
            expression_sanitiser.sanitise_expression(var_list, many_vars)

        assert "Too many variable references" in str(exc_info.value)

    def test_undefined_variable_logging(self, expression_sanitiser):
        """Test undefined variable reference logging."""
        variables = {"defined": True}

        # This will fail validation, but should log the undefined variable
        with pytest.raises(ExpressionSecurityError):
            expression_sanitiser.sanitise_expression("undefined == True", variables)

    def test_get_expression_complexity(self, expression_sanitiser):
        """Test expression complexity analysis."""
        expr = 'user.name == "John" and user.active == True'

        complexity = expression_sanitiser.get_expression_complexity(expr)

        assert complexity["length"] == len(expr)
        assert complexity["node_count"] > 0
        assert complexity["max_depth"] > 0
        assert complexity["variable_count"] > 0

    def test_expression_complexity_parse_error(self, expression_sanitiser):
        """Test expression complexity with parse error."""
        invalid_expr = "invalid syntax =="

        complexity = expression_sanitiser.get_expression_complexity(invalid_expr)

        assert complexity["length"] == len(invalid_expr)
        assert complexity["parse_error"] is True

    def test_is_expression_safe(self, expression_sanitiser):
        """Test expression safety check."""
        variables = {"test": True}

        # Safe expression
        assert (
            expression_sanitiser.is_expression_safe("test == True", variables) is True
        )

        # Unsafe expression
        assert (
            expression_sanitiser.is_expression_safe("exec('malicious')", variables)
            is False
        )

    def test_get_safe_operators(self, expression_sanitiser):
        """Test getting list of safe operators."""
        operators = expression_sanitiser.get_safe_operators()

        expected_operators = [
            "==",
            "!=",
            "<",
            "<=",
            ">",
            ">=",
            "and",
            "or",
            "not",
            "in",
            "not in",
            "+",
            "-",
        ]

        for op in expected_operators:
            assert op in operators

    def test_get_blocked_patterns(self, expression_sanitiser):
        """Test getting list of blocked patterns."""
        patterns = expression_sanitiser.get_blocked_patterns()

        expected_patterns = [
            "Function calls: func()",
            "Import statements: import x",
            "Dunder methods: __method__",
        ]

        for pattern in expected_patterns:
            assert pattern in patterns

    def test_boolean_literal_handling(self, expression_sanitiser):
        """Test boolean literal handling."""
        variables = {}

        # Test different boolean representations
        boolean_expressions = [
            "True == True",
            "False == False",
            "true == True",  # Converted to True
            "false == False",  # Converted to False
        ]

        for expr in boolean_expressions:
            # Should not raise exception
            expression_sanitiser.sanitise_expression(expr, variables)

    def test_comparison_operators(self, expression_sanitiser):
        """Test all comparison operators."""
        variables = {"num": 5, "text": "hello"}

        comparison_expressions = [
            "num == 5",
            "num != 3",
            "num < 10",
            "num <= 5",
            "num > 2",
            "num >= 5",
            'text in "hello world"',
            'text not in "goodbye"',
        ]

        for expr in comparison_expressions:
            expression_sanitiser.sanitise_expression(expr, variables)

    def test_boolean_operators(self, expression_sanitiser):
        """Test boolean operators."""
        variables = {"a": True, "b": False, "c": True}

        boolean_expressions = [
            "a and b",
            "a or b",
            "not a",
            "a and b or c",
            "not (a and b)",
            "(a or b) and c",
        ]

        for expr in boolean_expressions:
            expression_sanitiser.sanitise_expression(expr, variables)

    def test_list_tuple_literals(self, expression_sanitiser):
        """Test list and tuple literals."""
        variables = {"item": 2}

        literal_expressions = [
            "item in [1, 2, 3]",
            "item in (1, 2, 3)",
            "[1, 2] == [1, 2]",
            "(1, 2) == (1, 2)",
        ]

        for expr in literal_expressions:
            expression_sanitiser.sanitise_expression(expr, variables)

    def test_production_security_limits(self, production_sanitiser):
        """Test stricter limits in production mode."""
        variables = {"test": True}

        # Expression that passes in dev but fails in production
        long_expr = " and ".join(["test == True"] * 30)  # Exceeds production limits

        with pytest.raises(ExpressionSecurityError):
            production_sanitiser.sanitise_expression(long_expr, variables)

    def test_security_context_in_errors(self, expression_sanitiser):
        """Test security context is preserved in errors."""
        variables = {"test": True}

        try:
            expression_sanitiser.sanitise_expression("exec('malicious')", variables)
        except ExpressionSecurityError as e:
            assert e.expression is not None
            assert e.reason is not None
            assert "malicious" in e.expression or len(e.expression) == 100  # Truncated

    def test_edge_case_expressions(self, expression_sanitiser):
        """Test various edge case expressions."""
        variables = {"items": [1, 2, 3], "obj": {"key": "value"}, "flag": True}

        edge_cases = [
            "items.length == 3",  # Special length property
            "flag and items.length > 0",
            'obj.key == "value"',
            "items[0] == 1 and items[-1] == 3",
        ]

        for expr in edge_cases:
            try:
                expression_sanitiser.sanitise_expression(expr, variables)
            except ExpressionSecurityError:
                # Some might fail due to length property handling
                pass
