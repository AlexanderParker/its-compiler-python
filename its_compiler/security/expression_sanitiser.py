"""
Expression sanitisation and validation for ITS Compiler conditionals.
"""

import ast
from typing import Any, Dict, List, Union

from ..core.exceptions import ITSConditionalError
from .config import SecurityConfig


class ExpressionSecurityError(ITSConditionalError):
    """Expression security validation error."""

    def __init__(self, message: str, expression: str, reason: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.expression = expression
        self.reason = reason


class ExpressionSanitiser:
    """Sanitises and validates conditional expressions for security."""

    # Allowed AST node types for safe expression evaluation
    ALLOWED_NODES = {
        ast.Expression,  # Root expression node
        ast.BoolOp,  # and, or
        ast.UnaryOp,  # not, -, +
        ast.Compare,  # ==, !=, <, >, <=, >=, in, not in
        ast.Name,  # Variable names
        ast.Constant,  # Python 3.8+ literal values
        ast.Num,  # Python < 3.8 numbers
        ast.Str,  # Python < 3.8 strings
        ast.NameConstant,  # Python < 3.8 True/False/None
        ast.List,  # List literals
        ast.Tuple,  # Tuple literals
        ast.Attribute,  # Object.property access
        ast.Subscript,  # Array[index] access
        ast.Index,  # Index wrapper (Python < 3.9)
        ast.Slice,  # For subscript operations
        # Operators
        ast.And,
        ast.Or,
        ast.Not,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.In,
        ast.NotIn,
        ast.USub,
        ast.UAdd,
        # Load context (for reading variables)
        ast.Load,
    }

    # Dangerous patterns in variable names or expressions
    DANGEROUS_PATTERNS = [
        r"__\w+__",  # Dunder methods
        r"exec\s*\(",  # exec calls
        r"eval\s*\(",  # eval calls
        r"import\s+",  # import statements
        r"open\s*\(",  # file operations
        r"subprocess",  # process execution
        r"os\.",  # OS operations
        r"sys\.",  # System operations
        r"globals\s*\(",  # globals access
        r"locals\s*\(",  # locals access
        r"vars\s*\(",  # vars access
        r"dir\s*\(",  # dir access
        r"getattr\s*\(",  # attribute access
        r"setattr\s*\(",  # attribute setting
        r"hasattr\s*\(",  # attribute checking
        r"delattr\s*\(",  # attribute deletion
    ]

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.processing_config = config.processing

        # Compile dangerous patterns
        import re

        self.dangerous_regex = re.compile("|".join(self.DANGEROUS_PATTERNS), re.IGNORECASE)

    def sanitise_expression(self, expression: str, variables: Dict[str, Any]) -> str:
        """Sanitise and validate a conditional expression."""

        # Basic length and structure checks
        self._validate_basic_structure(expression)

        # Check for dangerous patterns
        self._check_dangerous_patterns(expression)

        # Parse and validate AST
        try:
            parsed = ast.parse(expression, mode="eval")
        except SyntaxError as e:
            self._security_violation(expression, f"Syntax error in expression: {e}", "syntax_error")

        # Validate AST structure
        self._validate_ast_security(parsed.body, expression)

        # Validate variable references
        self._validate_variable_references(parsed, expression, variables)

        # Return sanitised expression (could be modified in future)
        return expression

    def _validate_basic_structure(self, expression: str) -> None:
        """Validate basic expression structure."""

        # Length check
        if len(expression) > self.processing_config.max_expression_length:
            self._security_violation(
                expression,
                f"Expression too long: {len(expression)} characters",
                "expression_too_long",
            )

        # Character validation
        if not expression.strip():
            self._security_violation(expression, "Empty expression", "empty_expression")

        # Basic balance checks
        if expression.count("(") != expression.count(")"):
            self._security_violation(expression, "Unbalanced parentheses", "unbalanced_parentheses")

        if expression.count("[") != expression.count("]"):
            self._security_violation(expression, "Unbalanced brackets", "unbalanced_brackets")

    def _check_dangerous_patterns(self, expression: str) -> None:
        """Check for dangerous patterns in the expression."""

        if self.dangerous_regex.search(expression):
            self._security_violation(
                expression,
                "Dangerous pattern detected in expression",
                "dangerous_pattern",
            )

        # Check for suspicious characters
        suspicious_chars = {"\\", "$", "`", "@"}
        if any(char in expression for char in suspicious_chars):
            self._security_violation(
                expression,
                "Suspicious characters in expression",
                "suspicious_characters",
            )

    def _validate_ast_security(self, node: ast.AST, expression: str, depth: int = 0) -> None:
        """Validate AST node structure for security."""

        # Depth check to prevent stack overflow
        if depth > self.processing_config.max_expression_depth:
            self._security_violation(expression, f"Expression nesting too deep: {depth}", "nesting_too_deep")

        # Node type validation
        node_type = type(node)
        if node_type not in self.ALLOWED_NODES:
            self._security_violation(
                expression,
                f"Forbidden AST node type: {node_type.__name__}",
                "forbidden_node_type",
            )

        # Specific node validations
        if isinstance(node, ast.Name):
            self._validate_variable_name(node.id, expression)

        elif isinstance(node, ast.Attribute):
            self._validate_attribute_access(node, expression)

        elif isinstance(node, ast.Subscript):
            self._validate_subscript_access(node, expression)

        elif isinstance(node, (ast.List, ast.Tuple)):
            self._validate_literal_size(node, expression)

        # Recursively validate child nodes
        for child in ast.iter_child_nodes(node):
            self._validate_ast_security(child, expression, depth + 1)

    def _validate_variable_name(self, name: str, expression: str) -> None:
        """Validate variable name."""

        # Length check
        if len(name) > self.processing_config.max_variable_name_length:
            self._security_violation(expression, f"Variable name too long: {name}", "variable_name_too_long")

        # Character validation
        allowed_chars = set(self.processing_config.allowed_variable_chars)
        if not all(c in allowed_chars for c in name):
            self._security_violation(
                expression,
                f"Invalid characters in variable name: {name}",
                "invalid_variable_chars",
            )

        # Check for dangerous names
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
        }
        if name in dangerous_names:
            self._security_violation(
                expression,
                f"Dangerous variable name: {name}",
                "dangerous_variable_name",
            )

    def _validate_attribute_access(self, node: ast.Attribute, expression: str) -> None:
        """Validate object property access."""

        attr_name = node.attr

        # Check attribute name
        if attr_name.startswith("_"):
            self._security_violation(
                expression,
                f"Private attribute access not allowed: {attr_name}",
                "private_attribute_access",
            )

        # Dangerous method names
        dangerous_attrs = {
            "exec",
            "eval",
            "compile",
            "__class__",
            "__bases__",
            "__subclasses__",
            "__import__",
            "__builtins__",
            "__globals__",
            "__locals__",
        }
        if attr_name in dangerous_attrs:
            self._security_violation(
                expression,
                f"Dangerous attribute access: {attr_name}",
                "dangerous_attribute_access",
            )

    def _validate_subscript_access(self, node: ast.Subscript, expression: str) -> None:
        """Validate array/dict subscript access."""

        # Extract the slice node - handle Python version differences
        slice_node = node.slice

        # Extract the index value, handling different AST node types
        index_value: Union[int, float, None] = None

        # Handle direct constants
        if isinstance(slice_node, ast.Constant):  # Python 3.8+
            if isinstance(slice_node.value, (int, float)):
                index_value = slice_node.value
        elif isinstance(slice_node, ast.Num):  # Python < 3.8
            index_value = slice_node.n
        # Handle negative numbers (UnaryOp with USub)
        elif isinstance(slice_node, ast.UnaryOp) and isinstance(slice_node.op, ast.USub):
            if isinstance(slice_node.operand, ast.Constant):
                # Type check to ensure value is numeric
                operand_value = slice_node.operand.value
                if isinstance(operand_value, (int, float)):
                    index_value = -operand_value
            elif isinstance(slice_node.operand, ast.Num):
                index_value = -slice_node.operand.n

        # Validate the index if we successfully extracted a numeric value
        if isinstance(index_value, (int, float)):
            max_index = self.processing_config.max_array_index

            # Convert to int for comparison if it's a float
            index_int = int(index_value) if isinstance(index_value, float) else index_value

            if index_int > max_index:
                self._security_violation(
                    expression,
                    f"Array index too large: {index_int}",
                    "array_index_too_large",
                )
            elif index_int < 0 and abs(index_int) > max_index:
                self._security_violation(
                    expression,
                    f"Array index too negative: {index_int}",
                    "array_index_too_negative",
                )

    def _validate_literal_size(self, node: ast.AST, expression: str) -> None:
        """Validate size of list/tuple literals."""

        if isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) > 100:  # Reasonable limit for literals
                self._security_violation(
                    expression,
                    f"Literal too large: {len(node.elts)} elements",
                    "literal_too_large",
                )

    def _validate_variable_references(self, parsed: ast.Expression, expression: str, variables: Dict[str, Any]) -> None:
        """Validate that variable references are safe."""

        # Extract all variable names from the AST
        var_names = set()
        for node in ast.walk(parsed):
            if isinstance(node, ast.Name):
                var_names.add(node.id)

        # Check reference count
        if len(var_names) > self.processing_config.max_variable_references:
            self._security_violation(
                expression,
                f"Too many variable references: {len(var_names)}",
                "too_many_variables",
            )

        # Validate each variable exists (basic check)
        for var_name in var_names:
            # Skip boolean literals
            if var_name in ("True", "False", "true", "false"):
                continue

            # Check if variable is defined
            if var_name not in variables:
                # This might not be a security issue, but we log it
                print(f"Warning: undefined variable '{var_name}' in expression")

    def _security_violation(self, expression: str, message: str, reason: str) -> None:
        """Log security violation and raise error."""
        print(f"Expression security violation: {message}")
        raise ExpressionSecurityError(
            message,
            expression=expression[:100],  # Limit logged expression length
            reason=reason,
        )

    def get_expression_complexity(self, expression: str) -> Dict[str, Any]:
        """Analyse expression complexity for monitoring."""

        try:
            parsed = ast.parse(expression, mode="eval")

            complexity: Dict[str, Any] = {
                "length": len(expression),
                "node_count": len(list(ast.walk(parsed))),
                "max_depth": self._calculate_ast_depth(parsed.body),
                "variable_count": len([n for n in ast.walk(parsed) if isinstance(n, ast.Name)]),
                "operator_count": len([n for n in ast.walk(parsed) if isinstance(n, ast.operator)]),
            }

            return complexity

        except Exception:
            return {"length": len(expression), "parse_error": True}

    def _calculate_ast_depth(self, node: ast.AST, current_depth: int = 0) -> int:
        """Calculate maximum depth of AST."""

        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            child_depth = self._calculate_ast_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)

        return max_depth

    def is_expression_safe(self, expression: str, variables: Dict[str, Any]) -> bool:
        """Quick safety check without exceptions."""

        try:
            self.sanitise_expression(expression, variables)
            return True
        except ExpressionSecurityError:
            return False

    def get_safe_operators(self) -> List[str]:
        """Get list of safe operators for documentation."""

        return [
            "==",
            "!=",
            "<",
            "<=",
            ">",
            ">=",  # Comparison
            "and",
            "or",
            "not",  # Boolean
            "in",
            "not in",  # Membership
            "+",
            "-",  # Unary
        ]

    def get_blocked_patterns(self) -> List[str]:
        """Get list of blocked patterns for documentation."""

        return [
            "Function calls: func()",
            "Import statements: import x",
            "Dunder methods: __method__",
            "File operations: open()",
            "System access: os.*, sys.*",
            "Dynamic access: getattr(), eval()",
        ]
