"""
Variable processing for ITS Compiler with security enhancements.
Variables can only contain static values - no references to other variables.
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..security import InputValidator, SecurityConfig
from .exceptions import ITSVariableError


class VariableProcessor:
    """Handles variable resolution and substitution with security controls."""

    def __init__(self, security_config: Optional[SecurityConfig] = None):
        # Pattern to match ${variable} references
        self.variable_pattern = re.compile(r"\$\{([^}]+)\}")

        # Security components
        self.security_config = security_config or SecurityConfig.from_environment()

        self.input_validator = (
            InputValidator(self.security_config) if self.security_config.enable_input_validation else None
        )

        # Processing limits
        self.max_recursion_depth = self.security_config.processing.max_nesting_depth
        self.max_variable_count = self.security_config.processing.max_variable_count
        self.max_variable_name_length = self.security_config.processing.max_variable_name_length

    def process_content(
        self,
        content: List[Dict[str, Any]],
        variables: Dict[str, Any],
        object_references: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Process variable references in content elements with security validation."""

        # Validate variables first
        if self.input_validator:
            try:
                self._validate_variables_security(variables)
            except Exception as e:
                raise ITSVariableError(f"Variable security validation failed: {e}")

        processed_content = []

        for element in content:
            try:
                processed_element = self._process_element(element, variables, object_references)
                processed_content.append(processed_element)
            except ITSVariableError:
                raise
            except Exception as e:
                raise ITSVariableError(f"Error processing variables in element: {e}")

        return processed_content

    def _validate_variables_security(self, variables: Dict[str, Any]) -> None:
        """Validate variables for security issues."""

        if not isinstance(variables, dict):
            raise ITSVariableError("Variables must be a dictionary")

        # Check total variable count (nested values included)
        total_vars = self._count_total_variables(variables)
        if total_vars > self.max_variable_count:
            raise ITSVariableError(f"Too many variables: {total_vars} (max: {self.max_variable_count})")

        # Validate each variable recursively
        self._validate_variable_object(variables, "", 0)

    def _count_total_variables(self, obj: Any, depth: int = 0) -> int:
        """Count total number of variables recursively."""

        if depth > self.max_recursion_depth:
            return 0

        count = 0
        if isinstance(obj, dict):
            count += len(obj)
            for value in obj.values():
                count += self._count_total_variables(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                count += self._count_total_variables(item, depth + 1)

        return count

    def _validate_variable_object(self, obj: Any, path: str, depth: int) -> None:
        """Recursively validate variable object structure."""

        if depth > self.max_recursion_depth:
            raise ITSVariableError(f"Variable nesting too deep at {path}")

        if isinstance(obj, dict):
            for key, value in obj.items():
                self._validate_variable_name(key, f"{path}.{key}" if path else key)
                self._validate_variable_value(value, f"{path}.{key}" if path else key)
                self._validate_variable_object(value, f"{path}.{key}" if path else key, depth + 1)

        elif isinstance(obj, list):
            if len(obj) > self.security_config.processing.max_variable_array_items:
                raise ITSVariableError(f"Array too large at {path}: {len(obj)} items")

            for i, item in enumerate(obj):
                self._validate_variable_object(item, f"{path}[{i}]", depth + 1)

    def _validate_variable_name(self, name: str, path: str) -> None:
        """Validate variable name for security."""

        if not isinstance(name, str):
            raise ITSVariableError(f"Variable name must be string at {path}")

        if len(name) > self.max_variable_name_length:
            raise ITSVariableError(f"Variable name too long at {path}: {len(name)} chars")

        # Check for valid identifier pattern
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
            raise ITSVariableError(f"Invalid variable name at {path}: {name}")

        # Check for dangerous names
        dangerous_names = {
            "constructor",
            "prototype",
            "__proto__",
            "__class__",
            "__bases__",
            "eval",
            "exec",
            "function",
            "import",
            "global",
            "globals",
            "locals",
            "vars",
            "dir",
            "open",
            "input",
            "compile",
        }

        if name.lower() in dangerous_names or name.startswith("__"):
            raise ITSVariableError(f"Dangerous variable name at {path}: {name}")

    def _validate_variable_value(self, value: Any, path: str) -> None:
        """Validate variable value for security."""

        if isinstance(value, str):
            # Check string length
            if len(value) > self.security_config.processing.max_text_length:
                raise ITSVariableError(f"String value too long at {path}: {len(value)} chars")

            # Check for dangerous content patterns
            dangerous_patterns = [
                r"<script[^>]*>",  # Script tags
                r"javascript\s*:",  # JavaScript URLs
                r"data\s*:\s*text/html",  # Data URLs
                r"eval\s*\(",  # eval calls
                r"Function\s*\(",  # Function constructor
                r"\\x[0-9a-fA-F]{2}",  # Hex encoding
                r"%[0-9a-fA-F]{2}",  # URL encoding
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    raise ITSVariableError(f"Dangerous content detected in variable at {path}")

        elif isinstance(value, (int, float)):
            # Check for reasonable numeric ranges
            if isinstance(value, (int, float)) and abs(value) > 1e15:
                raise ITSVariableError(f"Numeric value too large at {path}: {value}")

    def _process_element(
        self,
        element: Dict[str, Any],
        variables: Dict[str, Any],
        object_references: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Process variables in a single content element."""
        element_copy = element.copy()

        if element["type"] == "text":
            # Process variables in text content
            element_copy["text"] = self._process_string(element["text"], variables, object_references)

        elif element["type"] == "placeholder":
            # Process variables in placeholder config
            element_copy["config"] = self._process_dict(element["config"], variables, object_references)

        elif element["type"] == "conditional":
            # Process variables in condition expression (no object pointers there)
            element_copy["condition"] = self._process_string(element["condition"], variables)

            # Recursively process nested content
            element_copy["content"] = self.process_content(element["content"], variables, object_references)

            if "else" in element:
                element_copy["else"] = self.process_content(element["else"], variables, object_references)

        return element_copy

    def _process_dict(
        self,
        data: Dict[str, Any],
        variables: Dict[str, Any],
        object_references: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Process variables in a dictionary."""
        processed: Dict[str, Any] = {}

        for key, value in data.items():
            if isinstance(value, str):
                processed[key] = self._process_string(value, variables, object_references)
            elif isinstance(value, dict):
                processed[key] = self._process_dict(value, variables, object_references)
            elif isinstance(value, list):
                processed[key] = self._process_list(value, variables, object_references)
            else:
                processed[key] = value

        return processed

    def _process_list(
        self,
        data: List[Any],
        variables: Dict[str, Any],
        object_references: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """Process variables in a list."""
        processed: List[Any] = []

        for item in data:
            if isinstance(item, str):
                processed.append(self._process_string(item, variables, object_references))
            elif isinstance(item, dict):
                processed.append(self._process_dict(item, variables, object_references))
            elif isinstance(item, list):
                processed.append(self._process_list(item, variables, object_references))
            else:
                processed.append(item)

        return processed

    def _process_string(
        self,
        text: str,
        variables: Dict[str, Any],
        object_references: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Process variable references in a string with security validation."""

        # Check for too many variable references in a single string
        var_refs = self.variable_pattern.findall(text)
        if len(var_refs) > 50:  # Reasonable limit per string
            raise ITSVariableError(f"Too many variable references in string: {len(var_refs)}")

        def replace_variable(match: re.Match[str]) -> str:
            var_ref = match.group(1)

            # Validate variable reference syntax
            if len(var_ref) > 200:  # Reasonable limit for reference length
                raise ITSVariableError(f"Variable reference too long: {var_ref[:50]}...")

            # Check for dangerous patterns in variable reference
            if ".." in var_ref or var_ref.startswith("_") or "__" in var_ref:
                raise ITSVariableError(f"Suspicious variable reference: ${{{var_ref}}}")

            try:
                value = self.resolve_variable_reference(var_ref, variables)

                # Object values substitute a pointer and render as reference data
                if object_references is not None and isinstance(value, dict):
                    object_references[var_ref] = value
                    return f"the {var_ref} reference data"

                # Sanitise the resolved value
                sanitised_value = self._sanitise_resolved_value(value, var_ref)

                return sanitised_value

            except ITSVariableError:
                # Re-raise with more context
                raise ITSVariableError(
                    f"Undefined variable reference: ${{{var_ref}}}",
                    variable_path=var_ref,
                    available_variables=list(variables.keys()),
                )

        return self.variable_pattern.sub(replace_variable, text)

    def _sanitise_resolved_value(self, value: Any, var_ref: str) -> str:
        """Sanitise resolved variable value for safe output."""

        if isinstance(value, str):
            # String values are returned as-is
            return value

        elif isinstance(value, list):
            # Convert arrays to comma-separated string
            return ", ".join(str(item) for item in value)

        elif isinstance(value, dict):
            # Convert objects to safe string representation
            return f"[Object with {len(value)} properties]"

        else:
            # Convert other types to string with length limit
            str_value = str(value)
            max_text_length = self.security_config.processing.max_text_length
            if len(str_value) > max_text_length:
                str_value = str_value[:max_text_length] + "... [TRUNCATED]"
            return str_value

    _FUNCTION_SUFFIX = re.compile(r"^(.*)\.(concat|sum|avg|min|max|top)\(\s*([A-Za-z_][A-Za-z0-9_]*|\d+)?\s*\)$")

    def resolve_variable_reference(self, var_ref: str, variables: Dict[str, Any]) -> Any:
        """Resolve a variable reference with enhanced security validation."""

        # Collection functions are a suffix chain applied after path resolution
        calls: List[Tuple[str, Optional[str]]] = []
        base_ref = var_ref
        while True:
            suffix = self._FUNCTION_SUFFIX.match(base_ref)
            if not suffix:
                break
            calls.insert(0, (suffix.group(2), suffix.group(3)))
            base_ref = suffix.group(1)
        if calls:
            value = self.resolve_variable_reference(base_ref, variables)
            for name, arg in calls:
                value = self._apply_collection_function(value, name, arg, var_ref)
            return value
        var_ref = base_ref

        # Validate reference syntax - updated to allow negative array indices
        if not re.match(
            r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*(\[-?\d+\])*$",
            var_ref.replace(".length", ""),
        ):
            raise ITSVariableError(
                f"Invalid variable reference syntax: {var_ref}",
                variable_path=var_ref,
            )

        # Split on dots for object property access
        parts = var_ref.split(".")
        current: Any = variables

        # Track access depth for security
        access_depth = 0
        max_access_depth = self.security_config.processing.max_property_chain_depth

        for i, part in enumerate(parts):
            access_depth += 1
            if access_depth > max_access_depth:
                raise ITSVariableError(
                    f"Variable access chain too deep: {var_ref}",
                    variable_path=var_ref,
                )

            # Handle array access like items[0] or items[-1]
            if "[" in part and part.endswith("]"):
                # Split array name and index - updated to handle negative indices
                array_match = re.match(r"([^[]+)\[(-?\d+)\]", part)
                if not array_match:
                    raise ITSVariableError(
                        f"Invalid array syntax in variable reference: {var_ref}",
                        variable_path=var_ref,
                    )

                array_name = array_match.group(1)
                array_index = int(array_match.group(2))

                # Validate array index - check absolute value for size limit
                if abs(array_index) > self.security_config.processing.max_array_index:
                    raise ITSVariableError(
                        f"Array index too large: {array_index} in {var_ref}",
                        variable_path=var_ref,
                    )

                if array_name not in current:
                    raise ITSVariableError(
                        f"Variable '{array_name}' not found in {'.'.join(parts[:i])}",
                        variable_path=var_ref,
                        available_variables=(list(current.keys()) if isinstance(current, dict) else []),
                    )

                array_value = current[array_name]
                if not isinstance(array_value, list):
                    raise ITSVariableError(
                        f"Variable '{array_name}' is not an array",
                        variable_path=var_ref,
                    )

                # Handle negative indexing
                if array_index < 0:
                    # Convert negative index to positive
                    positive_index = len(array_value) + array_index
                    if positive_index < 0:
                        raise ITSVariableError(
                            f"Array index {array_index} out of bounds for '{array_name}' (length: {len(array_value)})",
                            variable_path=var_ref,
                        )
                    array_index = positive_index

                if array_index >= len(array_value):
                    raise ITSVariableError(
                        f"Array index {array_index} out of bounds for '{array_name}' (length: {len(array_value)})",
                        variable_path=var_ref,
                    )

                current = array_value[array_index]
            else:
                if part == "length" and isinstance(current, (list, str)):
                    # Handle special array/string properties
                    return len(current)

                # Regular property access
                if not isinstance(current, dict):
                    raise ITSVariableError(
                        f"Cannot access property '{part}' on non-object value",
                        variable_path=var_ref,
                    )

                if part not in current:
                    raise ITSVariableError(
                        f"Variable '{part}' not found in {'.'.join(parts[:i]) if i > 0 else 'root'}",
                        variable_path=var_ref,
                        available_variables=list(current.keys()),
                    )

                current = current[part]

        return current

    def find_variable_references(self, content: List[Dict[str, Any]]) -> List[str]:
        """Find all variable references in content."""
        content_str = json.dumps(content)
        matches = self.variable_pattern.findall(content_str)
        return list(set(matches))  # Remove duplicates

    def validate_variables(self, content: List[Dict[str, Any]], variables: Dict[str, Any]) -> List[str]:
        """Validate that all variable references can be resolved."""
        errors = []
        variable_refs = self.find_variable_references(content)

        for var_ref in variable_refs:
            try:
                self.resolve_variable_reference(var_ref, variables)
            except ITSVariableError as e:
                errors.append(str(e))

        return errors

    def _apply_collection_function(self, value: Any, name: str, arg: Optional[str], var_ref: str) -> Any:
        """Apply a collection function; semantics match the JavaScript and .NET compilers."""

        if not isinstance(value, list):
            raise ITSVariableError(
                f"Function {name}() requires an array in reference '{var_ref}'", variable_path=var_ref
            )

        if name == "top":
            if arg is None or not arg.isdigit():
                raise ITSVariableError(
                    f"top() requires a non-negative integer in reference '{var_ref}'", variable_path=var_ref
                )
            return value[: int(arg)]

        items: List[Any] = []
        for item in value:
            if arg is None:
                if isinstance(item, (dict, list)):
                    raise ITSVariableError(
                        f"Function {name}() requires a property name for object items in reference '{var_ref}'",
                        variable_path=var_ref,
                    )
                items.append(item)
            else:
                if not isinstance(item, dict) or arg not in item:
                    raise ITSVariableError(
                        f"Property '{arg}' not found on every item in reference '{var_ref}'", variable_path=var_ref
                    )
                items.append(item[arg])

        if name == "concat":
            return ", ".join(self._concat_text(item) for item in items)

        numbers: List[float] = []
        for item in items:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise ITSVariableError(
                    f"Function {name}() requires numeric values in reference '{var_ref}'", variable_path=var_ref
                )
            numbers.append(item)

        if name == "sum":
            return self._normalise_number(sum(numbers))
        if not numbers:
            raise ITSVariableError(f"{name}() of an empty array in reference '{var_ref}'", variable_path=var_ref)
        if name == "avg":
            return self._normalise_number(sum(numbers) / len(numbers))
        if name == "min":
            return self._normalise_number(min(numbers))
        return self._normalise_number(max(numbers))

    @staticmethod
    def _concat_text(item: Any) -> str:
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "true" if item else "false"
        return str(item)

    @staticmethod
    def _normalise_number(value: float) -> Any:
        """Whole numbers render without a decimal part, matching the other compilers."""
        return int(value) if isinstance(value, float) and value.is_integer() else value

    def get_security_status(self) -> Dict[str, Any]:
        """Get security status for variable processing."""
        return {
            "input_validation_enabled": self.input_validator is not None,
            "max_variable_count": self.max_variable_count,
            "max_variable_name_length": self.max_variable_name_length,
            "max_recursion_depth": self.max_recursion_depth,
        }
