"""
Variable processing for ITS Compiler.
"""

import re
import json
from typing import Dict, List, Any, Union

from .exceptions import ITSVariableError


class VariableProcessor:
    """Handles variable resolution and substitution."""

    def __init__(self):
        # Pattern to match ${variable} references
        self.variable_pattern = re.compile(r"\$\{([^}]+)\}")

    def process_content(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process variable references in content elements."""
        processed_content = []

        for element in content:
            processed_element = self._process_element(element, variables)
            processed_content.append(processed_element)

        return processed_content

    def _process_element(
        self, element: Dict[str, Any], variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process variables in a single content element."""
        element_copy = element.copy()

        if element["type"] == "text":
            # Process variables in text content
            element_copy["text"] = self._process_string(element["text"], variables)

        elif element["type"] == "placeholder":
            # Process variables in placeholder config
            element_copy["config"] = self._process_dict(element["config"], variables)

        elif element["type"] == "conditional":
            # Process variables in condition expression
            element_copy["condition"] = self._process_string(
                element["condition"], variables
            )

            # Recursively process nested content
            element_copy["content"] = self.process_content(
                element["content"], variables
            )

            if "else" in element:
                element_copy["else"] = self.process_content(element["else"], variables)

        return element_copy

    def _process_dict(
        self, data: Dict[str, Any], variables: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process variables in a dictionary."""
        processed = {}

        for key, value in data.items():
            if isinstance(value, str):
                processed[key] = self._process_string(value, variables)
            elif isinstance(value, dict):
                processed[key] = self._process_dict(value, variables)
            elif isinstance(value, list):
                processed[key] = self._process_list(value, variables)
            else:
                processed[key] = value

        return processed

    def _process_list(self, data: List[Any], variables: Dict[str, Any]) -> List[Any]:
        """Process variables in a list."""
        processed = []

        for item in data:
            if isinstance(item, str):
                processed.append(self._process_string(item, variables))
            elif isinstance(item, dict):
                processed.append(self._process_dict(item, variables))
            elif isinstance(item, list):
                processed.append(self._process_list(item, variables))
            else:
                processed.append(item)

        return processed

    def _process_string(self, text: str, variables: Dict[str, Any]) -> str:
        """Process variable references in a string."""

        def replace_variable(match):
            var_ref = match.group(1)
            try:
                value = self.resolve_variable_reference(var_ref, variables)

                # Convert arrays to readable strings
                if isinstance(value, list):
                    return ", ".join(str(item) for item in value)

                return str(value)
            except ITSVariableError:
                # Re-raise with more context
                raise ITSVariableError(
                    f"Undefined variable reference: ${{{var_ref}}}",
                    variable_path=var_ref,
                    available_variables=list(variables.keys()),
                )

        return self.variable_pattern.sub(replace_variable, text)

    def resolve_variable_reference(
        self, var_ref: str, variables: Dict[str, Any]
    ) -> Any:
        """Resolve a variable reference like 'user.name', 'items[0]', or 'features.length'."""

        # Split on dots for object property access
        parts = var_ref.split(".")
        current = variables

        for i, part in enumerate(parts):
            # Handle array access like items[0]
            if "[" in part and part.endswith("]"):
                # Split array name and index
                array_match = re.match(r"([^[]+)\[(\d+)\]", part)
                if not array_match:
                    raise ITSVariableError(
                        f"Invalid array syntax in variable reference: {var_ref}",
                        variable_path=var_ref,
                    )

                array_name = array_match.group(1)
                array_index = int(array_match.group(2))

                if array_name not in current:
                    raise ITSVariableError(
                        f"Variable '{array_name}' not found in {'.'.join(parts[:i])}",
                        variable_path=var_ref,
                        available_variables=(
                            list(current.keys()) if isinstance(current, dict) else []
                        ),
                    )

                array_value = current[array_name]
                if not isinstance(array_value, list):
                    raise ITSVariableError(
                        f"Variable '{array_name}' is not an array",
                        variable_path=var_ref,
                    )

                if array_index >= len(array_value):
                    raise ITSVariableError(
                        f"Array index {array_index} out of bounds for '{array_name}' (length: {len(array_value)})",
                        variable_path=var_ref,
                    )

                current = array_value[array_index]
            else:
                # Handle special array/string properties
                if part == "length" and isinstance(current, (list, str)):
                    return len(current)

                # Regular property access
                if not isinstance(current, dict):
                    raise ITSVariableError(
                        f"Cannot access property '{part}' on non-object value",
                        variable_path=var_ref,
                    )

                if part not in current:
                    path_so_far = ".".join(parts[: i + 1])
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

    def validate_variables(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[str]:
        """Validate that all variable references can be resolved."""
        errors = []
        variable_refs = self.find_variable_references(content)

        for var_ref in variable_refs:
            try:
                self.resolve_variable_reference(var_ref, variables)
            except ITSVariableError as e:
                errors.append(str(e))

        return errors
