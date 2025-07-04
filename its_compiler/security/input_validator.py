"""
Input validation and sanitisation for ITS Compiler.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Union

from ..exceptions import ITSValidationError
from .config import SecurityConfig


class InputSecurityError(ITSValidationError):
    """Input security validation error."""

    def __init__(self, message: str, input_type: str, reason: str, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.input_type = input_type
        self.reason = reason


class InputValidator:
    """Validates and sanitises template inputs for security."""

    # Dangerous content patterns
    MALICIOUS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript\s*:",  # JavaScript URLs
        r"data\s*:\s*text/html",  # Data URLs with HTML
        r'on\w+\s*=\s*["\'][^"\']*["\']',  # Event handlers
        r"eval\s*\(",  # eval calls
        r"Function\s*\(",  # Function constructor
        r"setTimeout\s*\(",  # setTimeout
        r"setInterval\s*\(",  # setInterval
        r"\.innerHTML\s*=",  # innerHTML assignment
        r"document\.\w+",  # DOM access
        r"window\.\w+",  # Window access
        r"\\x[0-9a-fA-F]{2}",  # Hex encoding
        r"\\u[0-9a-fA-F]{4}",  # Unicode encoding
        r"%[0-9a-fA-F]{2}",  # URL encoding
    ]

    # Suspicious file extensions
    DANGEROUS_EXTENSIONS = {
        ".exe",
        ".bat",
        ".cmd",
        ".com",
        ".scr",
        ".pif",
        ".vbs",
        ".js",
        ".jar",
        ".php",
        ".asp",
        ".jsp",
        ".py",
        ".rb",
        ".pl",
        ".sh",
    }

    def __init__(
        self,
        config: SecurityConfig,
    ):
        self.config = config
        self.processing_config = config.processing

        # Compile patterns
        self.malicious_regex = re.compile("|".join(self.MALICIOUS_PATTERNS), re.IGNORECASE)

    def validate_template(self, template: Dict[str, Any], template_path: Optional[str] = None) -> None:
        """Validate complete template structure and content."""

        # Size validation
        self._validate_template_size(template)

        # Structure validation
        self._validate_template_structure(template)

        # Content validation
        if "content" in template:
            self._validate_content_array(template["content"], template_path)

        # Variables validation
        if "variables" in template:
            self._validate_variables(template["variables"])

        # Extensions validation
        if "extends" in template:
            self._validate_extensions(template["extends"])

        # Custom types validation
        if "customInstructionTypes" in template:
            self._validate_custom_types(template["customInstructionTypes"])

    def _validate_template_size(self, template: Dict[str, Any]) -> None:
        """Validate template size limits."""

        template_json = json.dumps(template)
        size = len(template_json.encode("utf-8"))

        if size > self.processing_config.max_template_size:
            self._security_violation(f"Template too large: {size} bytes", "template", "size_exceeded")

    def _validate_template_structure(self, template: Dict[str, Any]) -> None:
        """Validate basic template structure."""

        # Check for required fields
        required_fields = ["version", "content"]
        for field in required_fields:
            if field not in template:
                self._security_violation(
                    f"Missing required field: {field}",
                    "template",
                    "missing_required_field",
                )

        # Validate version format
        version = template.get("version")
        if not isinstance(version, str) or not re.match(r"^\d+\.\d+\.\d+$", version):
            self._security_violation(f"Invalid version format: {version}", "template", "invalid_version")

    def _validate_content_array(self, content: List[Dict[str, Any]], template_path: Optional[str] = None) -> None:
        """Validate content array and elements."""

        if len(content) > self.processing_config.max_content_elements:
            self._security_violation(
                f"Too many content elements: {len(content)}",
                "content",
                "too_many_elements",
            )

        if len(content) == 0:
            self._security_violation("Content array cannot be empty", "content", "empty_content")

        for i, element in enumerate(content):
            self._validate_content_element(element, i, template_path)

    def _validate_content_element(
        self, element: Dict[str, Any], index: int, template_path: Optional[str] = None
    ) -> None:
        """Validate individual content element."""

        if not isinstance(element, dict):
            self._security_violation(
                f"Content element {index} must be an object",
                "content_element",
                "invalid_type",
            )

        if "type" not in element:
            self._security_violation(
                f"Content element {index} missing type field",
                "content_element",
                "missing_type",
            )

        element_type = element["type"]

        if element_type == "text":
            self._validate_text_element(element, index)
        elif element_type == "placeholder":
            self._validate_placeholder_element(element, index)
        elif element_type == "conditional":
            self._validate_conditional_element(element, index, template_path)
        else:
            self._security_violation(
                f"Unknown content element type: {element_type}",
                "content_element",
                "unknown_type",
            )

    def _validate_text_element(self, element: Dict[str, Any], index: int) -> None:
        """Validate text content element."""

        if "text" not in element:
            self._security_violation(
                f"Text element {index} missing text field",
                "text_element",
                "missing_text",
            )

        text_content = element["text"]
        if not isinstance(text_content, str):
            self._security_violation(
                f"Text element {index} text must be string",
                "text_element",
                "invalid_text_type",
            )

        # Check for malicious content
        self._validate_text_content(text_content, f"text_element_{index}")

    def _validate_placeholder_element(self, element: Dict[str, Any], index: int) -> None:
        """Validate placeholder content element."""

        required_fields = ["instructionType", "config"]
        for field in required_fields:
            if field not in element:
                self._security_violation(
                    f"Placeholder element {index} missing {field} field",
                    "placeholder_element",
                    f"missing_{field}",
                )

        # Validate instruction type
        instruction_type = element["instructionType"]
        if not isinstance(instruction_type, str):
            self._security_violation(
                f"Placeholder element {index} instructionType must be string",
                "placeholder_element",
                "invalid_instruction_type",
            )

        self._validate_identifier(instruction_type, f"instructionType_{index}")

        # Validate config
        config = element["config"]
        if not isinstance(config, dict):
            self._security_violation(
                f"Placeholder element {index} config must be object",
                "placeholder_element",
                "invalid_config_type",
            )

        # Check required config fields
        if "description" not in config:
            self._security_violation(
                f"Placeholder element {index} config missing description",
                "placeholder_element",
                "missing_description",
            )

        # Validate config content
        self._validate_config_object(config, f"placeholder_{index}")

    def _validate_conditional_element(
        self, element: Dict[str, Any], index: int, template_path: Optional[str] = None
    ) -> None:
        """Validate conditional content element."""

        required_fields = ["condition", "content"]
        for field in required_fields:
            if field not in element:
                self._security_violation(
                    f"Conditional element {index} missing {field} field",
                    "conditional_element",
                    f"missing_{field}",
                )

        # Validate condition
        condition = element["condition"]
        if not isinstance(condition, str):
            self._security_violation(
                f"Conditional element {index} condition must be string",
                "conditional_element",
                "invalid_condition_type",
            )

        self._validate_text_content(condition, f"condition_{index}")

        # Validate nested content
        nested_content = element["content"]
        if not isinstance(nested_content, list):
            self._security_violation(
                f"Conditional element {index} content must be array",
                "conditional_element",
                "invalid_content_type",
            )

        self._validate_content_array(nested_content, template_path)

        # Validate else content if present
        if "else" in element:
            else_content = element["else"]
            if not isinstance(else_content, list):
                self._security_violation(
                    f"Conditional element {index} else must be array",
                    "conditional_element",
                    "invalid_else_type",
                )
            self._validate_content_array(else_content, template_path)

    def _validate_variables(self, variables: Dict[str, Any]) -> None:
        """Validate variables object."""

        if not isinstance(variables, dict):
            self._security_violation("Variables must be an object", "variables", "invalid_type")

        self._validate_object_depth(variables, 0, "variables")

        for key, value in variables.items():
            self._validate_variable_name(key)
            self._validate_variable_value(value, key)

    def _validate_variable_name(self, name: str) -> None:
        """Validate variable name."""

        if len(name) > self.processing_config.max_variable_name_length:
            self._security_violation(f"Variable name too long: {name}", "variable_name", "name_too_long")

        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
            self._security_violation(f"Invalid variable name: {name}", "variable_name", "invalid_chars")

        # Check for dangerous names
        dangerous_names = {
            "constructor",
            "prototype",
            "__proto__",
            "eval",
            "function",
            "this",
            "window",
            "document",
            "global",
            "process",
        }
        if name.lower() in dangerous_names:
            self._security_violation(f"Dangerous variable name: {name}", "variable_name", "dangerous_name")

    def _validate_variable_value(self, value: Any, path: str) -> None:
        """Validate variable value."""

        if isinstance(value, str):
            self._validate_text_content(value, f"variable_{path}")
        elif isinstance(value, dict):
            self._validate_object_depth(value, 0, f"variable_{path}")
            for k, v in value.items():
                self._validate_variable_name(k)
                self._validate_variable_value(v, f"{path}.{k}")
        elif isinstance(value, list):
            if len(value) > 1000:  # Reasonable limit
                self._security_violation(
                    f"Array too large in variable {path}",
                    "variable_value",
                    "array_too_large",
                )
            for i, item in enumerate(value):
                self._validate_variable_value(item, f"{path}[{i}]")

    def _validate_extensions(self, extends: List[str]) -> None:
        """Validate extends array."""

        if not isinstance(extends, list):
            self._security_violation("Extends must be an array", "extends", "invalid_type")

        if len(extends) > 10:  # Reasonable limit
            self._security_violation(f"Too many extensions: {len(extends)}", "extends", "too_many_extensions")

        for i, url in enumerate(extends):
            if not isinstance(url, str):
                self._security_violation(
                    f"Extension {i} must be a string",
                    "extends",
                    "invalid_extension_type",
                )

            # Basic URL validation (detailed validation done by URL validator)
            if not re.match(r"^https?://", url):
                self._security_violation(f"Invalid extension URL: {url}", "extends", "invalid_extension_url")

    def _validate_custom_types(self, custom_types: Dict[str, Any]) -> None:
        """Validate custom instruction types."""

        if not isinstance(custom_types, dict):
            self._security_violation(
                "Custom instruction types must be an object",
                "custom_types",
                "invalid_type",
            )

        if len(custom_types) > 50:  # Reasonable limit
            self._security_violation(
                f"Too many custom instruction types: {len(custom_types)}",
                "custom_types",
                "too_many_types",
            )

        for type_name, type_def in custom_types.items():
            self._validate_identifier(type_name, f"custom_type_{type_name}")
            self._validate_custom_type_definition(type_def, type_name)

    def _validate_custom_type_definition(self, type_def: Dict[str, Any], type_name: str) -> None:
        """Validate custom instruction type definition."""

        if not isinstance(type_def, dict):
            self._security_violation(
                f"Custom type {type_name} definition must be an object",
                "custom_type_def",
                "invalid_type",
            )

        if "template" not in type_def:
            self._security_violation(
                f"Custom type {type_name} missing template field",
                "custom_type_def",
                "missing_template",
            )

        template = type_def["template"]
        if not isinstance(template, str):
            self._security_violation(
                f"Custom type {type_name} template must be string",
                "custom_type_def",
                "invalid_template_type",
            )

        self._validate_text_content(template, f"custom_type_{type_name}_template")

    def _validate_config_object(self, config: Dict[str, Any], context: str) -> None:
        """Validate configuration object."""

        for key, value in config.items():
            self._validate_identifier(key, f"{context}_config_key")

            if isinstance(value, str):
                self._validate_text_content(value, f"{context}_config_{key}")
            elif isinstance(value, dict):
                self._validate_config_object(value, f"{context}_{key}")
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        self._validate_text_content(item, f"{context}_config_{key}_{i}")

    def _validate_text_content(self, text: str, context: str) -> None:
        """Validate text content for malicious patterns."""

        # Length check
        if len(text) > 10000:  # Reasonable limit for text content
            self._security_violation(f"Text content too long in {context}", "text_content", "text_too_long")

        # Check for malicious patterns
        if self.malicious_regex.search(text):
            self._security_violation(
                f"Malicious content detected in {context}",
                "text_content",
                "malicious_content",
            )

        # Check for suspicious encoding
        if "\\x" in text or "\\u" in text or "%" in text:
            # More detailed check for actual encoding
            if re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}", text):
                self._security_violation(
                    f"Suspicious encoding detected in {context}",
                    "text_content",
                    "suspicious_encoding",
                )

    def _validate_identifier(self, identifier: str, context: str) -> None:
        """Validate identifier (type names, variable names, etc.)."""

        if not isinstance(identifier, str):
            self._security_violation(f"Identifier must be string in {context}", "identifier", "invalid_type")

        if len(identifier) > 100:
            self._security_violation(
                f"Identifier too long in {context}: {identifier}",
                "identifier",
                "too_long",
            )

        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", identifier):
            self._security_violation(
                f"Invalid identifier in {context}: {identifier}",
                "identifier",
                "invalid_format",
            )

    def _validate_object_depth(self, obj: Union[Dict[str, Any], List[Any]], current_depth: int, context: str) -> None:
        """Validate object nesting depth."""

        if current_depth > self.processing_config.max_nesting_depth:
            self._security_violation(
                f"Object nesting too deep in {context}",
                "object_depth",
                "nesting_too_deep",
            )

        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    self._validate_object_depth(value, current_depth + 1, f"{context}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    self._validate_object_depth(item, current_depth + 1, f"{context}[{i}]")

    def _security_violation(self, message: str, input_type: str, reason: str) -> NoReturn:
        """Log security violation and raise error."""
        raise InputSecurityError(message, input_type=input_type, reason=reason)

    def sanitise_filename(self, filename: str) -> str:
        """Sanitise filename for safe storage."""

        # Remove path components
        filename = Path(filename).name

        # Check extension
        suffix = Path(filename).suffix.lower()
        if suffix in self.DANGEROUS_EXTENSIONS:
            filename = filename.replace(suffix, ".txt")

        # Remove dangerous characters
        sanitised = re.sub(r'[<>:"|?*\\]', "_", filename)

        # Limit length
        if len(sanitised) > 255:
            name, ext = Path(sanitised).stem, Path(sanitised).suffix
            sanitised = name[: 250 - len(ext)] + ext

        return sanitised

    def get_validation_stats(self) -> Dict[str, int]:
        """Get validation statistics."""

        return {
            "max_template_size": self.processing_config.max_template_size,
            "max_content_elements": self.processing_config.max_content_elements,
            "max_nesting_depth": self.processing_config.max_nesting_depth,
            "max_variable_name_length": self.processing_config.max_variable_name_length,
        }
