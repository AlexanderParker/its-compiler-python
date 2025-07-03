"""
Main ITS compiler implementation with core security enhancements.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .models import (
    ITSConfig,
    CompilationResult,
    ValidationResult,
    InstructionTypeDefinition,
    TypeOverride,
    OverrideType,
)
from .exceptions import (
    ITSValidationError,
    ITSCompilationError,
    ITSVariableError,
)
from .schema_loader import SchemaLoader
from .variable_processor import VariableProcessor
from .conditional_evaluator import ConditionalEvaluator
from .security import (
    SecurityConfig,
    InputValidator,
)


class ITSCompiler:
    """Main compiler for ITS templates with core security controls."""

    def __init__(
        self,
        config: Optional[ITSConfig] = None,
        security_config: Optional[SecurityConfig] = None,
    ):
        self.config = config or ITSConfig()
        self.security_config = security_config or SecurityConfig.from_environment()

        # Initialize security components
        self.input_validator = (
            InputValidator(self.security_config)
            if self.security_config.enable_input_validation
            else None
        )

        # Initialize core components with security
        self.schema_loader = SchemaLoader(self.config, self.security_config)
        self.variable_processor = VariableProcessor(self.security_config)
        self.conditional_evaluator = ConditionalEvaluator(self.security_config)

    def compile_file(
        self, template_path: str, variables: Optional[Dict[str, Any]] = None
    ) -> CompilationResult:
        """Compile a template from a file with security validation."""

        template_path_obj = Path(template_path)

        if not template_path_obj.exists():
            raise ITSCompilationError(f"Template file not found: {template_path}")

        # File security checks
        self._validate_file_security(template_path_obj)

        try:
            with open(template_path_obj, "r", encoding="utf-8") as f:
                template = json.load(f)
        except json.JSONDecodeError as e:
            raise ITSCompilationError(f"Invalid JSON in template file: {e}")

        # Set base URL for relative schema references
        base_url = None
        try:
            # Resolve to absolute path first to avoid relative URI issues
            abs_path = template_path_obj.resolve()
            base_url = abs_path.parent.as_uri() + "/"
        except (ValueError, OSError):
            # If we can't create a file URI, we'll skip relative URL resolution
            pass

        result = self.compile(template, variables, base_url)
        return result

    def _validate_file_security(self, template_path: Path) -> None:
        """Validate file security properties."""

        # Check file size
        try:
            file_size = template_path.stat().st_size
            if file_size > self.security_config.processing.max_template_size:
                raise ITSCompilationError(f"Template file too large: {file_size} bytes")
        except OSError as e:
            raise ITSCompilationError(f"Cannot access template file: {e}")

        # Check file extension
        if template_path.suffix.lower() not in {".json", ".its"}:
            print(f"Warning: Unusual file extension: {template_path.suffix}")

        # Validate filename for suspicious patterns
        filename = template_path.name
        suspicious_patterns = ["..", "%", "<", ">", "|", ":", '"', "?", "*"]
        if any(pattern in filename for pattern in suspicious_patterns):
            print(f"Warning: Suspicious filename pattern: {filename}")

    def compile(
        self,
        template: Dict[str, Any],
        variables: Optional[Dict[str, Any]] = None,
        base_url: Optional[str] = None,
    ) -> CompilationResult:
        """Compile a template dictionary with comprehensive security validation."""

        start_time = time.time()

        # Input validation
        if self.input_validator:
            try:
                self.input_validator.validate_template(template)
            except Exception as e:
                raise ITSValidationError(f"Template input validation failed: {e}")

        # Validate template structure
        validation_result = self.validate(template, base_url)
        if not validation_result.is_valid:
            raise ITSValidationError(
                "Template validation failed", validation_errors=validation_result.errors
            )

        # Merge template variables with provided variables
        template_variables = template.get("variables", {})
        merged_variables = {**template_variables, **(variables or {})}

        # Validate merged variables
        if self.input_validator and merged_variables:
            try:
                self.input_validator._validate_variables(merged_variables)
            except Exception as e:
                raise ITSValidationError(f"Variables validation failed: {e}")

        # Load and resolve instruction types
        instruction_types, overrides = self._load_instruction_types(template, base_url)

        # Process variables in content with security
        processed_content = self._process_variables(
            template["content"], merged_variables
        )

        # Evaluate conditionals with security
        final_content = self._evaluate_conditionals(processed_content, merged_variables)

        # Generate final prompt
        prompt = self._generate_prompt(final_content, instruction_types, template)

        # Validate final prompt
        self._validate_final_prompt(prompt)

        return CompilationResult(
            prompt=prompt,
            template=template,
            variables=merged_variables,
            overrides=overrides,
            warnings=validation_result.warnings,
        )

    def _validate_final_prompt(self, prompt: str) -> None:
        """Validate the final generated prompt for security."""

        # Check prompt length
        if len(prompt) > 1024 * 1024:  # 1MB limit
            print(f"Warning: Generated prompt is very large: {len(prompt)} characters")

        # Check for potential injection patterns in final output
        dangerous_patterns = [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"data\s*:\s*text/html",
            r"\\x[0-9a-fA-F]{2}",
        ]

        import re

        for pattern in dangerous_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                print(
                    f"Warning: Potentially dangerous pattern in final prompt: {pattern}"
                )

    def validate_file(self, template_path: str) -> ValidationResult:
        """Validate a template file with security checks."""

        template_path_obj = Path(template_path)

        if not template_path_obj.exists():
            return ValidationResult(
                is_valid=False,
                errors=[f"Template file not found: {template_path}"],
                warnings=[],
            )

        # File security validation
        try:
            self._validate_file_security(template_path_obj)
        except ITSCompilationError as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"File security validation failed: {e}"],
                warnings=[],
            )

        try:
            with open(template_path_obj, "r", encoding="utf-8") as f:
                template = json.load(f)
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Invalid JSON in template file: {e}"],
                warnings=[],
            )

        # Set base URL for relative schema references
        base_url = None
        try:
            # Resolve to absolute path first to avoid relative URI issues
            abs_path = template_path_obj.resolve()
            base_url = abs_path.parent.as_uri() + "/"
        except (ValueError, OSError) as e:
            # If we can't create a file URI, we'll skip relative URL resolution
            print(
                f"Warning: Could not create base URL for relative schema resolution: {e}"
            )

        result = self.validate(template, base_url)
        return result

    def validate(
        self, template: Dict[str, Any], base_url: Optional[str] = None
    ) -> ValidationResult:
        """Validate a template dictionary with security validation."""

        errors: List[str] = []
        warnings: List[str] = []

        # Input validation first
        if self.input_validator:
            try:
                self.input_validator.validate_template(template)
            except Exception as e:
                errors.append(f"Input validation failed: {e}")
                return ValidationResult(
                    is_valid=False, errors=errors, warnings=warnings
                )

        # Required fields
        if "version" not in template:
            errors.append("Missing required field: version")
        if "content" not in template:
            errors.append("Missing required field: content")
        elif not isinstance(template["content"], list):
            errors.append("Field 'content' must be an array")
        elif len(template["content"]) == 0:
            errors.append("Field 'content' cannot be empty")

        # Validate content elements
        if "content" in template:
            content_errors = self._validate_content(template["content"])
            errors.extend(content_errors)

        # Try to load schemas (this will catch schema-related errors)
        try:
            self._load_instruction_types(template, base_url)
        except Exception as e:
            errors.append(f"Schema loading error: {e}")

        # Always validate variables - check references even if no variables defined
        template_variables = template.get("variables", {})
        if "content" in template:
            var_errors = self._validate_variables(
                template_variables, template["content"]
            )
            errors.extend(var_errors)

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    def _validate_content(self, content: List[Dict[str, Any]]) -> List[str]:
        """Validate content elements with enhanced security checks."""
        errors: List[str] = []

        for i, element in enumerate(content):

            if "type" not in element:
                errors.append(f"Content element {i} missing required field: type")
                continue

            element_type = element["type"]

            if element_type == "text":
                if "text" not in element:
                    errors.append(f"Text element {i} missing required field: text")
                else:
                    # Validate text content for security
                    text_content = element["text"]
                    if len(str(text_content)) > 50000:  # Reasonable limit
                        errors.append(f"Text element {i} content too large")

            elif element_type == "placeholder":
                if "instructionType" not in element:
                    errors.append(
                        f"Placeholder element {i} missing required field: instructionType"
                    )
                if "config" not in element:
                    errors.append(
                        f"Placeholder element {i} missing required field: config"
                    )
                elif not isinstance(element["config"], dict):
                    errors.append(f"Placeholder element {i} config must be an object")
                elif "description" not in element["config"]:
                    errors.append(
                        f"Placeholder element {i} config missing required field: description"
                    )

            elif element_type == "conditional":
                if "condition" not in element:
                    errors.append(
                        f"Conditional element {i} missing required field: condition"
                    )
                if "content" not in element:
                    errors.append(
                        f"Conditional element {i} missing required field: content"
                    )
                elif not isinstance(element["content"], list):
                    errors.append(f"Conditional element {i} content must be an array")
                else:
                    # Recursively validate nested content
                    nested_errors = self._validate_content(element["content"])
                    errors.extend(nested_errors)

                if "else" in element:
                    if not isinstance(element["else"], list):
                        errors.append(f"Conditional element {i} else must be an array")
                    else:
                        nested_errors = self._validate_content(element["else"])
                        errors.extend(nested_errors)
            else:
                errors.append(f"Content element {i} has invalid type: {element_type}")

        return errors

    def _validate_variables(
        self, variables: Dict[str, Any], content: List[Dict[str, Any]]
    ) -> List[str]:
        """Validate that all variable references can be resolved."""
        errors: List[str] = []

        # Find all variable references in content
        content_str = json.dumps(content)
        import re

        variable_refs = re.findall(r"\$\{([^}]+)\}", content_str)

        for var_ref in variable_refs:
            try:
                self.variable_processor.resolve_variable_reference(var_ref, variables)
            except ITSVariableError:
                errors.append(f"Undefined variable reference: ${{{var_ref}}}")

        return errors

    def _load_instruction_types(
        self, template: Dict[str, Any], base_url: Optional[str] = None
    ) -> Tuple[Dict[str, InstructionTypeDefinition], List[TypeOverride]]:
        """Load and resolve instruction types from schemas."""

        instruction_types: Dict[str, InstructionTypeDefinition] = {}
        overrides: List[TypeOverride] = []

        # Load extended schemas in order
        extends = template.get("extends", [])
        for schema_url in extends:
            # Resolve relative URLs
            if base_url and not urlparse(schema_url).scheme:
                schema_url = urljoin(base_url, schema_url)

            schema = self.schema_loader.load_schema(schema_url)
            schema_types = schema.get("instructionTypes", {})

            # Check for overrides
            for type_name, type_def in schema_types.items():
                if type_name in instruction_types:
                    overrides.append(
                        TypeOverride(
                            type_name=type_name,
                            override_source=schema_url,
                            overridden_source=instruction_types[type_name].source
                            or "unknown",
                            override_type=OverrideType.SCHEMA_EXTENSION,
                        )
                    )

                instruction_types[type_name] = InstructionTypeDefinition(
                    name=type_name,
                    template=type_def["template"],
                    description=type_def.get("description"),
                    config_schema=type_def.get("configSchema"),
                    source=schema_url,
                )

        # Apply custom instruction types (highest precedence)
        custom_types = template.get("customInstructionTypes", {})
        for type_name, type_def in custom_types.items():
            if type_name in instruction_types:
                overrides.append(
                    TypeOverride(
                        type_name=type_name,
                        override_source="customInstructionTypes",
                        overridden_source=instruction_types[type_name].source
                        or "unknown",
                        override_type=OverrideType.CUSTOM,
                    )
                )

            instruction_types[type_name] = InstructionTypeDefinition(
                name=type_name,
                template=type_def["template"],
                description=type_def.get("description"),
                config_schema=type_def.get("configSchema"),
                source="custom",
            )

        return instruction_types, overrides

    def _process_variables(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Process variable references in content with security."""
        return self.variable_processor.process_content(content, variables)

    def _evaluate_conditionals(
        self, content: List[Dict[str, Any]], variables: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate conditional elements with security."""
        return self.conditional_evaluator.evaluate_content(content, variables)

    def _generate_prompt(
        self,
        content: List[Dict[str, Any]],
        instruction_types: Dict[str, InstructionTypeDefinition],
        template: Dict[str, Any],
    ) -> str:
        """Generate the final AI prompt."""

        # Get compiler configuration
        compiler_config = template.get("compilerConfig", {})
        system_prompt = compiler_config.get(
            "systemPrompt", self.config.default_system_prompt
        )
        user_content_wrapper = compiler_config.get(
            "userContentWrapper", self.config.default_user_content_wrapper
        )
        instruction_wrapper = compiler_config.get(
            "instructionWrapper", self.config.default_instruction_wrapper
        )
        processing_instructions = compiler_config.get(
            "processingInstructions", self.config.default_processing_instructions
        )

        # Process content elements
        processed_content = []

        for element in content:
            if element["type"] == "text":
                processed_content.append(element["text"])
            elif element["type"] == "placeholder":
                instruction = self._generate_instruction(
                    element, instruction_types, user_content_wrapper
                )

                # Check if the instruction already has wrapper brackets
                if instruction.startswith("<<") and instruction.endswith(">>"):
                    # Template already has wrapper, use as-is
                    processed_content.append(instruction)
                else:
                    # Template doesn't have wrapper, apply it
                    wrapped_instruction = instruction_wrapper.format(
                        instruction=instruction
                    )
                    processed_content.append(wrapped_instruction)

        # Assemble final prompt
        prompt_parts = ["INTRODUCTION", "", system_prompt, "", "INSTRUCTIONS", ""]

        for i, instruction in enumerate(processing_instructions or [], 1):
            prompt_parts.append(f"{i}. {instruction}")

        prompt_parts.extend(["", "TEMPLATE", "", "".join(processed_content)])

        return "\n".join(prompt_parts)

    def _generate_instruction(
        self,
        placeholder: Dict[str, Any],
        instruction_types: Dict[str, InstructionTypeDefinition],
        user_content_wrapper: str,
    ) -> str:
        """Generate an instruction for a placeholder."""

        instruction_type_name = placeholder["instructionType"]
        config = placeholder["config"]

        if instruction_type_name not in instruction_types:
            available_types = list(instruction_types.keys())
            raise ITSCompilationError(
                f"Unknown instruction type: '{instruction_type_name}'",
                element_id=placeholder.get("id"),
                details={"available_types": available_types},
            )

        instruction_type = instruction_types[instruction_type_name]

        try:
            return instruction_type.format_instruction(config, user_content_wrapper)
        except KeyError as e:
            raise ITSCompilationError(
                f"Missing required configuration for instruction type '{instruction_type_name}': {e}",
                element_id=placeholder.get("id"),
            )

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status."""
        status = {
            "security_enabled": True,
            "components": {
                "schema_loader": (
                    self.schema_loader.get_security_status()
                    if hasattr(self.schema_loader, "get_security_status")
                    else {}
                ),
                "variable_processor": self.variable_processor.get_security_status(),
                "conditional_evaluator": self.conditional_evaluator.get_security_status(),
            },
            "features": {
                "allowlist": self.security_config.enable_allowlist,
                "input_validation": self.security_config.enable_input_validation,
                "expression_sanitisation": self.security_config.enable_expression_sanitisation,
            },
        }

        return status
