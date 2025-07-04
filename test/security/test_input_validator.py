"""
Tests for InputValidator malicious content detection and input validation.
"""

from typing import Any, Dict

import pytest

from its_compiler.security import InputSecurityError, InputValidator, SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config for testing."""
    return SecurityConfig.for_development()


@pytest.fixture
def production_config() -> SecurityConfig:
    """Create production security config."""
    config = SecurityConfig.from_environment()
    config.processing.max_template_size = 1024 * 1024  # 1MB
    config.processing.max_content_elements = 500
    config.processing.max_nesting_depth = 8
    return config


@pytest.fixture
def input_validator(security_config: SecurityConfig) -> InputValidator:
    """Create input validator with test config."""
    return InputValidator(security_config)


@pytest.fixture
def production_validator(production_config: SecurityConfig) -> InputValidator:
    """Create input validator with production config."""
    return InputValidator(production_config)


class TestInputValidator:
    """Test InputValidator security functionality."""

    def test_valid_template_structure(self, input_validator: InputValidator) -> None:
        """Test valid template structure passes validation."""
        valid_template = {
            "version": "1.0.0",
            "content": [
                {"type": "text", "text": "Hello world"},
                {
                    "type": "placeholder",
                    "instructionType": "paragraph",
                    "config": {"description": "Write a paragraph"},
                },
            ],
        }

        # Should not raise exception
        input_validator.validate_template(valid_template)

    def test_template_too_large(self, input_validator: InputValidator) -> None:
        """Test template size limit enforcement."""
        # Create large template content
        large_text = "x" * (2 * 1024 * 1024)  # 2MB of content
        large_template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": large_text}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(large_template)

        assert "Template too large" in str(exc_info.value)
        assert exc_info.value.reason == "size_exceeded"

    def test_missing_required_fields(self, input_validator: InputValidator) -> None:
        """Test detection of missing required fields."""
        # Missing version
        template_no_version = {"content": [{"type": "text", "text": "test"}]}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template_no_version)

        assert "Missing required field: version" in str(exc_info.value)
        assert exc_info.value.reason == "missing_required_field"

        # Missing content
        template_no_content = {"version": "1.0.0"}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template_no_content)

        assert "Missing required field: content" in str(exc_info.value)

    def test_invalid_version_format(self, input_validator: InputValidator) -> None:
        """Test detection of invalid version format."""
        invalid_versions = [
            "1.0",  # Missing patch version
            "v1.0.0",  # Extra prefix
            "1.0.0-beta",  # Extra suffix
            "invalid",  # Not a version
        ]

        for version in invalid_versions:
            template = {
                "version": version,
                "content": [{"type": "text", "text": "test"}],
            }

            with pytest.raises(InputSecurityError) as exc_info:
                input_validator.validate_template(template)

            assert "Invalid version format" in str(exc_info.value)
            assert exc_info.value.reason == "invalid_version"

    def test_content_array_validation(self, input_validator: InputValidator) -> None:
        """Test content array validation."""
        # Empty content array
        empty_content_template = {"version": "1.0.0", "content": []}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(empty_content_template)

        assert "Content array cannot be empty" in str(exc_info.value)
        assert exc_info.value.reason == "empty_content"

        # Content not an array
        invalid_content_template = {"version": "1.0.0", "content": "not an array"}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(invalid_content_template)

        assert "Field 'content' must be an array" in str(exc_info.value)

    def test_too_many_content_elements(self, production_validator: InputValidator) -> None:
        """Test limit on number of content elements."""
        # Create template with too many elements
        many_elements = [{"type": "text", "text": f"element {i}"} for i in range(600)]

        template = {"version": "1.0.0", "content": many_elements}

        with pytest.raises(InputSecurityError) as exc_info:
            production_validator.validate_template(template)

        assert "Too many content elements" in str(exc_info.value)
        assert exc_info.value.reason == "too_many_elements"

    def test_text_element_validation(self, input_validator: InputValidator) -> None:
        """Test text element validation."""
        # Missing text field
        template = {"version": "1.0.0", "content": [{"type": "text"}]}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Text element 0 missing required field: text" in str(exc_info.value)
        assert exc_info.value.reason == "missing_text"

        # Invalid text type
        template = {"version": "1.0.0", "content": [{"type": "text", "text": 123}]}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "text must be string" in str(exc_info.value)

    def test_text_content_too_large(self, input_validator: InputValidator) -> None:
        """Test text content size limits."""
        large_text = "x" * 60000  # Exceeds limit

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": large_text}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Text content too large" in str(exc_info.value)

    def test_placeholder_element_validation(self, input_validator: InputValidator) -> None:
        """Test placeholder element validation."""
        # Missing instructionType
        template = {
            "version": "1.0.0",
            "content": [{"type": "placeholder", "config": {"description": "test"}}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing instructionType field" in str(exc_info.value)

        # Missing config
        template = {
            "version": "1.0.0",
            "content": [{"type": "placeholder", "instructionType": "paragraph"}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing config field" in str(exc_info.value)

        # Missing description in config
        template = {
            "version": "1.0.0",
            "content": [{"type": "placeholder", "instructionType": "paragraph", "config": {}}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing description" in str(exc_info.value)

    def test_conditional_element_validation(self, input_validator: InputValidator) -> None:
        """Test conditional element validation."""
        # Missing condition
        template = {
            "version": "1.0.0",
            "content": [{"type": "conditional", "content": [{"type": "text", "text": "test"}]}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing condition field" in str(exc_info.value)

        # Missing content
        template = {
            "version": "1.0.0",
            "content": [{"type": "conditional", "condition": "test == true"}],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing content field" in str(exc_info.value)

        # Invalid else type
        template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "conditional",
                    "condition": "test == true",
                    "content": [{"type": "text", "text": "test"}],
                    "else": "not an array",
                }
            ],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "else must be an array" in str(exc_info.value)

    def test_unknown_element_type(self, input_validator: InputValidator) -> None:
        """Test detection of unknown element types."""
        template = {"version": "1.0.0", "content": [{"type": "unknown_type"}]}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Unknown content element type: unknown_type" in str(exc_info.value)
        assert exc_info.value.reason == "unknown_type"

    def test_malicious_content_detection(self, input_validator: InputValidator) -> None:
        """Test detection of malicious content patterns."""
        malicious_patterns = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "eval('malicious code')",
            "Function('malicious')",
            "setTimeout('bad', 0)",
            "document.write('xss')",
            "window.location='evil.com'",
        ]

        for pattern in malicious_patterns:
            template = {
                "version": "1.0.0",
                "content": [{"type": "text", "text": pattern}],
            }

            with pytest.raises(InputSecurityError) as exc_info:
                input_validator.validate_template(template)

            assert "Malicious content detected" in str(exc_info.value)
            assert exc_info.value.reason == "malicious_content"

    def test_suspicious_encoding_detection(self, input_validator: InputValidator) -> None:
        """Test detection of suspicious encoding patterns."""
        suspicious_content = [
            "\\x61\\x6c\\x65\\x72\\x74",  # Hex encoding
            "\\u0061\\u006c\\u0065\\u0072\\u0074",  # Unicode encoding
            "%61%6c%65%72%74",  # URL encoding
        ]

        for content in suspicious_content:
            template = {
                "version": "1.0.0",
                "content": [{"type": "text", "text": content}],
            }

            with pytest.raises(InputSecurityError) as exc_info:
                input_validator.validate_template(template)

            assert "Suspicious encoding detected" in str(exc_info.value)
            assert exc_info.value.reason == "suspicious_encoding"

    def test_variables_validation(self, input_validator: InputValidator) -> None:
        """Test variables object validation."""
        # Variables not an object
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "variables": "not an object",
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Variables must be an object" in str(exc_info.value)
        assert exc_info.value.reason == "invalid_type"

    def test_variable_name_validation(self, input_validator: InputValidator) -> None:
        """Test variable name validation."""
        invalid_names = [
            "123invalid",  # Starts with number
            "invalid-name",  # Contains hyphen
            "invalid name",  # Contains space
            "invalid.name",  # Contains dot
            "constructor",  # Dangerous name
            "__proto__",  # Dangerous name
        ]

        for invalid_name in invalid_names:
            template = {
                "version": "1.0.0",
                "content": [{"type": "text", "text": "test"}],
                "variables": {invalid_name: "value"},
            }

            with pytest.raises(InputSecurityError) as exc_info:
                input_validator.validate_template(template)

            assert exc_info.value.reason in ["invalid_chars", "dangerous_name"]

    def test_variable_name_too_long(self, input_validator: InputValidator) -> None:
        """Test variable name length limit."""
        long_name = "a" * 200  # Exceeds limit

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "variables": {long_name: "value"},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Variable name too long" in str(exc_info.value)
        assert exc_info.value.reason == "name_too_long"

    def test_variable_value_validation(self, input_validator: InputValidator) -> None:
        """Test variable value validation."""
        # String too long
        long_string = "x" * 15000

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "variables": {"long": long_string},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "String value too long" in str(exc_info.value)

    def test_large_array_variable(self, input_validator: InputValidator) -> None:
        """Test large array variable validation."""
        large_array = list(range(2000))  # Very large array

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "variables": {"large_array": large_array},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Array too large" in str(exc_info.value)
        assert exc_info.value.reason == "array_too_large"

    def test_object_nesting_depth(self, input_validator: InputValidator) -> None:
        """Test object nesting depth validation."""
        # Create deeply nested object
        nested_obj: Dict[str, Any] = {}
        current = nested_obj
        for _ in range(15):  # Exceed depth limit
            current["nested"] = {}
            current = current["nested"]

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "variables": {"deep": nested_obj},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Object nesting too deep" in str(exc_info.value)
        assert exc_info.value.reason == "nesting_too_deep"

    def test_extensions_validation(self, input_validator: InputValidator) -> None:
        """Test extensions array validation."""
        # Extensions not an array
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "extends": "not an array",
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Extends must be an array" in str(exc_info.value)
        assert exc_info.value.reason == "invalid_type"

        # Too many extensions
        many_extensions = [f"https://example.com/schema{i}.json" for i in range(15)]
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "extends": many_extensions,
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Too many extensions" in str(exc_info.value)

    def test_invalid_extension_url(self, input_validator: InputValidator) -> None:
        """Test invalid extension URL detection."""
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "extends": ["not-a-url"],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Invalid extension URL" in str(exc_info.value)
        assert exc_info.value.reason == "invalid_extension_url"

    def test_custom_instruction_types_validation(self, input_validator: InputValidator) -> None:
        """Test custom instruction types validation."""
        # Too many custom types
        many_types = {f"type{i}": {"template": "test"} for i in range(60)}

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "customInstructionTypes": many_types,
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Too many custom instruction types" in str(exc_info.value)
        assert exc_info.value.reason == "too_many_types"

    def test_custom_type_definition_validation(self, input_validator: InputValidator) -> None:
        """Test custom instruction type definition validation."""
        # Missing template field
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "customInstructionTypes": {"custom": {"description": "test"}},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "missing template field" in str(exc_info.value)
        assert exc_info.value.reason == "missing_template"

    def test_identifier_validation(self, input_validator: InputValidator) -> None:
        """Test identifier validation."""
        # Invalid instruction type name
        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "customInstructionTypes": {"123invalid": {"template": "test"}},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Invalid identifier" in str(exc_info.value)
        assert exc_info.value.reason == "invalid_format"

    def test_identifier_too_long(self, input_validator: InputValidator) -> None:
        """Test identifier length validation."""
        long_name = "a" * 150

        template = {
            "version": "1.0.0",
            "content": [{"type": "text", "text": "test"}],
            "customInstructionTypes": {long_name: {"template": "test"}},
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Identifier too long" in str(exc_info.value)
        assert exc_info.value.reason == "too_long"

    def test_nested_content_validation(self, input_validator: InputValidator) -> None:
        """Test nested content validation in conditionals."""
        # Invalid nested content
        template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "conditional",
                    "condition": "test == true",
                    "content": [{"type": "invalid_type"}],
                }
            ],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Unknown content element type: invalid_type" in str(exc_info.value)

    def test_sanitise_filename(self, input_validator: InputValidator) -> None:
        """Test filename sanitisation."""
        dangerous_filenames = [
            "../../../etc/passwd",
            "file<>name.json",
            'file"name.json',
            "file|name.json",
            "file?name.json",
            "file*name.json",
        ]

        for filename in dangerous_filenames:
            sanitised = input_validator.sanitise_filename(filename)

            # Should not contain dangerous characters
            assert not any(char in sanitised for char in ["<", ">", ":", '"', "|", "?", "*", "\\"])

            # Should not contain path traversal
            assert ".." not in sanitised

    def test_dangerous_file_extension_sanitisation(self, input_validator: InputValidator) -> None:
        """Test dangerous file extension handling."""
        dangerous_extensions = [
            "malware.exe",
            "script.bat",
            "code.php",
            "shell.sh",
        ]

        for filename in dangerous_extensions:
            sanitised = input_validator.sanitise_filename(filename)

            # Should be converted to .txt
            assert sanitised.endswith(".txt")

    def test_filename_length_limit(self, input_validator: InputValidator) -> None:
        """Test filename length limiting."""
        long_filename = "a" * 300 + ".json"

        sanitised = input_validator.sanitise_filename(long_filename)

        # Should be truncated
        assert len(sanitised) <= 255

    def test_get_validation_stats(self, input_validator: InputValidator) -> None:
        """Test getting validation statistics."""
        stats = input_validator.get_validation_stats()

        expected_keys = [
            "max_template_size",
            "max_content_elements",
            "max_nesting_depth",
            "max_variable_name_length",
        ]

        for key in expected_keys:
            assert key in stats
            assert isinstance(stats[key], int)

    def test_config_object_validation(self, input_validator: InputValidator) -> None:
        """Test config object validation."""
        # Test nested config validation
        template = {
            "version": "1.0.0",
            "content": [
                {
                    "type": "placeholder",
                    "instructionType": "test",
                    "config": {
                        "description": "test",
                        "nested": {"malicious": "<script>alert('xss')</script>"},
                    },
                }
            ],
        }

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Malicious content detected" in str(exc_info.value)

    def test_content_element_not_object(self, input_validator: InputValidator) -> None:
        """Test content element that is not an object."""
        template = {"version": "1.0.0", "content": ["not an object"]}

        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template(template)

        assert "Content element 0 must be an object" in str(exc_info.value)

    def test_template_not_object(self, input_validator: InputValidator) -> None:
        """Test template that is not an object."""
        with pytest.raises(InputSecurityError) as exc_info:
            input_validator.validate_template("not an object")  # type: ignore

        assert "Template must be a JSON object" in str(exc_info.value)
