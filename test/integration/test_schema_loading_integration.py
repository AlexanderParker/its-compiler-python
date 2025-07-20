"""
Integration tests for schema loading and custom instruction types.
Tests using real templates from the its-example-templates repository.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.exceptions import ITSCompilationError
from its_compiler.security import SecurityConfig

from .conftest import TemplateFetcher


class TestSchemaLoadingIntegration:
    """Test schema loading and custom instruction types with real templates."""

    @pytest.fixture
    def compiler(self) -> ITSCompiler:
        """Create compiler instance with development security config."""
        config = SecurityConfig.for_development()
        # Allow the official ITS schema domain
        config.allowlist.interactive_mode = False
        config.allowlist.auto_approve_in_ci = True
        config.allowlist.require_confirmation = False
        return ITSCompiler(security_config=config)

    @pytest.fixture
    def fetcher(self, template_fetcher: TemplateFetcher) -> TemplateFetcher:
        """Use the shared template fetcher fixture."""
        return template_fetcher

    def test_text_only_template_no_schema(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test 01-text-only.json with no external schemas or instruction types."""
        template = fetcher.fetch_template("01-text-only.json")

        # Verify this template has no schema extensions
        assert "extends" not in template
        assert "customInstructionTypes" not in template

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "This is a simple template with no placeholders" in result.prompt
        assert "It should compile to a prompt with just this text" in result.prompt
        # Should contain the standard prompt structure
        assert "INTRODUCTION" in result.prompt
        assert "INSTRUCTIONS" in result.prompt
        assert "TEMPLATE" in result.prompt

    @patch("socket.getaddrinfo")
    def test_single_placeholder_with_schema_loading(
        self, mock_getaddrinfo: MagicMock, compiler: ITSCompiler, fetcher: TemplateFetcher
    ) -> None:
        """Test 02-single-placeholder.json that loads external schema for instruction types."""
        # Mock DNS resolution for GitHub Pages
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("185.199.108.153", 443))]

        template = fetcher.fetch_template("02-single-placeholder.json")

        # Verify this template extends the standard types schema
        assert "extends" in template
        assert len(template["extends"]) > 0
        assert "alexanderparker.github.io" in template["extends"][0]
        assert "its-standard-types-v1.json" in template["extends"][0]

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "Here are some fruits:" in result.prompt
        assert "list 5 different citrus fruits" in result.prompt
        assert "bullet_points formatting" in result.prompt
        # Should use the 'list' instruction type from the loaded schema
        assert "list" in result.prompt.lower()

    @patch("socket.getaddrinfo")
    def test_multiple_placeholders_with_schema(
        self, mock_getaddrinfo: MagicMock, compiler: ITSCompiler, fetcher: TemplateFetcher
    ) -> None:
        """Test 03-multiple-placeholders.json with multiple instruction types from schema."""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("185.199.108.153", 443))]

        template = fetcher.fetch_template("03-multiple-placeholders.json")

        # Verify schema extension
        assert "extends" in template
        assert "its-standard-types-v1.json" in template["extends"][0]

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "Create a catchy title about healthy eating" in result.prompt
        assert "Write an engaging introduction about the benefits of healthy eating" in result.prompt
        assert "List 5 superfoods and their benefits" in result.prompt

        # Check that different instruction types are used (title, paragraph, list)
        content_elements = template["content"]
        instruction_types = [elem.get("instructionType") for elem in content_elements if elem["type"] == "placeholder"]
        assert "title" in instruction_types
        assert "paragraph" in instruction_types
        assert "list" in instruction_types

    def test_custom_instruction_types(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test 08-custom-types.json with custom instruction type definitions."""
        template = fetcher.fetch_template("08-custom-types.json")

        # Verify the template has custom instruction types
        assert "customInstructionTypes" in template
        assert "recipe_step" in template["customInstructionTypes"]

        # Check the custom type definition structure
        custom_type = template["customInstructionTypes"]["recipe_step"]
        assert "template" in custom_type
        assert "description" in custom_type
        assert "configSchema" in custom_type

        # Verify the template structure
        assert "stepNumber" in custom_type["configSchema"]["properties"]
        assert "duration" in custom_type["configSchema"]["properties"]

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "Chocolate Chip Cookies Recipe" in result.prompt
        assert "Step 1:" in result.prompt
        assert "Step 2:" in result.prompt
        assert "Duration: 5 minutes" in result.prompt
        assert "Duration: 3 minutes" in result.prompt
        assert "Preheat oven and prepare baking sheets" in result.prompt
        assert "Mix dry ingredients in a large bowl" in result.prompt
        assert "List required kitchen tools" in result.prompt

    @patch("socket.getaddrinfo")
    def test_schema_and_custom_type_combination(
        self, mock_getaddrinfo: MagicMock, compiler: ITSCompiler, fetcher: TemplateFetcher
    ) -> None:
        """Test 08-custom-types.json which has both schema extension and custom types."""
        mock_getaddrinfo.return_value = [(2, 1, 6, "", ("185.199.108.153", 443))]

        template = fetcher.fetch_template("08-custom-types.json")

        # This template has both schema extension and custom types
        assert "extends" in template
        assert "customInstructionTypes" in template

        # Should use custom recipe_step type and standard list type
        content_elements = template["content"]
        instruction_types = [elem.get("instructionType") for elem in content_elements if elem["type"] == "placeholder"]
        assert "recipe_step" in instruction_types  # Custom type
        assert "list" in instruction_types  # Standard type from schema

        result = compiler.compile(template)
        assert result.prompt is not None

        # Should have custom recipe_step formatting
        assert "Step 1:" in result.prompt
        assert "Duration: 5 minutes" in result.prompt

        # Should also have standard list formatting
        assert "List required kitchen tools" in result.prompt

    def test_templates_with_variables_and_schema_loading(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test templates that combine variables, conditionals, and schema loading."""
        # Test 04-simple-variables.json with schema
        template = fetcher.fetch_template("04-simple-variables.json")
        assert "extends" in template
        assert "variables" in template

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "sustainable technology" in result.prompt
        assert "Write an introduction about sustainable technology" in result.prompt
        assert "List 4 examples of sustainable technology" in result.prompt

    def test_complex_template_with_arrays_and_schema(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test 09-array-usage.json which uses arrays and schema loading."""
        template = fetcher.fetch_template("09-array-usage.json")

        # This template has schema extension, variables, and arrays
        assert "extends" in template
        assert "variables" in template
        assert "features" in template["variables"]
        assert isinstance(template["variables"]["features"], list)

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "SmartHome Hub" in result.prompt
        assert "voice control, home automation, energy monitoring, security integration" in result.prompt

    def test_conditional_templates_with_schema(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test conditional templates that also load schemas."""
        # Test 06-simple-conditionals.json
        template = fetcher.fetch_template("06-simple-conditionals.json")

        assert "extends" in template
        assert "variables" in template

        # Test with different variable combinations
        test_vars = fetcher.fetch_variables("conditional-test-variables.json")
        result = compiler.compile(template, variables=test_vars)
        assert result.prompt is not None
        assert "Gaming Laptop Pro X" in result.prompt

    def test_comprehensive_conditionals_no_schema(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test 10-comprehensive-conditionals.json which tests all operators."""
        template = fetcher.fetch_template("10-comprehensive-conditionals.json")

        # This template extends schema and has comprehensive conditional tests
        assert "extends" in template

        result = compiler.compile(template)
        assert result.prompt is not None

        # Should have all the conditional test results
        assert "[OK] Unary NOT operator works" in result.prompt
        assert "[OK] AND operator with comparisons works" in result.prompt
        assert "[OK] Array length property works" in result.prompt
        assert "[FAIL]" not in result.prompt

    def test_type_override_with_custom_types(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that custom instruction types can override schema types."""
        template = fetcher.fetch_template("08-custom-types.json")

        # Modify to override a standard type
        template_modified = template.copy()
        template_modified["customInstructionTypes"]["list"] = {
            "template": "CUSTOM LIST: ([{<{description}>}]) Format: {format}",
            "description": "Custom list that overrides standard list type",
        }

        result = compiler.compile(template_modified)
        assert result.prompt is not None

        # Should use the custom list type instead of schema list type
        assert "CUSTOM LIST:" in result.prompt
        assert "List required kitchen tools" in result.prompt

    def test_missing_instruction_type_error(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test error when instruction type is not found in schema or custom types."""
        template = fetcher.fetch_template("02-single-placeholder.json")

        # Modify to use non-existent instruction type
        template_modified = template.copy()
        template_modified["content"][1]["instructionType"] = "nonExistentType"

        with pytest.raises(ITSCompilationError) as exc_info:
            compiler.compile(template_modified)

        assert "unknown instruction type" in str(exc_info.value).lower()

    def test_schema_loading_failure_graceful_degradation(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that compilation fails gracefully when schema loading fails and no custom types exist."""
        template = fetcher.fetch_template("02-single-placeholder.json")

        # Modify to use a non-existent schema
        template_modified = template.copy()
        template_modified["extends"] = ["https://nonexistent.example.com/fake-schema.json"]

        # Should fail because it can't load the schema and doesn't have custom types
        with pytest.raises(ITSCompilationError):
            compiler.compile(template_modified)

    def test_schema_loading_with_variables_in_descriptions(
        self, compiler: ITSCompiler, fetcher: TemplateFetcher
    ) -> None:
        """Test schema loading combined with variable substitution in descriptions."""
        template = fetcher.fetch_template("05-complex-variables.json")

        # This template uses variables in instruction descriptions
        result = compiler.compile(template)
        assert result.prompt is not None

        # Check that variables are substituted in the instruction descriptions
        assert "EcoPhone Pro" in result.prompt
        assert "smartphone" in result.prompt
        assert "solar charging" in result.prompt
        assert "$899" in result.prompt

    def test_all_schema_loading_templates(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test all templates that use schema loading."""
        schema_templates = [
            "02-single-placeholder.json",
            "03-multiple-placeholders.json",
            "04-simple-variables.json",
            "05-complex-variables.json",
            "06-simple-conditionals.json",
            "07-complex-conditionals.json",
            "08-custom-types.json",
            "09-array-usage.json",
            "10-comprehensive-conditionals.json",
        ]

        for template_name in schema_templates:
            template = fetcher.fetch_template(template_name)

            # Verify template has schema extension
            assert "extends" in template, f"Template {template_name} should extend schemas"

            # Should compile successfully
            result = compiler.compile(template)
            assert result.prompt is not None
            assert len(result.prompt) > 0

    def test_custom_type_config_parameter_substitution(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that custom type config parameters are properly substituted."""
        template = fetcher.fetch_template("08-custom-types.json")

        # Check the recipe_step config parameters
        recipe_steps = [elem for elem in template["content"] if elem.get("instructionType") == "recipe_step"]
        assert len(recipe_steps) == 2

        # First step should have stepNumber=1, duration=5
        step1 = recipe_steps[0]
        assert step1["config"]["stepNumber"] == 1
        assert step1["config"]["duration"] == 5

        # Second step should have stepNumber=2, duration=3
        step2 = recipe_steps[1]
        assert step2["config"]["stepNumber"] == 2
        assert step2["config"]["duration"] == 3

        result = compiler.compile(template)
        assert result.prompt is not None
        assert "Step 1:" in result.prompt
        assert "Step 2:" in result.prompt
        assert "Duration: 5 minutes" in result.prompt
        assert "Duration: 3 minutes" in result.prompt

    def test_schema_url_validation(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that schema URLs are validated by security components."""
        template = fetcher.fetch_template("02-single-placeholder.json")

        # Verify the schema URL is from the trusted domain
        schema_url = template["extends"][0]
        assert schema_url.startswith("https://alexanderparker.github.io/")
        assert "its-standard-types-v1.json" in schema_url

        # Should compile successfully with trusted domain
        result = compiler.compile(template)
        assert result.prompt is not None

    def test_instruction_type_wrapper_application(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that instruction types get proper wrapper formatting."""
        template = fetcher.fetch_template("02-single-placeholder.json")

        result = compiler.compile(template)
        assert result.prompt is not None

        # Should have instruction wrapped with << >>
        assert "<<" in result.prompt
        assert ">>" in result.prompt
        # Should contain the user content wrapper ([{< >}])
        assert "([{<" in result.prompt
        assert ">}])" in result.prompt

    def test_compiler_override_reporting(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that compiler properly reports type overrides."""
        template = fetcher.fetch_template("08-custom-types.json")

        result = compiler.compile(template)
        assert result.prompt is not None

        # Check override reporting
        assert hasattr(result, "overrides")
        assert isinstance(result.overrides, list)

        # Should report any overrides that occurred
        if result.overrides:
            for override in result.overrides:
                assert hasattr(override, "type_name")
                assert hasattr(override, "override_source")

    def test_security_status_with_schema_components(self, compiler: ITSCompiler) -> None:
        """Test security status includes schema loading components."""
        status = compiler.get_security_status()

        assert "security_enabled" in status
        assert "components" in status
        assert "features" in status

        # Should have allowlist feature status
        assert "allowlist" in status["features"]

    def test_template_compilation_metrics(self, compiler: ITSCompiler, fetcher: TemplateFetcher) -> None:
        """Test that compilation provides useful metrics."""
        template = fetcher.fetch_template("08-custom-types.json")

        result = compiler.compile(template)
        assert result.prompt is not None

        # Check result metadata
        assert hasattr(result, "template")
        assert hasattr(result, "variables")
        assert hasattr(result, "overrides")
        assert hasattr(result, "warnings")

        # Template should be preserved
        assert result.template == template

        # Should have some variables (from template)
        assert isinstance(result.variables, dict)
