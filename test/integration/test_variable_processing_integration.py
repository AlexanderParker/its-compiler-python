"""
Integration tests for variable processing and conditional logic.
Tests using real templates from the its-example-templates repository.
Focus on complex real-world scenarios and template integration.
"""

from typing import Any, Dict

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.exceptions import ITSCompilationError, ITSValidationError, ITSVariableError


class TestVariableProcessingIntegration:
    """Test variable processing using real templates from the example repository."""

    @pytest.fixture
    def compiler(self) -> ITSCompiler:
        """Create compiler instance."""
        return ITSCompiler()

    @pytest.fixture
    def fetcher(self, template_fetcher):
        """Use the shared template fetcher fixture."""
        return template_fetcher

    def test_complex_variables_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 05-complex-variables.json with object properties and arrays."""
        template = fetcher.fetch_template("05-complex-variables.json")

        # Test with template's default variables
        result = compiler.compile(template)
        assert result.prompt is not None
        assert "EcoPhone Pro" in result.prompt
        assert "$899" in result.prompt
        assert "smartphone" in result.prompt
        assert "solar charging" in result.prompt

        # Test with custom variables
        custom_vars = fetcher.fetch_variables("custom-variables.json")
        result_custom = compiler.compile(template, variables=custom_vars)
        assert result_custom.prompt is not None
        assert "AI Assistant Pro" in result_custom.prompt
        assert "$299" in result_custom.prompt
        assert "software platform" in result_custom.prompt
        assert "natural language processing" in result_custom.prompt

    def test_complex_conditionals_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 07-complex-conditionals.json with complex conditional logic."""
        template = fetcher.fetch_template("07-complex-conditionals.json")

        # Test with complex-conditional-variables (beginner audience, low price, showBeginner=true)
        complex_vars = fetcher.fetch_variables("complex-conditional-variables.json")
        result_complex = compiler.compile(template, variables=complex_vars)
        assert result_complex.prompt is not None
        # Should show beginner content, not advanced (audience != "technical" or showBeginner == true)
        assert "getting started" in result_complex.prompt.lower()
        # Should not show premium features (price <= 1000)
        assert "premium features" not in result_complex.prompt.lower()
        # Should not show advanced details (audience != "technical" and showAdvanced == false)
        assert "advanced technical details" not in result_complex.prompt.lower()

        # Test with custom variables (should show different sections)
        template_vars = {
            "audience": "technical",
            "productPrice": 1200,
            "settings": {"showAdvanced": True, "showBeginner": False},
        }
        result_custom = compiler.compile(template, variables=template_vars)
        assert result_custom.prompt is not None
        # Should show advanced details (audience == "technical" and showAdvanced == true)
        assert "advanced technical details" in result_custom.prompt.lower()
        # Should show premium features (price > 1000)
        assert "premium features" in result_custom.prompt.lower()
        # Should not show beginner content (audience == "technical" and showBeginner == false)
        assert "getting started" not in result_custom.prompt.lower()

    def test_array_usage_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 09-array-usage.json with arrays and complex variable access."""
        template = fetcher.fetch_template("09-array-usage.json")

        # Test with template's default variables
        result = compiler.compile(template)
        assert result.prompt is not None
        assert "SmartHome Hub" in result.prompt
        assert "voice control, home automation, energy monitoring, security integration" in result.prompt
        assert "WiFi, Bluetooth, Zigbee" in result.prompt
        assert "smart, connected, efficient" in result.prompt
        assert "IoT device" in result.prompt

        # Test with custom variables
        custom_vars = fetcher.fetch_variables("custom-variables.json")
        result_custom = compiler.compile(template, variables=custom_vars)
        assert result_custom.prompt is not None
        assert "AI Assistant Pro" in result_custom.prompt
        assert "natural language processing, computer vision, predictive analytics" in result_custom.prompt
        assert "software platform" in result_custom.prompt

    def test_comprehensive_conditionals_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 10-comprehensive-conditionals.json with all conditional operators."""
        template = fetcher.fetch_template("10-comprehensive-conditionals.json")

        # Test with template's default variables
        result = compiler.compile(template)
        assert result.prompt is not None

        # Check that all conditional tests pass
        expected_tests = [
            "[OK] Unary NOT operator works",
            "[OK] AND operator with comparisons works",
            "[OK] IN operator with list works",
            "[OK] IN operator with string contains works",
            "[OK] NOT IN operator works",
            "[OK] Chained comparison works",
            "[OK] Greater than or equal works",
            "[OK] Less than or equal works",
            "[OK] Not equal operator works",
            "[OK] Parentheses and complex logic work",
            "[OK] Unary minus operator works",
            "[OK] Unary plus operator works",
            "[OK] Array length property works",
            "[OK] String length property works",
        ]

        for test in expected_tests:
            assert test in result.prompt, f"Missing test result: {test}"

        # Ensure no FAIL markers appear
        assert "[FAIL]" not in result.prompt

    def test_nested_object_access(self, compiler: ITSCompiler, fetcher) -> None:
        """Test deep object property access using complex variables."""
        template = fetcher.fetch_template("05-complex-variables.json")

        # Create variables with deeper nesting
        deep_vars = {
            "product": {
                "name": "Advanced Gadget",
                "category": "electronics",
                "price": 599,
                "specs": {
                    "performance": {"cpu": "High-end processor", "memory": {"ram": "16GB", "storage": "512GB SSD"}}
                },
            },
            "features": ["advanced AI", "premium materials"],
        }

        # Modify template to access deeper properties
        modified_template = template.copy()
        modified_template["content"][1]["config"][
            "description"
        ] = "Write about the ${product.name} which is a ${product.category} with ${product.specs.performance.memory.ram} RAM"

        result = compiler.compile(modified_template, variables=deep_vars)
        assert result.prompt is not None
        assert "Advanced Gadget" in result.prompt
        assert "electronics" in result.prompt
        assert "16GB RAM" in result.prompt

    def test_variable_override_precedence(self, compiler: ITSCompiler, fetcher) -> None:
        """Test that provided variables override template variables."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Override the template variables
        override_vars = {"topic": "artificial intelligence", "itemCount": 7}

        result = compiler.compile(template, variables=override_vars)
        assert result.prompt is not None
        assert "artificial intelligence" in result.prompt
        assert "7 examples" in result.prompt.lower()
        # Should not contain the original template values
        assert "sustainable technology" not in result.prompt

    def test_boolean_conditionals_with_different_values(self, compiler: ITSCompiler, fetcher) -> None:
        """Test boolean conditionals with various true/false combinations."""
        template = fetcher.fetch_template("06-simple-conditionals.json")

        # Test all false
        all_false_vars = {"includeSpecs": False, "includePricing": False, "productName": "Minimal Device"}

        result_false = compiler.compile(template, variables=all_false_vars)
        assert result_false.prompt is not None
        assert "Minimal Device" in result_false.prompt
        assert "availability" in result_false.prompt.lower()  # Should show else branch

        # Test all true
        all_true_vars = {"includeSpecs": True, "includePricing": True, "productName": "Full-Featured Device"}

        result_true = compiler.compile(template, variables=all_true_vars)
        assert result_true.prompt is not None
        assert "Full-Featured Device" in result_true.prompt
        assert "specifications" in result_true.prompt.lower() or "table" in result_true.prompt.lower()
        assert "pricing" in result_true.prompt.lower()

    def test_conditional_edge_cases(self, compiler: ITSCompiler, fetcher) -> None:
        """Test conditional evaluation with various edge cases."""
        template = fetcher.fetch_template("07-complex-conditionals.json")

        # Test edge cases for conditional logic
        edge_cases = [
            # Exact boundary conditions
            {
                "audience": "technical",
                "productPrice": 1000,  # Exactly at boundary
                "settings": {"showAdvanced": True, "showBeginner": False},
            },
            # Empty strings
            {"audience": "", "productPrice": 0, "settings": {"showAdvanced": False, "showBeginner": False}},
            # Extreme values
            {"audience": "expert", "productPrice": 99999, "settings": {"showAdvanced": True, "showBeginner": True}},
        ]

        for test_vars in edge_cases:
            result = compiler.compile(template, variables=test_vars)
            assert result.prompt is not None
            # Should handle edge cases gracefully without errors

    def test_mixed_variable_types(self, compiler: ITSCompiler, fetcher) -> None:
        """Test mixing different variable types in a single template."""
        template = fetcher.fetch_template("09-array-usage.json")

        # Mix different types of variables
        mixed_vars = {
            "product": {"name": "Mixed Type Test", "category": "test device", "price": 0},  # Edge case: zero price
            "features": [],  # Empty array
            "tags": ["single"],  # Single item array
            "specifications": {"connectivity": ["TCP", "UDP", "HTTP"]},  # Different protocols
        }

        result = compiler.compile(template, variables=mixed_vars)
        assert result.prompt is not None
        assert "Mixed Type Test" in result.prompt
        assert "test device" in result.prompt
        # Should handle empty arrays gracefully

    def test_all_variable_files_with_templates(self, compiler: ITSCompiler, fetcher) -> None:
        """Test all variable files with compatible templates."""
        variable_files = fetcher.list_variables()

        # Templates that work well with variables
        compatible_templates = [
            "05-complex-variables.json",
            "06-simple-conditionals.json",
            "09-array-usage.json",
        ]

        for var_file in variable_files:
            variables = fetcher.fetch_variables(var_file)

            for template_name in compatible_templates:
                template = fetcher.fetch_template(template_name)

                # Should compile successfully with any variable combination
                result = compiler.compile(template, variables=variables)
                assert result.prompt is not None
                assert len(result.prompt) > 0

    def test_variable_scoping_and_precedence(self, compiler: ITSCompiler, fetcher) -> None:
        """Test variable scoping and precedence rules."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Test that external variables completely override template variables
        external_vars = {
            "topic": "external topic",
            "itemCount": 99,
            "additionalVar": "should be ignored",  # Not used in template
        }

        result = compiler.compile(template, variables=external_vars)
        assert result.prompt is not None
        assert "external topic" in result.prompt
        assert "99 examples" in result.prompt.lower()
        assert "sustainable technology" not in result.prompt  # Template default overridden

    def test_error_handling_with_real_templates(self, compiler: ITSCompiler, fetcher) -> None:
        """Test error handling using real templates with missing variables."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Remove the variables section to cause undefined variable errors
        template_no_vars = template.copy()
        if "variables" in template_no_vars:
            del template_no_vars["variables"]

        # Should raise error for undefined variables
        with pytest.raises((ITSValidationError, ITSVariableError, ITSCompilationError)):
            compiler.compile(template_no_vars)
