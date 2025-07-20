"""
Integration tests for variable processing and conditional logic.
Tests using real templates from the its-example-templates repository.
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

    def test_simple_variables_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 04-simple-variables.json with default and custom variables."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Test with template's default variables
        result = compiler.compile(template)
        assert result.prompt is not None
        assert "sustainable technology" in result.prompt
        assert "4 examples" in result.prompt.lower()

        # Test with custom variables
        custom_vars = fetcher.fetch_variables("custom-variables.json")
        result_custom = compiler.compile(template, variables=custom_vars)
        assert result_custom.prompt is not None
        assert "machine learning algorithms" in result_custom.prompt
        assert "7 examples" in result_custom.prompt.lower()

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

    def test_simple_conditionals_template(self, compiler: ITSCompiler, fetcher) -> None:
        """Test 06-simple-conditionals.json with different variable sets."""
        template = fetcher.fetch_template("06-simple-conditionals.json")

        # Test with conditional-test-variables (includePricing=true, includeSpecs=false)
        test_vars = fetcher.fetch_variables("conditional-test-variables.json")
        result_test = compiler.compile(template, variables=test_vars)
        assert result_test.prompt is not None
        assert "Gaming Laptop Pro X" in result_test.prompt
        assert "pricing" in result_test.prompt.lower()
        assert "specifications" not in result_test.prompt.lower() or "table" not in result_test.prompt.lower()

        # Test with conditional-minimal-variables (both false)
        minimal_vars = fetcher.fetch_variables("conditional-minimal-variables.json")
        result_minimal = compiler.compile(template, variables=minimal_vars)
        assert result_minimal.prompt is not None
        assert "Basic Fitness Tracker" in result_minimal.prompt
        assert "availability" in result_minimal.prompt.lower()
        assert "pricing" not in result_minimal.prompt.lower()
        assert "specifications" not in result_minimal.prompt.lower() or "table" not in result_minimal.prompt.lower()

        # Test with custom variables (includeSpecs=true by default)
        custom_vars = fetcher.fetch_variables("custom-variables.json")
        result_custom = compiler.compile(template, variables=custom_vars)
        assert result_custom.prompt is not None
        assert "SmartWatch X1" in result_custom.prompt
        assert "specifications" in result_custom.prompt.lower() or "table" in result_custom.prompt.lower()

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

        # Test with different variables to ensure conditional logic works
        test_vars = {
            "flag": False,  # This should change the NOT test
            "number": 15,  # This might affect some comparisons
            "text": "hello world",
            "items": ["apple", "banana", "cherry"],
            "price": 100,
            "category": "electronics",
        }

        result_modified = compiler.compile(template, variables=test_vars)
        assert result_modified.prompt is not None
        # Most tests should still pass, but some conditions might change

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

    def test_array_length_and_indexing(self, compiler: ITSCompiler, fetcher) -> None:
        """Test array length property and indexing."""
        template = fetcher.fetch_template("09-array-usage.json")

        # Test with arrays of different sizes
        test_vars = {
            "product": {"name": "Test Device", "category": "gadget", "price": 199},
            "features": ["feature1", "feature2", "feature3", "feature4", "feature5"],
            "tags": ["tag1", "tag2"],
            "specifications": {"connectivity": ["WiFi", "Bluetooth"]},
        }

        result = compiler.compile(template, variables=test_vars)
        assert result.prompt is not None
        assert "feature1, feature2, feature3, feature4, feature5" in result.prompt
        assert "tag1, tag2" in result.prompt
        assert "WiFi, Bluetooth" in result.prompt

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

    def test_string_operations_in_conditionals(self, compiler: ITSCompiler, fetcher) -> None:
        """Test string operations in conditional expressions."""
        template = fetcher.fetch_template("10-comprehensive-conditionals.json")

        # Test with different string values
        string_test_vars = {
            "flag": True,
            "number": 5,
            "text": "testing string operations",  # Different text
            "items": ["test", "string", "operations"],
            "price": 100,
            "category": "software",  # Different category
        }

        result = compiler.compile(template, variables=string_test_vars)
        assert result.prompt is not None

        # Most tests should still pass
        assert "[OK]" in result.prompt
        # Should handle the string length test with new text
        assert "String length property works" in result.prompt

    def test_numeric_comparisons_edge_cases(self, compiler: ITSCompiler, fetcher) -> None:
        """Test numeric comparisons with edge cases."""
        template = fetcher.fetch_template("10-comprehensive-conditionals.json")

        # Test with edge case numbers
        edge_case_vars = {
            "flag": True,
            "number": 0,  # Edge case: zero
            "text": "hello world",
            "items": [],  # Empty array
            "price": -50,  # Negative price
            "category": "electronics",
        }

        result = compiler.compile(template, variables=edge_case_vars)
        assert result.prompt is not None
        # Some tests might behave differently with these edge cases
        # But the template should still compile successfully

    def test_error_handling_with_real_templates(self, compiler: ITSCompiler, fetcher) -> None:
        """Test error handling using real templates with missing variables."""
        template = fetcher.fetch_template("04-simple-variables.json")

        # Remove the variables section to cause undefined variable errors
        template_no_vars = template.copy()
        if "variables" in template_no_vars:
            del template_no_vars["variables"]

        # The current implementation raises ITSVariableError during variable processing
        # when undefined variables are encountered
        with pytest.raises((ITSValidationError, ITSVariableError, ITSCompilationError)):
            compiler.compile(template_no_vars)

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
            "04-simple-variables.json",
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

    def test_array_access_patterns(self, compiler: ITSCompiler, fetcher) -> None:
        """Test various array access patterns."""
        template = fetcher.fetch_template("05-complex-variables.json")

        # Test different array structures
        array_test_vars = {
            "product": {"name": "Array Test Device", "category": "test", "price": 100},
            "features": [
                "first feature",
                "second feature with spaces",
                "third-feature-with-dashes",
                "fourth_feature_with_underscores",
            ],
            "reviewCount": 4,
        }

        result = compiler.compile(template, variables=array_test_vars)
        assert result.prompt is not None
        assert "Array Test Device" in result.prompt
        assert "first feature" in result.prompt  # Should access features[0]

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
