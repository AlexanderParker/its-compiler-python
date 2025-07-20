"""
Integration tests for successful template compilation.
Tests the complete compilation pipeline with valid templates from the example repository.
"""

from typing import Any, Dict

import pytest

from its_compiler import ITSCompiler, ITSConfig
from its_compiler.security import SecurityConfig


class TestCompilationIntegration:
    """Test successful compilation of valid templates."""

    @pytest.fixture
    def compiler(self) -> ITSCompiler:
        """Create compiler instance with development security config."""
        security_config = SecurityConfig.for_development()
        security_config.allowlist.interactive_mode = False
        security_config.allowlist.auto_approve_in_ci = True
        security_config.allowlist.require_confirmation = False
        return ITSCompiler(security_config=security_config)

    @pytest.fixture
    def secure_compiler(self) -> ITSCompiler:
        """Create compiler with production security config."""
        security_config = SecurityConfig.from_environment()
        security_config.allowlist.interactive_mode = False
        return ITSCompiler(security_config=security_config)

    @pytest.fixture
    def text_only_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch text-only template."""
        return template_fetcher.fetch_template("01-text-only.json")

    @pytest.fixture
    def single_placeholder_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch single placeholder template."""
        return template_fetcher.fetch_template("02-single-placeholder.json")

    @pytest.fixture
    def multiple_placeholders_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch multiple placeholders template."""
        return template_fetcher.fetch_template("03-multiple-placeholders.json")

    @pytest.fixture
    def simple_variables_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch simple variables template."""
        return template_fetcher.fetch_template("04-simple-variables.json")

    @pytest.fixture
    def complex_variables_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch complex variables template."""
        return template_fetcher.fetch_template("05-complex-variables.json")

    @pytest.fixture
    def custom_types_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch custom types template."""
        return template_fetcher.fetch_template("08-custom-types.json")

    @pytest.fixture
    def array_usage_template(self, template_fetcher) -> Dict[str, Any]:
        """Fetch array usage template."""
        return template_fetcher.fetch_template("09-array-usage.json")

    @pytest.fixture
    def template_files(self, temp_directory, template_fetcher) -> Dict[str, str]:
        """Create temporary template files."""
        template = template_fetcher.fetch_template("01-text-only.json")
        file_path = temp_directory / "01-text-only.json"
        with open(file_path, "w") as f:
            import json

            json.dump(template, f)
        return {"01-text-only.json": str(file_path)}

    def test_multiple_placeholders_template(
        self, compiler: ITSCompiler, multiple_placeholders_template: Dict[str, Any]
    ) -> None:
        """Test compilation of template with multiple placeholders."""
        result = compiler.compile(multiple_placeholders_template)

        assert result.prompt is not None
        assert "catchy title about healthy eating" in result.prompt
        assert "benefits of healthy eating" in result.prompt
        assert "5 superfoods and their benefits" in result.prompt
        assert result.prompt.count("<<") >= 3
        assert result.prompt.count(">>") >= 3

    def test_simple_variables_template(self, compiler: ITSCompiler, simple_variables_template: Dict[str, Any]) -> None:
        """Test compilation with simple variable substitution."""
        result = compiler.compile(simple_variables_template)

        assert result.prompt is not None
        assert "sustainable technology" in result.prompt
        assert "4 examples of sustainable technology" in result.prompt
        assert "${" not in result.prompt  # Variables should be resolved
        assert result.variables["topic"] == "sustainable technology"
        assert result.variables["itemCount"] == 4

    def test_complex_variables_template(
        self, compiler: ITSCompiler, complex_variables_template: Dict[str, Any]
    ) -> None:
        """Test compilation with complex object and array variables."""
        result = compiler.compile(complex_variables_template)

        assert result.prompt is not None
        assert "EcoPhone Pro Review" in result.prompt
        assert "smartphone that costs $899" in result.prompt
        assert "solar charging works" in result.prompt
        assert result.variables["product"]["name"] == "EcoPhone Pro"
        assert result.variables["product"]["price"] == 899
        assert "solar charging" in result.variables["features"]

    def test_custom_types_template(self, compiler: ITSCompiler, custom_types_template: Dict[str, Any]) -> None:
        """Test compilation with custom instruction types."""
        result = compiler.compile(custom_types_template)

        assert result.prompt is not None
        assert "Chocolate Chip Cookies Recipe" in result.prompt
        assert "Step 1:" in result.prompt
        assert "Duration: 5 minutes" in result.prompt
        assert "Step 2:" in result.prompt
        assert "Duration: 3 minutes" in result.prompt
        assert "List required kitchen tools" in result.prompt

    def test_array_usage_template(self, compiler: ITSCompiler, array_usage_template: Dict[str, Any]) -> None:
        """Test compilation with comprehensive array usage."""
        result = compiler.compile(array_usage_template)

        assert result.prompt is not None
        assert "SmartHome Hub Product Description" in result.prompt
        assert "voice control, home automation, energy monitoring, security integration" in result.prompt
        assert "WiFi, Bluetooth, Zigbee" in result.prompt
        assert "smart, connected, efficient" in result.prompt

    def test_template_with_variables_override(
        self, compiler: ITSCompiler, simple_variables_template: Dict[str, Any]
    ) -> None:
        """Test that provided variables override template variables."""
        custom_variables = {"topic": "renewable energy systems", "itemCount": 6}

        result = compiler.compile(simple_variables_template, variables=custom_variables)

        assert result.prompt is not None
        assert "renewable energy systems" in result.prompt
        assert "6 examples of renewable energy systems" in result.prompt
        assert result.variables["topic"] == "renewable energy systems"
        assert result.variables["itemCount"] == 6

    def test_template_compilation_result_structure(
        self, compiler: ITSCompiler, text_only_template: Dict[str, Any]
    ) -> None:
        """Test that compilation result has expected structure."""
        result = compiler.compile(text_only_template)

        assert hasattr(result, "prompt")
        assert hasattr(result, "template")
        assert hasattr(result, "variables")
        assert hasattr(result, "overrides")
        assert hasattr(result, "warnings")

        assert result.template == text_only_template
        assert isinstance(result.variables, dict)
        assert isinstance(result.overrides, list)
        assert isinstance(result.warnings, list)

    def test_template_with_extends_field(
        self, compiler: ITSCompiler, single_placeholder_template: Dict[str, Any]
    ) -> None:
        """Test template that extends external schemas."""
        # Mock the allowlist to allow the standard schema
        if compiler.schema_loader.allowlist_manager:
            schema_url = "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-standard-types-v1.json"
            compiler.schema_loader.allowlist_manager.add_trusted_url(schema_url)

        result = compiler.compile(single_placeholder_template)

        assert result.prompt is not None
        assert "list 5 different citrus fruits" in result.prompt

    def test_file_compilation(self, compiler: ITSCompiler, template_files: Dict[str, str]) -> None:
        """Test compilation from file paths."""
        # Test with a simple template file
        file_path = template_files["01-text-only.json"]
        result = compiler.compile_file(file_path)

        assert result.prompt is not None
        assert "This is a simple template with no placeholders" in result.prompt

    def test_compilation_with_security_features_enabled(
        self, secure_compiler: ITSCompiler, simple_variables_template: Dict[str, Any]
    ) -> None:
        """Test compilation with all security features enabled."""
        result = secure_compiler.compile(simple_variables_template)

        assert result.prompt is not None
        assert "sustainable technology" in result.prompt

        # Check security status
        security_status = secure_compiler.get_security_status()
        assert security_status["security_enabled"] is True
        assert "features" in security_status
        assert "components" in security_status

    def test_large_template_compilation(self, compiler: ITSCompiler) -> None:
        """Test compilation of larger, more complex templates."""
        # Create a template with many elements
        large_template = {
            "version": "1.0.0",
            "customInstructionTypes": {"custom_text": {"template": "Generate: ([{<{description}>}]). Style: {style}."}},
            "variables": {"sections": ["intro", "main", "conclusion"], "count": 10},
            "content": [],
        }

        # Add many content elements
        for i in range(20):
            large_template["content"].extend(
                [
                    {"type": "text", "text": f"# Section {i}\n\n"},
                    {
                        "type": "placeholder",
                        "instructionType": "custom_text",
                        "config": {"description": f"Content for section {i}", "style": "professional"},
                    },
                ]
            )

        result = compiler.compile(large_template)

        assert result.prompt is not None
        assert len(result.prompt) > 1000  # Should be substantial
        assert result.prompt.count("Section") >= 20

    def test_compiler_configuration_variants(self) -> None:
        """Test different compiler initialization and configuration scenarios."""
        # Default initialization
        compiler1 = ITSCompiler()
        assert compiler1.config is not None
        assert compiler1.security_config is not None

        # With custom config
        config = ITSConfig(cache_enabled=False, strict_mode=False)
        compiler2 = ITSCompiler(config=config)
        assert compiler2.config.cache_enabled is False
        assert compiler2.config.strict_mode is False

        # With custom security config
        security_config = SecurityConfig.for_development()
        compiler3 = ITSCompiler(security_config=security_config)
        assert compiler3.security_config.is_development()

        # With both configs
        compiler4 = ITSCompiler(config, security_config)
        assert compiler4.config.cache_enabled is False
        assert compiler4.security_config.is_development()

    def test_compiler_with_custom_config(
        self, secure_compiler: ITSCompiler, text_only_template: Dict[str, Any]
    ) -> None:
        """Test compilation with custom compiler configuration."""
        result = secure_compiler.compile(text_only_template)

        assert result.prompt is not None
        assert len(result.prompt) > 0
