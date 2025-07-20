"""
Shared pytest fixtures for integration tests.

Provides common fixtures and utilities for integration testing
of the ITS Compiler with real templates and data.
"""

import json
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Generator, List
from urllib.parse import quote

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.models import ITSConfig
from its_compiler.security import SecurityConfig


class TemplateFetcher:
    """Fetches templates from the its-example-templates GitHub repository."""

    BASE_URL = "https://raw.githubusercontent.com/AlexanderParker/its-example-templates/main"

    def __init__(self, version: str = "v1.0"):
        self.version = version
        self.base_path = f"{self.BASE_URL}/{version}"

    def fetch_template(self, template_name: str, category: str = "templates") -> Dict[str, Any]:
        """
        Fetch a template from the repository.

        Args:
            template_name: Name of the template file (e.g., "01-text-only.json")
            category: Category subdirectory ("templates", "templates/invalid", "templates/security")

        Returns:
            Parsed JSON template
        """
        url = f"{self.base_path}/{category}/{template_name}"

        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                content = response.read().decode("utf-8")
                return json.loads(content)
        except urllib.error.URLError as e:
            pytest.skip(f"Could not fetch template {template_name}: {e}")
        except json.JSONDecodeError as e:
            pytest.skip(f"Invalid JSON in template {template_name}: {e}")
        except Exception as e:
            pytest.skip(f"Error fetching template {template_name}: {e}")

    def fetch_variables(self, variables_name: str) -> Dict[str, Any]:
        """
        Fetch a variables file from the repository.

        Args:
            variables_name: Name of the variables file (e.g., "custom-variables.json")

        Returns:
            Parsed JSON variables
        """
        url = f"{self.base_path}/variables/{variables_name}"

        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                content = response.read().decode("utf-8")
                return json.loads(content)
        except urllib.error.URLError as e:
            pytest.skip(f"Could not fetch variables {variables_name}: {e}")
        except json.JSONDecodeError as e:
            pytest.skip(f"Invalid JSON in variables {variables_name}: {e}")
        except Exception as e:
            pytest.skip(f"Error fetching variables {variables_name}: {e}")

    def list_templates(self, category: str = "templates") -> List[str]:
        """
        Get a list of available templates for a category.

        Note: This returns a hardcoded list based on the known templates
        in the repository since GitHub doesn't provide directory listing.
        """
        if category == "templates":
            return [
                "01-text-only.json",
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
        elif category == "templates/invalid":
            return [
                "01-invalid-json.json",
                "02-missing-required-fields.json",
                "03-undefined-variables.json",
                "04-unknown-instruction-type.json",
                "05-invalid-conditional.json",
                "06-missing-placeholder-config.json",
                "07-empty-content.json",
            ]
        elif category == "templates/security":
            return [
                "malicious_expressions.json",
                "malicious_injection.json",
                "malicious_schema.json",
                "malicious_variables.json",
            ]
        else:
            return []

    def list_variables(self) -> List[str]:
        """Get a list of available variable files."""
        return [
            "custom-variables.json",
            "conditional-test-variables.json",
            "conditional-minimal-variables.json",
            "complex-conditional-variables.json",
        ]


@pytest.fixture(scope="session")
def template_fetcher() -> TemplateFetcher:
    """
    Provide a TemplateFetcher instance for the entire test session.

    This is session-scoped to avoid creating multiple instances
    and to allow for potential caching of fetched templates.
    """
    return TemplateFetcher()


@pytest.fixture
def temp_directory() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test files.

    Automatically cleaned up after the test completes.
    """
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def basic_compiler() -> ITSCompiler:
    """
    Create a basic ITSCompiler instance with default configuration.

    Uses standard security settings suitable for testing.
    """
    return ITSCompiler()


@pytest.fixture
def development_compiler() -> ITSCompiler:
    """
    Create an ITSCompiler with development-friendly security settings.

    Allows HTTP, localhost access, and disables interactive prompts.
    Suitable for integration testing with external resources.
    """
    config = SecurityConfig.for_development()
    config.allowlist.interactive_mode = False
    config.allowlist.auto_approve_in_ci = True
    config.allowlist.require_confirmation = False
    return ITSCompiler(security_config=config)


@pytest.fixture
def production_compiler() -> ITSCompiler:
    """
    Create an ITSCompiler with production security settings.

    Uses strict security controls for testing security behavior.
    """
    config = SecurityConfig.from_environment()
    config.allowlist.interactive_mode = False
    return ITSCompiler(security_config=config)


@pytest.fixture
def no_cache_compiler() -> ITSCompiler:
    """
    Create an ITSCompiler with caching disabled.

    Useful for testing schema loading behavior without cache interference.
    """
    its_config = ITSConfig()
    its_config.cache_enabled = False

    security_config = SecurityConfig.for_development()
    security_config.allowlist.interactive_mode = False
    security_config.allowlist.auto_approve_in_ci = True

    return ITSCompiler(its_config, security_config)


@pytest.fixture
def sample_templates(template_fetcher: TemplateFetcher) -> Dict[str, Dict[str, Any]]:
    """
    Pre-fetch a selection of commonly used templates.

    Returns a dictionary mapping template names to template content.
    Useful for tests that need multiple templates.
    """
    template_names = [
        "01-text-only.json",
        "04-simple-variables.json",
        "06-simple-conditionals.json",
        "08-custom-types.json",
    ]

    templates = {}
    for name in template_names:
        try:
            templates[name] = template_fetcher.fetch_template(name)
        except Exception:
            # Skip templates that can't be fetched
            pass

    return templates


@pytest.fixture
def sample_variables(template_fetcher: TemplateFetcher) -> Dict[str, Dict[str, Any]]:
    """
    Pre-fetch commonly used variable files.

    Returns a dictionary mapping variable file names to variable content.
    """
    variable_names = ["custom-variables.json", "conditional-test-variables.json", "conditional-minimal-variables.json"]

    variables = {}
    for name in variable_names:
        try:
            variables[name] = template_fetcher.fetch_variables(name)
        except Exception:
            # Skip variables that can't be fetched
            pass

    return variables


@pytest.fixture
def invalid_templates(template_fetcher: TemplateFetcher) -> Dict[str, Dict[str, Any]]:
    """
    Pre-fetch invalid templates for error testing.

    Returns a dictionary mapping invalid template names to template content.
    """
    invalid_names = [
        "02-missing-required-fields.json",
        "03-undefined-variables.json",
        "04-unknown-instruction-type.json",
        "07-empty-content.json",
    ]

    templates = {}
    for name in invalid_names:
        try:
            templates[name] = template_fetcher.fetch_template(name, category="templates/invalid")
        except Exception:
            # Skip templates that can't be fetched
            pass

    return templates


@pytest.fixture
def security_templates(template_fetcher: TemplateFetcher) -> Dict[str, Dict[str, Any]]:
    """
    Pre-fetch security test templates.

    Returns a dictionary mapping security template names to template content.
    These templates should be blocked by security controls.
    """
    security_names = ["malicious_expressions.json", "malicious_injection.json", "malicious_variables.json"]

    templates = {}
    for name in security_names:
        try:
            templates[name] = template_fetcher.fetch_template(name, category="templates/security")
        except Exception:
            # Skip templates that can't be fetched
            pass

    return templates


@pytest.fixture
def template_categories(template_fetcher: TemplateFetcher) -> Dict[str, List[str]]:
    """
    Get organized lists of templates by category.

    Returns a dictionary with template categories and their template lists.
    """
    return {
        "valid": template_fetcher.list_templates("templates"),
        "invalid": template_fetcher.list_templates("templates/invalid"),
        "security": template_fetcher.list_templates("templates/security"),
        "variables": template_fetcher.list_variables(),
    }


@pytest.fixture
def mock_schema_response() -> Dict[str, Any]:
    """
    Provide a mock schema response for testing schema loading.

    Returns a valid ITS schema structure that can be used
    when mocking HTTP responses.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Mock ITS Schema",
        "version": "1.0.0",
        "instructionTypes": {
            "mock_paragraph": {
                "template": "Write a paragraph: ([{<{description}>}]). Tone: {tone}",
                "description": "Mock paragraph instruction type",
                "configSchema": {
                    "type": "object",
                    "properties": {"tone": {"type": "string", "enum": ["casual", "formal", "technical"]}},
                },
            },
            "mock_list": {
                "template": "Create a list: ([{<{description}>}]). Format: {format}",
                "description": "Mock list instruction type",
                "configSchema": {
                    "type": "object",
                    "properties": {"format": {"type": "string", "enum": ["bullet_points", "numbered"]}},
                },
            },
        },
    }


@pytest.fixture
def compilation_test_helper() -> Any:
    """
    Provide helper functions for common compilation test operations.

    Returns an object with utility methods for testing compilation results.
    """

    class CompilationTestHelper:
        @staticmethod
        def assert_valid_prompt(prompt: str) -> None:
            """Assert that a prompt has the expected ITS structure."""
            assert prompt is not None
            assert len(prompt.strip()) > 0
            assert "INTRODUCTION" in prompt
            assert "INSTRUCTIONS" in prompt
            assert "TEMPLATE" in prompt

        @staticmethod
        def assert_contains_instruction(prompt: str, description: str) -> None:
            """Assert that a prompt contains an instruction with the given description."""
            assert description in prompt
            assert "([{<" in prompt  # User content wrapper
            assert ">}])" in prompt

        @staticmethod
        def assert_variable_substituted(prompt: str, variable: str, value: str) -> None:
            """Assert that a variable was properly substituted."""
            assert value in prompt
            assert f"${{{variable}}}" not in prompt  # Should not have unresolved variables

        @staticmethod
        def count_placeholders(prompt: str) -> int:
            """Count the number of placeholders in a prompt."""
            return prompt.count("<<")

        @staticmethod
        def extract_user_prompts(prompt: str) -> List[str]:
            """Extract all user prompt content from a compiled prompt."""
            import re

            pattern = r"\(\[\{<(.+?)>\}\]\)"
            return re.findall(pattern, prompt)

    return CompilationTestHelper()


@pytest.fixture(autouse=True)
def reset_compiler_state() -> Generator[None, None, None]:
    """
    Reset any global compiler state before each test.

    This is an autouse fixture that runs before every test
    to ensure clean state between tests.
    """
    # Clear any global caches or state if needed
    # This could be expanded if the compiler maintains global state
    yield
    # Cleanup after test if needed


def pytest_configure(config: Any) -> None:
    """Configure pytest with custom markers for integration tests."""
    config.addinivalue_line("markers", "network: mark test as requiring network access")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "template_repo: mark test as requiring template repository access")


def pytest_collection_modifyitems(config: Any, items: List[Any]) -> None:
    """Modify test collection to add markers based on test content."""
    for item in items:
        # Add network marker to tests that use template_fetcher
        if "template_fetcher" in item.fixturenames:
            item.add_marker(pytest.mark.network)
            item.add_marker(pytest.mark.template_repo)

        # Add slow marker to tests that compile many templates
        if any(keyword in item.name.lower() for keyword in ["all_templates", "comprehensive", "batch"]):
            item.add_marker(pytest.mark.slow)
