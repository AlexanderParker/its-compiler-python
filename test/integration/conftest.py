"""
Integration test specific fixtures.

Provides fixtures specific to integration testing scenarios.
"""

from typing import Any, Dict, List

import pytest


@pytest.fixture
def sample_templates(template_fetcher: Any) -> Dict[str, Dict[str, Any]]:
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
            # Skip templates that can't be fetched but don't break the fixture
            pass

    return templates


@pytest.fixture
def sample_variables(template_fetcher: Any) -> Dict[str, Dict[str, Any]]:
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
            # Skip variables that can't be fetched but don't break the fixture
            pass

    return variables


@pytest.fixture
def invalid_templates(template_fetcher: Any) -> Dict[str, Dict[str, Any]]:
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
            # Skip templates that can't be fetched but don't break the fixture
            pass

    return templates


@pytest.fixture
def security_templates(template_fetcher: Any) -> Dict[str, Dict[str, Any]]:
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
            # Skip templates that can't be fetched but don't break the fixture
            pass

    return templates


@pytest.fixture
def template_categories(template_fetcher: Any) -> Dict[str, List[str]]:
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
def reset_compiler_state():
    """
    Reset any global compiler state before each test.

    This is an autouse fixture that runs before every test
    to ensure clean state between tests.
    """
    # Clear any global caches or state if needed
    # This could be expanded if the compiler maintains global state
    yield
    # Cleanup after test if needed
