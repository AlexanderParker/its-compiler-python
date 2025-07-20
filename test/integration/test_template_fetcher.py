"""
Template fetcher utility for integration tests.

Fetches templates and variables from the its-example-templates GitHub repository
for use in integration testing.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import pytest

from .conftest import TemplateFetcher


@pytest.fixture
def template_fetcher() -> TemplateFetcher:
    """Pytest fixture providing a TemplateFetcher instance."""
    return TemplateFetcher()


def test_fetch_basic_template(template_fetcher: TemplateFetcher):
    """Test fetching a basic template."""
    template = template_fetcher.fetch_template("01-text-only.json")

    assert isinstance(template, dict)
    assert "version" in template
    assert "content" in template
    assert template["version"] == "1.0.0"


def test_fetch_invalid_template(template_fetcher: TemplateFetcher):
    """Test fetching an invalid template."""
    template = template_fetcher.fetch_template("01-invalid-json.json", "templates/invalid")

    # Note: This will likely skip due to invalid JSON, which is expected
    assert isinstance(template, dict)


def test_fetch_variables(template_fetcher: TemplateFetcher):
    """Test fetching variables."""
    variables = template_fetcher.fetch_variables("custom-variables.json")

    assert isinstance(variables, dict)
    # Variables should contain actual variable data
    assert len(variables) > 0


def test_list_templates(template_fetcher: TemplateFetcher):
    """Test listing available templates."""
    templates = template_fetcher.list_templates()

    assert isinstance(templates, list)
    assert len(templates) > 0
    assert "01-text-only.json" in templates


def test_list_invalid_templates(template_fetcher: TemplateFetcher):
    """Test listing invalid templates."""
    templates = template_fetcher.list_templates("templates/invalid")

    assert isinstance(templates, list)
    assert len(templates) > 0
    assert "01-invalid-json.json" in templates


def test_list_security_templates(template_fetcher: TemplateFetcher):
    """Test listing security templates."""
    templates = template_fetcher.list_templates("templates/security")

    assert isinstance(templates, list)
    assert len(templates) > 0
    assert "malicious_injection.json" in templates


def test_list_variables(template_fetcher: TemplateFetcher):
    """Test listing available variables."""
    variables = template_fetcher.list_variables()

    assert isinstance(variables, list)
    assert len(variables) > 0
    assert "custom-variables.json" in variables


def test_nonexistent_template(template_fetcher: TemplateFetcher):
    """Test fetching a non-existent template skips the test."""
    with pytest.raises(pytest.skip.Exception):
        template_fetcher.fetch_template("nonexistent.json")


def test_nonexistent_variables(template_fetcher: TemplateFetcher):
    """Test fetching non-existent variables skips the test."""
    with pytest.raises(pytest.skip.Exception):
        template_fetcher.fetch_variables("nonexistent.json")
