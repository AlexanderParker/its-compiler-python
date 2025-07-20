"""
Shared pytest fixtures for all tests with improved TemplateFetcher.

Provides common fixtures and utilities for testing the ITS Compiler.
Includes caching and retry logic to handle GitHub rate limiting.
"""

import copy
import json
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.models import ITSConfig
from its_compiler.security import SecurityConfig


class TemplateFetcher:
    """Fetches templates from the its-example-templates GitHub repository with caching and retry logic."""

    BASE_URL = "https://raw.githubusercontent.com/AlexanderParker/its-example-templates/main"

    def __init__(self, version: str = "v1.0"):
        self.version = version
        self.base_path = f"{self.BASE_URL}/{version}"
        # In-memory cache for the session
        self._template_cache: Dict[str, Dict[str, Any]] = {}
        self._variables_cache: Dict[str, Dict[str, Any]] = {}

    def _fetch_with_retry(self, url: str, max_retries: int = 3, base_delay: float = 1.0) -> str:
        """
        Fetch content from URL with exponential backoff retry logic.

        Args:
            url: URL to fetch
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds, will be doubled for each retry

        Returns:
            Response content as string

        Raises:
            Exception: If all retries fail
        """
        last_exception: Optional[Exception] = None

        for attempt in range(max_retries + 1):
            try:
                with urllib.request.urlopen(url, timeout=10) as response:
                    if response.status != 200:
                        raise urllib.error.HTTPError(
                            url, response.status, f"HTTP {response.status}", response.headers, None
                        )
                    content_bytes: bytes = response.read()
                    content: str = content_bytes.decode("utf-8")
                    return content

            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                last_exception = e

                # Don't retry on 404 - the file definitely doesn't exist
                if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                    break

                # For rate limiting (429) or server errors (5xx), retry with backoff
                should_retry = (isinstance(e, urllib.error.HTTPError) and e.code in [429, 502, 503, 504]) or isinstance(
                    e, urllib.error.URLError
                )

                if should_retry and attempt < max_retries:
                    delay = base_delay * (2**attempt)  # Exponential backoff
                    print(f"Request failed (attempt {attempt + 1}/{max_retries + 1}), retrying in {delay}s: {e}")
                    time.sleep(delay)
                    continue

                break

            except Exception as e:
                last_exception = e
                # For unexpected errors, only retry once
                if attempt < min(1, max_retries):
                    delay = base_delay
                    print(f"Unexpected error (attempt {attempt + 1}), retrying in {delay}s: {e}")
                    time.sleep(delay)
                    continue
                break

        # All retries failed
        if last_exception:
            raise last_exception
        else:
            raise Exception("All retry attempts failed")

    def fetch_template(self, template_name: str, category: str = "templates") -> Dict[str, Any]:
        """
        Fetch a template from the repository with caching and retry logic.

        FIXED: Returns a deep copy to prevent shared mutable state issues.

        Args:
            template_name: Name of the template file (e.g., "01-text-only.json")
            category: Category subdirectory ("templates", "templates/invalid", "templates/security")

        Returns:
            Parsed JSON template (deep copy)

        Raises:
            pytest.skip.Exception: If template cannot be fetched after retries
        """
        cache_key = f"{category}/{template_name}"

        # Check cache first
        if cache_key in self._template_cache:
            # CRITICAL FIX: Return a deep copy, not the cached object itself
            return copy.deepcopy(self._template_cache[cache_key])

        url = f"{self.base_path}/{category}/{template_name}"

        try:
            content = self._fetch_with_retry(url)
            parsed_data = json.loads(content)

            # Ensure the parsed data is a dictionary
            if not isinstance(parsed_data, dict):
                pytest.skip(f"Template {template_name} is not a JSON object, got {type(parsed_data).__name__}")

            # Cache the successful result
            self._template_cache[cache_key] = parsed_data

            # CRITICAL FIX: Return a deep copy, not the cached object itself
            return copy.deepcopy(parsed_data)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                pytest.skip(f"Template {template_name} not found in repository (404)")
            elif e.code == 429:
                pytest.skip(f"Rate limited fetching template {template_name}, try again later")
            else:
                pytest.skip(f"HTTP error fetching template {template_name}: {e.code}")

        except urllib.error.URLError as e:
            pytest.skip(f"Network error fetching template {template_name}: {e.reason}")

        except json.JSONDecodeError as e:
            pytest.skip(f"Invalid JSON in template {template_name}: {e}")

        except Exception as e:
            pytest.skip(f"Error fetching template {template_name} after retries: {e}")

    def fetch_variables(self, variables_name: str) -> Dict[str, Any]:
        """
        Fetch a variables file from the repository with caching and retry logic.

        FIXED: Returns a deep copy to prevent shared mutable state issues.

        Args:
            variables_name: Name of the variables file (e.g., "custom-variables.json")

        Returns:
            Parsed JSON variables (deep copy)

        Raises:
            pytest.skip.Exception: If variables cannot be fetched after retries
        """
        # Check cache first
        if variables_name in self._variables_cache:
            # Return a deep copy, not the cached object itself
            return copy.deepcopy(self._variables_cache[variables_name])

        url = f"{self.base_path}/variables/{variables_name}"

        try:
            content = self._fetch_with_retry(url)
            parsed_data = json.loads(content)

            # Ensure the parsed data is a dictionary
            if not isinstance(parsed_data, dict):
                pytest.skip(f"Variables {variables_name} is not a JSON object, got {type(parsed_data).__name__}")

            # Cache the successful result
            self._variables_cache[variables_name] = parsed_data

            # Return a deep copy, not the cached object itself
            return copy.deepcopy(parsed_data)

        except urllib.error.HTTPError as e:
            if e.code == 404:
                pytest.skip(f"Variables {variables_name} not found in repository (404)")
            elif e.code == 429:
                pytest.skip(f"Rate limited fetching variables {variables_name}, try again later")
            else:
                pytest.skip(f"HTTP error fetching variables {variables_name}: {e.code}")

        except urllib.error.URLError as e:
            pytest.skip(f"Network error fetching variables {variables_name}: {e.reason}")

        except json.JSONDecodeError as e:
            pytest.skip(f"Invalid JSON in variables {variables_name}: {e}")

        except Exception as e:
            pytest.skip(f"Error fetching variables {variables_name} after retries: {e}")

    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        self._template_cache.clear()
        self._variables_cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {"templates_cached": len(self._template_cache), "variables_cached": len(self._variables_cache)}

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
                "11-override-types.json",
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
    and to enable caching across all tests in the session.
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


def pytest_configure(config: Any) -> None:
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "network: mark test as requiring network access")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "template_repo: mark test as requiring template repository access")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "security: mark test as security-focused")
    config.addinivalue_line("markers", "unit: mark test as unit test")


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

        # Add integration marker to tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add security marker to tests in security directory
        if "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)

        # Add unit marker to tests in core directory
        if "core" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
