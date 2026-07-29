"""
Integration tests for the published structured-output type libraries.

Local fixture copies of the JSON, HTML and YAML libraries are loaded through
relative extends with local schemas enabled, so no network is involved.
"""

from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from its_compiler import ITSCompilationError, ITSCompiler
from its_compiler.security import SecurityConfig

FIXTURES = Path(__file__).parent.parent / "fixtures" / "type_libraries"

RAW_OUTPUT_CLAUSES = {
    "json": "Output raw, valid JSON only - no markdown code fences, no surrounding commentary, and no explanation.",
    "html": "Output raw, valid HTML only - no markdown code fences, no surrounding commentary, and no explanation.",
    "yaml": "Output raw, valid YAML only - no markdown code fences, no surrounding commentary, and no explanation.",
}

PUBLISHED_BASE = "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0"


def local_compiler() -> ITSCompiler:
    security = SecurityConfig()
    security.allow_local_schemas()
    security.allowlist.interactive_mode = False
    return ITSCompiler(security_config=security)


def compile_fixture(name: str, variables: Optional[Dict[str, Any]] = None) -> str:
    result = local_compiler().compile_file(str(FIXTURES / name), variables)
    return str(result.prompt)


class TestTypeLibrarySecurity:
    """The published library URLs are trusted; local files are opt-in."""

    def test_published_urls_pass_default_validation(self) -> None:
        from its_compiler.security import AllowlistManager, URLValidator

        config = SecurityConfig()
        validator = URLValidator(config)
        allowlist = AllowlistManager(config)

        for file_name in ["its-json-types-v1.json", "its-html-types-v1.json", "its-yaml-types-v1.json"]:
            url = f"{PUBLISHED_BASE}/{file_name}"
            validator.validate_url(url)
            assert allowlist._is_builtin_trusted(url)

    def test_local_file_schemas_blocked_by_default(self) -> None:
        security = SecurityConfig()
        security.allowlist.interactive_mode = False
        compiler = ITSCompiler(security_config=security)

        with pytest.raises(ITSCompilationError, match="blocked by security policy"):
            compiler.compile_file(str(FIXTURES / "json-types-template.json"))

    def test_relative_extends_accepted_by_input_validation(self) -> None:
        # Compiles cleanly with local schemas enabled and input validation on
        prompt = compile_fixture("json-types-template.json")
        assert "<<" in prompt


class TestJsonTypeLibrary:
    def test_raw_output_clause_and_escaping(self) -> None:
        prompt = compile_fixture("json-types-template.json")

        assert RAW_OUTPUT_CLAUSES["json"] in prompt
        assert "([{<A orders API response object>}])" in prompt
        assert "two_spaces indentation" in prompt

    def test_conditionals_follow_variables(self) -> None:
        with_error = compile_fixture("json-types-template.json")
        assert "not_found error object" in with_error

        without_error = compile_fixture("json-types-template.json", {"includeErrorExample": False})
        assert "not_found error object" not in without_error

    def test_defaults_render_when_config_omitted(self) -> None:
        # The json_schema placeholder sets only a description
        prompt = compile_fixture("json-types-template.json")

        assert "targets the 2020-12 draft" in prompt
        assert "{draft}" not in prompt
        assert "{indent}" not in prompt


class TestHtmlTypeLibrary:
    def test_raw_output_clause_and_fragment_wording(self) -> None:
        prompt = compile_fixture("html-types-template.json")

        assert RAW_OUTPUT_CLAUSES["html"] in prompt
        assert "([{<A summary paragraph for the Solar Garden Lantern>}])" in prompt
        assert "Do not include a doctype or html, head or body tags." in prompt

    def test_defaults_and_boolean_rendering(self) -> None:
        prompt = compile_fixture("html-types-template.json")

        # html_list relies on the listType default
        assert "unordered list element" in prompt
        assert "{listType}" not in prompt
        # Booleans render JSON-style, not Python-style
        assert "Include class attributes on elements: true." in prompt
        assert "True" not in prompt


class TestYamlTypeLibrary:
    def test_raw_output_clause_and_defaults(self) -> None:
        prompt = compile_fixture("yaml-types-template.json")

        assert RAW_OUTPUT_CLAUSES["yaml"] in prompt
        assert "([{<A CI pipeline for example-storefront>}])" in prompt
        # yaml_block relies on the indentSize default
        assert "2-space indentation" in prompt
        assert "{indentSize}" not in prompt
        assert "Use anchors and aliases for repeated values: false." in prompt
