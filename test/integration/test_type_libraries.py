"""
Integration tests for the published structured-output type libraries.

The libraries fill value positions inside structure authored verbatim in the
template text. Local fixture copies of the JSON, HTML, YAML and Markdown
libraries are loaded through relative extends with local schemas enabled, so
no network is involved.
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
    "markdown": (
        "Output raw, valid Markdown only - no surrounding commentary and no explanation, "
        "and do not wrap the output in code fences."
    ),
    "markdown_code": "Output raw code only - no code fences, no surrounding commentary and no explanation.",
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

        for file_name in [
            "its-json-types-v1.json",
            "its-html-types-v1.json",
            "its-yaml-types-v1.json",
            "its-markdown-types-v1.json",
        ]:
            url = f"{PUBLISHED_BASE}/{file_name}"
            validator.validate_url(url)
            assert allowlist._is_builtin_trusted(url)

    def test_local_file_schemas_blocked_by_default(self) -> None:
        security = SecurityConfig()
        security.allowlist.interactive_mode = False
        compiler = ITSCompiler(security_config=security)

        # The file schema is refused, so its types never load and the
        # placeholder cannot resolve
        with pytest.raises(ITSCompilationError, match="Unknown instruction type"):
            compiler.compile_file(str(FIXTURES / "json-types-template.json"))

    def test_relative_extends_accepted_by_input_validation(self) -> None:
        # Compiles cleanly with local schemas enabled and input validation on
        prompt = compile_fixture("json-types-template.json")
        assert "<<" in prompt


class TestJsonTypeLibrary:
    def test_authored_structure_verbatim_with_fills(self) -> None:
        prompt = compile_fixture("json-types-template.json")

        # The document scaffolding comes from the template text, not the model
        assert '{\n  "data": [\n' in prompt
        assert '"page": 1,' in prompt
        assert '"code": "not_found",' in prompt
        # Fills carry the raw-output clause and escaped descriptions
        assert RAW_OUTPUT_CLAUSES["json"] in prompt
        assert "([{<three orders objects with id and status fields>}])" in prompt
        assert "without the enclosing square brackets" in prompt
        assert "of kind integer" in prompt

    def test_conditionals_follow_variables(self) -> None:
        with_error = compile_fixture("json-types-template.json")
        assert "not_found" in with_error

        without_error = compile_fixture("json-types-template.json", {"includeErrorExample": False})
        assert "not_found" not in without_error

    def test_defaults_render_when_config_omitted(self) -> None:
        # The json_value placeholder sets only a description
        prompt = compile_fixture("json-types-template.json")

        assert "of type any" in prompt
        assert "{valueType}" not in prompt
        assert "{numberType}" not in prompt


class TestHtmlTypeLibrary:
    def test_authored_markup_verbatim_with_fills(self) -> None:
        prompt = compile_fixture("html-types-template.json")

        assert '<section class="product-card">' in prompt
        assert "<thead><tr><th>Specification</th><th>Value</th></tr></thead>" in prompt
        assert RAW_OUTPUT_CLAUSES["html"] in prompt
        assert "([{<a summary of the Solar Garden Lantern>}])" in prompt
        assert "without the enclosing list tags" in prompt
        assert "without the enclosing table, thead or tbody tags" in prompt
        # Booleans render JSON-style, not Python-style
        assert "Inline markup such as strong, em and a is allowed: true." in prompt
        # html_fragment placeholder relies on the includeClasses default
        assert "Include class attributes on elements: true." in prompt
        assert "{includeClasses}" not in prompt
        assert "True" not in prompt

    def test_complete_element_generator_html_list(self) -> None:
        template = {
            "$schema": "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json",
            "version": "1.0.0",
            "extends": ["./its-html-types-v1.json"],
            "content": [
                {"type": "text", "text": "<nav>\n"},
                {
                    "type": "placeholder",
                    "instructionType": "html_list",
                    "config": {
                        "description": "links to the main documentation sections",
                        "listType": "unordered",
                        "itemCount": 4,
                    },
                },
                {"type": "text", "text": "\n</nav>"},
            ],
        }

        result = local_compiler().compile(template, base_url=FIXTURES.resolve().as_uri() + "/")
        prompt = str(result.prompt)

        assert "Produce a complete unordered list element including its items" in prompt
        assert RAW_OUTPUT_CLAUSES["html"] in prompt
        assert "([{<links to the main documentation sections>}])" in prompt


class TestYamlTypeLibrary:
    def test_authored_structure_verbatim_with_fills(self) -> None:
        prompt = compile_fixture("yaml-types-template.json")

        assert "build:\n  script:\n" in prompt
        assert RAW_OUTPUT_CLAUSES["yaml"] in prompt
        assert "([{<commands that build example-storefront>}])" in prompt
        assert "beginning with 4 spaces followed by a hyphen" in prompt
        # yaml_block placeholder relies on the indentSpaces default
        assert "indented by 2 spaces" in prompt
        assert "{indentSpaces}" not in prompt


class TestMarkdownTypeLibrary:
    def test_authored_scaffolding_verbatim_with_fills(self) -> None:
        prompt = compile_fixture("markdown-types-template.json")

        # The document scaffolding comes from the template text, not the model
        assert "# example-storefront release notes" in prompt
        assert "## Features\n" in prompt
        assert "| Package | Version |\n| --- | --- |\n" in prompt
        assert "## Installation\n\n```bash\n" in prompt
        assert "\n```" in prompt
        # Fills carry the raw-output clauses and escaped descriptions
        assert RAW_OUTPUT_CLAUSES["markdown"] in prompt
        assert RAW_OUTPUT_CLAUSES["markdown_code"] in prompt
        assert "([{<three headline features of example-storefront>}])" in prompt
        assert "without producing a header or separator row" in prompt

    def test_conditionals_follow_variables(self) -> None:
        with_install = compile_fixture("markdown-types-template.json")
        assert "## Installation" in with_install

        without_install = compile_fixture("markdown-types-template.json", {"includeInstall": False})
        assert "## Installation" not in without_install
        assert "```bash" not in without_install

    def test_defaults_render_when_config_omitted(self) -> None:
        # The markdown_list_items placeholder omits listType; the default is bullet
        prompt = compile_fixture("markdown-types-template.json")

        assert "using bullet markers" in prompt
        assert "{listType}" not in prompt
