"""Tests for object references substituting a pointer and rendering as reference data."""

from typing import Any, Dict

from its_compiler import ITSCompiler
from its_compiler.core.reference_data import REFERENCE_DATA_INSTRUCTION
from its_compiler.security import SecurityConfig


def template(text: str) -> Dict[str, Any]:
    return {
        "version": "1.0.0",
        "variables": {
            "school": {"name": "Riverbank Secondary", "students": 940},
            "product": {"details": {"weight": "1.2kg", "battery": "12h"}},
        },
        "content": [{"type": "text", "text": text}],
    }


def compile_prompt(text: str, extra_content: Any = None) -> str:
    data = template(text)
    if extra_content:
        data.update(extra_content)
    security = SecurityConfig()
    security.allowlist.interactive_mode = False
    return str(ITSCompiler(security_config=security).compile(data).prompt)


class TestObjectReferenceData:
    def test_pointer_substitution_and_field_table(self) -> None:
        prompt = compile_prompt("Prepared for ${school}.")

        assert "Prepared for the school reference data." in prompt
        assert "[Object with" not in prompt
        assert "### school" in prompt
        assert "| name | Riverbank Secondary |" in prompt
        assert "| students | 940 |" in prompt
        assert REFERENCE_DATA_INSTRUCTION in prompt

    def test_nested_object_path_names_the_section(self) -> None:
        prompt = compile_prompt("Specs: ${product.details}.")

        assert "Specs: the product.details reference data." in prompt
        assert "### product.details" in prompt
        assert "| weight | 1.2kg |" in prompt

    def test_deduplicates_with_explicit_data_source(self) -> None:
        prompt = compile_prompt(
            "About ${school}.",
            {
                "customInstructionTypes": {"summary": {"template": "<<Summarise: ([{<{description}>}]).>>"}},
            },
        )
        data = template("About ${school}.")
        data["customInstructionTypes"] = {"summary": {"template": "<<Summarise: ([{<{description}>}]).>>"}}
        data["content"].append(
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {"description": "Summarise the school reference data", "dataSource": "school"},
            }
        )
        security = SecurityConfig()
        security.allowlist.interactive_mode = False
        prompt = str(ITSCompiler(security_config=security).compile(data).prompt)

        assert prompt.count("### school") == 1

    def test_scalars_and_arrays_unchanged(self) -> None:
        prompt = compile_prompt("Name: ${school.name}, students: ${school.students}.")

        assert "Name: Riverbank Secondary, students: 940." in prompt
        assert "REFERENCE DATA" not in prompt
