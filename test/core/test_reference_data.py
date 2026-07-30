"""Tests for reference data sections."""

from typing import Any, Dict

import pytest

from its_compiler import ITSCompilationError, ITSCompiler
from its_compiler.core.reference_data import REFERENCE_DATA_INSTRUCTION, render_data_source
from its_compiler.security import SecurityConfig


def forecast_template() -> Dict[str, Any]:
    return {
        "version": "1.0.0",
        "customInstructionTypes": {
            "summary": {
                "template": "<<Summarise using this prompt: ([{<{description}>}]).>>",
            }
        },
        "variables": {
            "location": "Adelaide",
            "forecast": [
                {"day": "Monday", "high": 29, "wet": False},
                {"day": "Tuesday", "high": 32, "wet": False},
                {"day": "Sunday", "high": 27, "wet": True},
            ],
        },
        "content": [
            {"type": "text", "text": "# Briefing for ${location}\n\n"},
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {
                    "description": "Summarise the trends in the forecast reference data",
                    "dataSource": "forecast",
                },
            },
        ],
    }


def make_compiler() -> ITSCompiler:
    security = SecurityConfig()
    security.allowlist.interactive_mode = False
    return ITSCompiler(security_config=security)


class TestReferenceDataSections:
    def test_renders_referenced_variables_above_the_template(self) -> None:
        prompt = str(make_compiler().compile(forecast_template()).prompt)

        assert "REFERENCE DATA" in prompt
        assert "### forecast" in prompt
        assert "| day | high | wet |" in prompt
        assert "| Monday | 29 | false |" in prompt
        assert REFERENCE_DATA_INSTRUCTION in prompt
        assert prompt.index("REFERENCE DATA") < prompt.index("TEMPLATE")
        template_section = prompt[prompt.index("TEMPLATE") :]
        assert "| Monday |" not in template_section

    def test_one_section_per_source_when_a_placeholder_synthesises_several_inputs(self) -> None:
        template = forecast_template()
        template["variables"] = {
            "examResults": [{"subject": "Maths", "averageScore": 58}],
            "attendance": [{"term": "Term 1", "attendancePct": 91}],
            "surveyResults": [{"question": "I feel supported", "agreePct": 64}],
        }
        template["content"] = [
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {
                    "description": "Recommend improvements using the examResults, attendance and surveyResults reference data",
                    "dataSource": ["examResults", "attendance", "surveyResults"],
                },
            }
        ]

        prompt = str(make_compiler().compile(template).prompt)

        exams_at = prompt.index("### examResults")
        attendance_at = prompt.index("### attendance")
        survey_at = prompt.index("### surveyResults")
        assert exams_at < attendance_at < survey_at
        assert "| Maths | 58 |" in prompt
        assert "| Term 1 | 91 |" in prompt
        assert "| I feel supported | 64 |" in prompt

    def test_deduplicates_sources_across_placeholders(self) -> None:
        template = forecast_template()
        template["content"].append(
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {
                    "description": "Recommendations from the forecast reference data",
                    "dataSource": ["forecast"],
                },
            }
        )

        prompt = str(make_compiler().compile(template).prompt)

        assert prompt.count("### forecast") == 1

    def test_omitted_when_no_placeholder_names_a_source(self) -> None:
        template = forecast_template()
        del template["content"][1]["config"]["dataSource"]

        prompt = str(make_compiler().compile(template).prompt)

        assert "REFERENCE DATA" not in prompt
        assert REFERENCE_DATA_INSTRUCTION not in prompt

    def test_unknown_source_fails_compilation(self) -> None:
        template = forecast_template()
        template["content"][1]["config"]["dataSource"] = "missing"

        with pytest.raises(ITSCompilationError, match="Unknown data source 'missing'"):
            make_compiler().compile(template)

    def test_sources_in_excluded_branches_are_skipped(self) -> None:
        template = forecast_template()
        placeholder = template["content"][1]
        template["variables"]["includeSummary"] = False
        template["content"] = [
            {"type": "text", "text": "Header\n"},
            {"type": "conditional", "condition": "includeSummary == true", "content": [placeholder]},
        ]

        prompt = str(make_compiler().compile(template).prompt)

        assert "REFERENCE DATA" not in prompt


class TestDataLimits:
    def test_caps_items_at_the_placeholder_data_limit(self) -> None:
        template = forecast_template()
        template["content"][1]["config"]["dataLimit"] = 2

        prompt = str(make_compiler().compile(template).prompt)

        assert "| Monday | 29 | false |" in prompt
        assert "| Tuesday | 32 | false |" in prompt
        assert "| Sunday |" not in prompt
        assert "Showing the first 2 of 3 items." in prompt

    def test_maximum_limit_wins_across_placeholders(self) -> None:
        template = forecast_template()
        template["content"][1]["config"]["dataLimit"] = 1
        template["content"].append(
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {
                    "description": "More from the forecast reference data",
                    "dataSource": "forecast",
                    "dataLimit": 2,
                },
            }
        )

        prompt = str(make_compiler().compile(template).prompt)

        assert "Showing the first 2 of 3 items." in prompt
        assert prompt.count("### forecast") == 1

    def test_unlimited_reference_beats_any_limit(self) -> None:
        template = forecast_template()
        template["content"][1]["config"]["dataLimit"] = 1
        template["content"].append(
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {"description": "Everything from the forecast reference data", "dataSource": "forecast"},
            }
        )

        prompt = str(make_compiler().compile(template).prompt)

        assert "| Sunday | 27 | true |" in prompt
        assert "Showing the first" not in prompt

    def test_non_truncating_limit_adds_no_note(self) -> None:
        template = forecast_template()
        template["content"][1]["config"]["dataLimit"] = 50

        prompt = str(make_compiler().compile(template).prompt)

        assert "| Sunday | 27 | true |" in prompt
        assert "Showing the first" not in prompt


class TestRenderDataSource:
    def test_primitive_array_renders_as_list(self) -> None:
        assert render_data_source(["a", "b"]) == "- a\n- b"

    def test_plain_object_renders_as_field_table(self) -> None:
        assert render_data_source({"name": "x", "count": 2}) == (
            "| Field | Value |\n| --- | --- |\n| name | x |\n| count | 2 |"
        )

    def test_nested_values_render_as_compact_json_with_escaped_pipes(self) -> None:
        assert render_data_source([{"a": {"b": 1}, "note": "x|y"}]) == (
            '| a | note |\n| --- | --- |\n| {"b":1} | x\\|y |'
        )
