"""Tests for collection functions in variable references."""

from typing import Any, Dict

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.exceptions import ITSVariableError
from its_compiler.security import SecurityConfig


def template(text: str) -> Dict[str, Any]:
    return {
        "version": "1.0.0",
        "variables": {
            "forecast": [
                {"day": "Monday", "high": 24, "wet": False},
                {"day": "Tuesday", "high": 31, "wet": True},
                {"day": "Wednesday", "high": 27, "wet": False},
            ],
            "tags": ["solar", "garden", "lantern"],
            "scores": [2, 4, 9],
        },
        "content": [{"type": "text", "text": text}],
    }


def compile_text(text: str) -> str:
    security = SecurityConfig()
    security.allowlist.interactive_mode = False
    prompt = str(ITSCompiler(security_config=security).compile(template(text)).prompt)
    return prompt[prompt.index("TEMPLATE") :]


class TestCollectionFunctions:
    def test_concat_joins_property_values_and_plain_items(self) -> None:
        assert "Monday, Tuesday, Wednesday" in compile_text("${forecast.concat(day)}")
        assert "solar, garden, lantern" in compile_text("${tags.concat()}")

    def test_aggregations(self) -> None:
        assert "sum=82." in compile_text("sum=${forecast.sum(high)}.")
        assert "sum=15." in compile_text("sum=${scores.sum()}.")
        assert "avg=5." in compile_text("avg=${scores.avg()}.")
        assert "min=24." in compile_text("min=${forecast.min(high)}.")
        assert "max=31." in compile_text("max=${forecast.max(high)}.")

    def test_top_slices_and_chains(self) -> None:
        assert "Monday, Tuesday" in compile_text("${forecast.top(2).concat(day)}")
        assert "solar" in compile_text("${tags.top(1).concat()}")

    def test_booleans_concat_json_style(self) -> None:
        assert "false, true, false" in compile_text("${forecast.concat(wet)}")

    @pytest.mark.parametrize(
        "reference,expected",
        [
            ("${forecast[0].sum(high)}", r"sum\(\) requires an array"),
            ("${forecast.sum(missing)}", r"Property 'missing' not found on every item"),
            ("${forecast.sum(day)}", r"sum\(\) requires numeric values"),
            ("${forecast.top(x)}", r"top\(\) requires a non-negative integer"),
            ("${forecast.concat(day).sum()}", r"sum\(\) requires an array"),
        ],
    )
    def test_invalid_usages_fail(self, reference: str, expected: str) -> None:
        with pytest.raises(ITSVariableError, match=expected):
            compile_text(reference)
