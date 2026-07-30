"""Tests for configurable variable payload limits."""

from typing import Any, Dict

import pytest

from its_compiler import ITSCompiler
from its_compiler.core.exceptions import ITSValidationError, ITSVariableError
from its_compiler.security import SecurityConfig


def dataset_template(rows: int) -> Dict[str, Any]:
    return {
        "version": "1.0.0",
        "customInstructionTypes": {"summary": {"template": "<<Summarise using this prompt: ([{<{description}>}]).>>"}},
        "variables": {"rows": [{"n": i} for i in range(rows)]},
        "content": [
            {
                "type": "placeholder",
                "instructionType": "summary",
                "config": {"description": "Summarise the rows reference data", "dataSource": "rows", "dataLimit": 5},
            }
        ],
    }


def compiler_with(**processing_overrides: int) -> ITSCompiler:
    security = SecurityConfig()
    security.allowlist.interactive_mode = False
    for name, value in processing_overrides.items():
        setattr(security.processing, name, value)
    return ITSCompiler(security_config=security)


class TestConfigurableLimits:
    def test_default_variable_count_accepts_reference_datasets(self) -> None:
        # 500 rows was rejected by the old hardcoded conflated cap of 100
        result = compiler_with().compile(dataset_template(500))
        assert "Showing the first 5 of 500 items." in str(result.prompt)

    def test_variable_count_is_configurable(self) -> None:
        with pytest.raises(ITSVariableError, match="Too many variables"):
            compiler_with(max_variable_count=50).compile(dataset_template(60))

    def test_array_items_limit_is_configurable(self) -> None:
        # Surfaces via the input validator or the variable processor depending
        # on which security layer is enabled; both honour the configured cap
        with pytest.raises((ITSValidationError, ITSVariableError), match="Array too large"):
            compiler_with(max_variable_array_items=10).compile(dataset_template(11))

    def test_environment_overrides_map_to_processing_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ITS_MAX_VARIABLE_COUNT", "123")
        monkeypatch.setenv("ITS_MAX_VARIABLE_ARRAY_ITEMS", "45")
        monkeypatch.setenv("ITS_MAX_TEXT_LENGTH", "67")

        config = SecurityConfig.from_environment()

        assert config.processing.max_variable_count == 123
        assert config.processing.max_variable_array_items == 45
        assert config.processing.max_text_length == 67
