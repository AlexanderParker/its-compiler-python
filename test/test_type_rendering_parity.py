"""
Cross-compiler type-rendering parity.

The golden-prompt comparison checks one whole template byte-for-byte, which is
a strong check but a narrow one: that template contains no ``false``, no
``null`` and no negative numbers. A boolean rendering divergence lived in the
compilers for months and reached the published example outputs without failing
anything.

This fixture is broad instead. Every line is ``name=${expression}``, so a
divergence names itself. The same fixture and the same expectations are
asserted by its-compiler-js and Its.Compiler (.NET), which is what makes it a
parity test rather than a snapshot.

If a value here changes, the three compilers have diverged. Fix the
divergence; do not edit the expectation to match one implementation.
"""

import re
from pathlib import Path
from typing import Dict

import pytest

from its_compiler import ITSCompiler

FIXTURE = Path(__file__).parent / "fixtures" / "type-rendering.json"

# The canonical rendering every implementation must produce.
EXPECTED: Dict[str, str] = {
    # Booleans and null are lowercase words, never a language's own spelling.
    # This module used to emit True, False and None here.
    "bool-true": "true",
    "bool-false": "false",
    "null": "null",
    # Whole values carry no decimal part, however they were written.
    "whole-float": "1",
    "fraction": "0.5",
    "repeating": "0.1",
    "negative": "-42",
    "negative-fraction": "-0.25",
    "zero": "0",
    "big": "1000000000000000",
    # Exponents: lowercase e, no plus, no leading zeros. This module used to
    # emit 1e-07 and .NET emitted 1E-07.
    "small": "1e-7",
    "precise": "1.005",
    # Arrays join with ", " after each element is rendered by the same rules.
    "array-strings": "alpha, beta",
    "array-mixed": "1, true, null, x, 2.5",
    "unicode": "café — naïve ☂",
    "quoted": 'she said "hi"',
    "len-array": "2",
    "len-string": "14",
    # Float arithmetic is IEEE 754 everywhere, so the artefacts must match too.
    "sum-int": "10",
    "avg-int": "2.5",
    "min": "1",
    "max": "4",
    "sum-float": "0.30000000000000004",
    "avg-thirds": "1",
    "avg-money": "0.15000000000000002",
    "concat-scalars": "alpha, beta",
    "concat-mixed": "1, true, null, x, 2.5",
    "concat-prop": "a, b",
    "sum-prop": "4",
    "concat-flags": "true, false",
    "top2": "1, 2",
    "index-neg": "beta",
    "index-0": "alpha",
    "cond-bool": "taken",
    "cond-float-eq-int": "taken",
    "cond-in-and-negative": "taken",
}

LINE = re.compile(r"^([a-z0-9-]+)=(.*)$")


@pytest.fixture(scope="module")
def rendered() -> Dict[str, str]:
    # The fixture extends nothing and has no placeholders, so this needs no
    # network and no schema files.
    result = ITSCompiler().compile_file(str(FIXTURE))
    values: Dict[str, str] = {}
    for line in result.prompt.splitlines():
        match = LINE.match(line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_every_value_is_rendered(rendered: Dict[str, str]) -> None:
    assert sorted(rendered) == sorted(EXPECTED)


@pytest.mark.parametrize("key,expected", sorted(EXPECTED.items()))
def test_value_matches_the_other_compilers(rendered: Dict[str, str], key: str, expected: str) -> None:
    assert rendered[key] == expected
