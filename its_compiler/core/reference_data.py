"""Reference data sections.

A placeholder's config may name one or more data sources through the
reserved ``dataSource`` key (a variable name or list of variable names).
The compiler renders each referenced variable once in a REFERENCE DATA
section above the template, so the model can ground generated content in
the data without the data appearing in the rendered output; a processing
instruction tells the model the section is context only.

Rendering is kept byte-compatible with the JavaScript compiler.
"""

import json
from typing import Any, Dict, List

REFERENCE_DATA_INSTRUCTION = (
    "Use the REFERENCE DATA section as context when generating placeholder content"
    " - never include the reference data itself in your output"
)


def collect_data_source_names(content: List[Dict[str, Any]]) -> List[str]:
    """Collect data source names from placeholder configs, deduplicated in order of first appearance."""
    names: List[str] = []
    for element in content:
        if element.get("type") != "placeholder":
            continue
        raw = element.get("config", {}).get("dataSource")
        candidates = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
        for candidate in candidates:
            if isinstance(candidate, str) and candidate and candidate not in names:
                names.append(candidate)
    return names


def _render_cell(value: Any) -> str:
    """Cell rendering: strings verbatim, everything else compact JSON."""
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return text.replace("|", "\\|").replace("\n", " ")


def _render_object_table(rows: List[Dict[str, Any]]) -> str:
    columns: List[str] = []
    for row in rows:
        for key in row.keys():
            if key not in columns:
                columns.append(key)
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_render_cell(row[c]) if c in row else "" for c in columns) + " |")
    return "\n".join(lines)


def render_data_source(value: Any) -> str:
    """Render one data source as markdown: arrays of objects become tables, plain objects become field tables."""
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            return _render_object_table(value)
        return "\n".join(f"- {_render_cell(item)}" for item in value)
    if isinstance(value, dict):
        lines = ["| Field | Value |", "| --- | --- |"]
        for key, item in value.items():
            lines.append(f"| {_render_cell(key)} | {_render_cell(item)} |")
        return "\n".join(lines)
    return _render_cell(value)
