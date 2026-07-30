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
from typing import Any, Dict, List, Optional, Tuple

REFERENCE_DATA_INSTRUCTION = (
    "Use the REFERENCE DATA section as context when generating placeholder content"
    " - never include the reference data itself in your output"
)


def collect_data_sources(content: List[Dict[str, Any]]) -> List[Tuple[str, Optional[int]]]:
    """Collect (name, limit) data source requests from placeholder configs.

    Deduplicated in order of first appearance. A placeholder's optional
    dataLimit config caps how much of each of its sources is included; when
    several placeholders reference the same source the most generous request
    wins (no limit beats any limit, otherwise the maximum).
    """
    requests: List[Tuple[str, Optional[int]]] = []
    for element in content:
        if element.get("type") != "placeholder":
            continue
        config = element.get("config", {})
        raw = config.get("dataSource")
        raw_limit = config.get("dataLimit")
        limit = raw_limit if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) and raw_limit >= 1 else None
        candidates = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate:
                continue
            index = next((i for i, (name, _) in enumerate(requests) if name == candidate), None)
            if index is None:
                requests.append((candidate, limit))
            else:
                existing = requests[index][1]
                if existing is not None:
                    requests[index] = (candidate, None if limit is None else max(existing, limit))
    return requests


def collect_data_source_names(content: List[Dict[str, Any]]) -> List[str]:
    """Collect data source names only. Kept for API compatibility."""
    return [name for name, _ in collect_data_sources(content)]


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


def render_data_source(value: Any, limit: Optional[int] = None) -> str:
    """Render one data source as markdown, capped at limit items or fields.

    Arrays of objects become tables, plain objects become field tables, and
    any truncation is stated so the model knows the data is partial.
    Rendering is byte-compatible with the JavaScript compiler.
    """
    if isinstance(value, list):
        items = value[:limit] if limit is not None and limit < len(value) else value
        note = f"\n\nShowing the first {len(items)} of {len(value)} items." if len(items) < len(value) else ""
        if items and all(isinstance(item, dict) for item in items):
            return _render_object_table(items) + note
        return "\n".join(f"- {_render_cell(item)}" for item in items) + note
    if isinstance(value, dict):
        entries = list(value.items())
        shown = entries[:limit] if limit is not None and limit < len(entries) else entries
        note = f"\n\nShowing the first {len(shown)} of {len(entries)} fields." if len(shown) < len(entries) else ""
        lines = ["| Field | Value |", "| --- | --- |"]
        for key, item in shown:
            lines.append(f"| {_render_cell(key)} | {_render_cell(item)} |")
        return "\n".join(lines) + note
    return _render_cell(value)
