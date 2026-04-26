"""Shared text-formatting helpers for safe report output."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any


def beautify_structured_text(content: Any) -> tuple[str, str]:
    """Return pretty text for JSON/XML payloads when possible."""
    if isinstance(content, (dict, list)):
        return json.dumps(content, indent=2, ensure_ascii=False), "json"

    text = str(content)
    stripped = text.strip()
    if not stripped:
        return text, "text"

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, indent=2, ensure_ascii=False), "json"
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    if stripped.startswith("<") and stripped.endswith(">"):
        try:
            root = ET.fromstring(stripped)
            tree = ET.ElementTree(root)
            if hasattr(ET, "indent"):
                ET.indent(tree, space="  ")
            return ET.tostring(root, encoding="unicode"), "xml"
        except ET.ParseError:
            pass

    return text, "text"


def prepare_text_for_write(
    content: Any,
    beautify_structured: bool = True,
    wrap_long_lines: bool = False,
) -> str:
    """Normalize text output before writing it to disk.

    The wrap_long_lines parameter is retained for compatibility with existing
    call sites and future formatting hooks.
    """
    _ = wrap_long_lines
    if beautify_structured:
        formatted, _content_type = beautify_structured_text(content)
        return formatted
    return str(content)
