"""Shared text-formatting helpers for safe report output."""

from __future__ import annotations

import json
import textwrap
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


def wrap_text_block(
    content: Any,
    *,
    width: int = 100,
    initial_indent: str = "",
    subsequent_indent: str | None = None,
) -> str:
    """Wrap long lines while preserving existing paragraph boundaries."""
    text = str(content).replace("\r", "")
    if not text:
        return initial_indent.rstrip()

    effective_sub_indent = subsequent_indent if subsequent_indent is not None else initial_indent
    wrapped_lines: list[str] = []
    for raw_line in text.splitlines() or [text]:
        line = raw_line.rstrip()
        if not line:
            wrapped_lines.append("")
            continue
        wrapped_lines.extend(
            textwrap.wrap(
                line,
                width=max(20, width),
                initial_indent=initial_indent,
                subsequent_indent=effective_sub_indent,
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return "\n".join(wrapped_lines)


def section_header(title: str, *, width: int = 100, fill: str = "=") -> str:
    """Render a consistent section header line for text reports."""
    normalized = " ".join(str(title or "").split()).upper() or "SECTION"
    token = f" {normalized} "
    return token.center(max(len(token) + 2, width), fill)


def prepare_text_for_write(
    content: Any,
    beautify_structured: bool = True,
    wrap_long_lines: bool = False,
) -> str:
    """Normalize text output before writing it to disk.

    The wrap_long_lines parameter is retained for compatibility with existing
    call sites and future formatting hooks.
    """
    if beautify_structured:
        formatted, _content_type = beautify_structured_text(content)
    else:
        formatted = str(content)

    if wrap_long_lines:
        return wrap_text_block(formatted)
    return formatted
