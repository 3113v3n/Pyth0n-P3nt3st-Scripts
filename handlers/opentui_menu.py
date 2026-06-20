"""OpenTUI-powered menu helpers for richer interactive terminal selection."""

from __future__ import annotations

import asyncio
import os
import re
import sys
import textwrap
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class OpenTUIMenuRequired(RuntimeError):
    """Raised when an interactive flow requires OpenTUI but it is unavailable."""


_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


@dataclass(frozen=True)
class MenuOption:
    label: str
    value: Any
    description: str = ""
    badge: str = ""
    meta: str = ""


@dataclass
class MenuModel:
    title: str
    prompt: str
    options: list[MenuOption]
    selected_index: int = 0
    footer: str = "↑/↓ navigate • Enter select • Esc/q cancel"
    subtitle: str = ""
    cancelled: bool = False

    def __post_init__(self) -> None:
        if not self.options:
            raise ValueError("MenuModel requires at least one option")
        self.selected_index %= len(self.options)

    @property
    def selected_option(self) -> MenuOption:
        return self.options[self.selected_index]

    def move_up(self) -> None:
        self.selected_index = (self.selected_index - 1) % len(self.options)

    def move_down(self) -> None:
        self.selected_index = (self.selected_index + 1) % len(self.options)


@dataclass(frozen=True)
class TextViewerState:
    content_width: int
    visible_lines: int
    body_lines: tuple[str, ...]
    max_scroll: int
    current_offset: int
    line_start: int
    line_end: int
    scroll_ratio: float


def opentui_menu_enabled() -> bool:
    """Return True when OpenTUI should be used for interactive menus."""
    raw = os.environ.get("PENTEST_USE_OPENTUI", "1").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        import opentui  # noqa: F401
    except Exception:
        return False
    return True


def ensure_opentui_menu_enabled(*, context: str) -> None:
    """Raise a clear error when an interactive flow requires OpenTUI."""
    if opentui_menu_enabled():
        return
    raise OpenTUIMenuRequired(
        f"OpenTUI is required for {context}. Ensure a TTY session with OpenTUI available, "
        "or use '-M cli_args' for non-interactive runs."
    )


def normalize_menu_text(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def truncate_menu_text(value: Any, *, max_length: int = 88) -> str:
    text = normalize_menu_text(value)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def format_menu_option_label(option: MenuOption, *, index: int | None = None) -> str:
    badge = option.badge or (str(index + 1) if index is not None else "")
    prefix = f"[{badge}] " if badge else ""
    return f"{prefix}{truncate_menu_text(option.label, max_length=72)}"


def summarize_menu_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float, str)):
        return truncate_menu_text(value, max_length=48)
    if value is None:
        return "none"
    return type(value).__name__


def format_input_cursor_line(current: str, cursor: int) -> str:
    current_text = str(current or "")
    cursor_index = max(0, min(int(cursor), len(current_text)))
    before = current_text[:cursor_index]
    after = current_text[cursor_index:]
    return f"> {before}▌{after}"


def selected_option_details(model: MenuModel) -> list[str]:
    selected = model.selected_option
    details = [
        f"Selection {model.selected_index + 1}/{len(model.options)}",
        f"Action: {summarize_menu_value(selected.value)}",
    ]
    if selected.meta:
        details.append(normalize_menu_text(selected.meta))
    return details


def build_menu_options(
    items: list[Any] | tuple[Any, ...],
    *,
    label_getter: Callable[[Any, int], Any],
    value_getter: Callable[[Any, int], Any],
    description_getter: Callable[[Any, int], Any] | None = None,
    badge_getter: Callable[[Any, int], Any] | None = None,
    meta_getter: Callable[[Any, int], Any] | None = None,
) -> list[MenuOption]:
    """Build ``MenuOption`` objects from arbitrary source records."""
    options: list[MenuOption] = []
    for index, item in enumerate(items):
        description = description_getter(item, index) if description_getter else ""
        badge = badge_getter(item, index) if badge_getter else ""
        meta = meta_getter(item, index) if meta_getter else ""
        options.append(
            MenuOption(
                label=truncate_menu_text(label_getter(item, index), max_length=72),
                value=value_getter(item, index),
                description=truncate_menu_text(description, max_length=96),
                badge=normalize_menu_text(badge),
                meta=truncate_menu_text(meta, max_length=72),
            )
        )
    return options


def build_menu_lines(model: MenuModel) -> list[str]:
    """Return plain-text lines representing the current menu state."""
    lines = [f"✦ {normalize_menu_text(model.title)}"]
    if model.subtitle:
        lines.append(normalize_menu_text(model.subtitle))
    lines.extend(
        [
            "",
            normalize_menu_text(model.prompt),
            f"{len(model.options)} choices • selected {model.selected_index + 1}/{len(model.options)}",
            "",
        ]
    )
    for index, option in enumerate(model.options):
        marker = "❯" if index == model.selected_index else " "
        line = f"{marker} {format_menu_option_label(option, index=index)}"
        if option.description:
            line = f"{line} — {option.description}"
        lines.append(line)
        if option.meta:
            lines.append(f"    {option.meta}")

    selected = model.selected_option
    selected_label = format_menu_option_label(selected, index=model.selected_index)
    lines.extend(
        [
            "",
            f"Selected: {selected_label}",
            selected.description or "Press Enter to confirm or Esc to cancel.",
            *selected_option_details(model),
            "",
            normalize_menu_text(model.footer),
        ]
    )
    return lines


def _event_name(event: Any) -> str:
    key = getattr(event, "name", None) or getattr(event, "key", "")
    if key in {"\n", "\r"}:
        return "linefeed"
    return str(key or "").strip().lower()


def _reset_opentui_runtime_state() -> None:
    """Clear global OpenTUI hook state before rendering a new menu."""
    try:
        import opentui.hooks as hooks
        from opentui import (
            clear_keyboard_handlers,
            clear_mouse_handlers,
            clear_paste_handlers,
            clear_resize_handlers,
            clear_selection_handlers,
        )

        clear_keyboard_handlers()
        clear_mouse_handlers()
        clear_paste_handlers()
        clear_resize_handlers()
        clear_selection_handlers()
        hooks.clear_focus_handlers()
        hooks._current_renderer = None
        hooks._pending_mount_fns.clear()
    except Exception:
        return


async def _render_opentui_menu(model: MenuModel) -> MenuOption | None:
    from opentui import Box, Keys, Signal, Text, component, render, use_keyboard, use_renderer

    selected_index = Signal(model.selected_index)
    selection: dict[str, MenuOption | None] = {"value": None}
    renderer_ref: dict[str, Any] = {"value": None}

    up_keys = {str(getattr(Keys, "UP", "")).lower(), "up", "arrowup", "k"}
    down_keys = {str(getattr(Keys, "DOWN", "")).lower(), "down", "arrowdown", "j"}
    enter_keys = {
        str(getattr(Keys, "RETURN", "")).lower(),
        str(getattr(Keys, "ENTER", "")).lower(),
        str(getattr(Keys, "LINEFEED", "")).lower(),
        "return",
        "enter",
        "linefeed",
    }
    cancel_keys = {str(getattr(Keys, "ESCAPE", "")).lower(), "escape", "esc", "q"}

    def _stop_renderer() -> None:
        renderer = renderer_ref.get("value")
        if renderer is not None:
            renderer.stop()

    def _set_index(index: int) -> None:
        selected_index.set(index % len(model.options))

    def _confirm() -> None:
        model.cancelled = False
        selection["value"] = model.options[selected_index()]
        _stop_renderer()

    def _cancel() -> None:
        model.cancelled = True
        selection["value"] = None
        _stop_renderer()

    def handle_key(event: Any) -> None:
        key = _event_name(event)
        if key in up_keys:
            _set_index(selected_index() - 1)
            event.stop()
            return
        if key in down_keys:
            _set_index(selected_index() + 1)
            event.stop()
            return
        if key in enter_keys:
            _confirm()
            event.stop()
            return
        if key in cancel_keys:
            _cancel()
            event.stop()
            return
        if key.isdigit():
            numeric_index = int(key) - 1
            if 0 <= numeric_index < len(model.options):
                _set_index(numeric_index)
                event.stop()

    @component
    def App():
        renderer_ref["value"] = use_renderer()
        renderer = renderer_ref["value"]
        use_keyboard(handle_key)

        current_model = MenuModel(
            title=model.title,
            prompt=model.prompt,
            options=model.options,
            selected_index=selected_index(),
            footer=model.footer,
            subtitle=model.subtitle,
        )
        selected = current_model.selected_option
        layout_direction = "row" if getattr(renderer, "width", 120) >= 110 else "column"

        option_cards = []
        for index, option in enumerate(model.options):
            is_selected = selected_index() == index
            option_cards.append(
                Box(
                    Text(
                        f"{'❯' if is_selected else ' '} {format_menu_option_label(option, index=index)}",
                        fg="#E2E8F0" if is_selected else "#CBD5E1",
                        bold=is_selected,
                    ),
                    Text(
                        option.description or "Press Enter to continue.",
                        fg="#FDE68A" if is_selected else "#94A3B8",
                    ),
                    Text(
                        option.meta or f"Shortcut {option.badge or index + 1}",
                        fg="#67E8F9" if is_selected else "#64748B",
                    ),
                    border=True,
                    border_style="rounded",
                    border_color="#22D3EE" if is_selected else "#334155",
                    background_color="#082F49" if is_selected else "#0F172A",
                    padding=1,
                    gap=1,
                )
            )

        detail_panel = Box(
            Text("Selection Inspector", fg="#A78BFA", bold=True),
            Text(
                f"Selected: {format_menu_option_label(selected, index=current_model.selected_index)}",
                fg="#4ADE80",
                bold=True,
            ),
            Text(
                selected.description or "Choose an option and press Enter to continue.",
                fg="#FCD34D",
            ),
            *[Text(line, fg="#94A3B8") for line in selected_option_details(current_model)],
            Box(
                Text("Hotkeys", fg="#F472B6", bold=True),
                Text("↑/↓ or j/k • move", fg="#CBD5E1"),
                Text("1-9 • jump to an item", fg="#CBD5E1"),
                Text("Enter • confirm • Esc/q • cancel", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#4C1D95",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Text("Navigation", fg="#22D3EE", bold=True),
                Text("Move through choices with arrows or j/k.", fg="#CBD5E1"),
                Text("Press Enter to continue with the highlighted item.", fg="#CBD5E1"),
                Text("Use Esc/q to return without committing a choice.", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#0F766E",
                background_color="#042F2E",
                padding=1,
                gap=1,
            ),
            border=True,
            border_style="rounded",
            border_color="#166534",
            background_color="#052E16",
            padding=1,
            gap=1,
            min_width=36,
        )

        return Box(
            Box(
                Text(lambda: f"✦ {normalize_menu_text(model.title)}", fg="#F472B6", bold=True),
                Text(
                    lambda: normalize_menu_text(model.subtitle)
                    or "Interactive navigation with a richer OpenTUI layout",
                    fg="#C4B5FD",
                ),
                Text(lambda: normalize_menu_text(model.prompt), fg="#67E8F9"),
                Box(
                    Text(lambda: f"{len(model.options)} choices", fg="#E2E8F0", bold=True),
                    Text(lambda: f"Selected {selected_index() + 1}/{len(model.options)}", fg="#93C5FD"),
                    Text("Numbers jump directly to an item", fg="#94A3B8"),
                    flex_direction="row",
                    justify_content="space-between",
                    gap=2,
                ),
                border=True,
                border_style="rounded",
                border_color="#7C3AED",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Box(
                    *option_cards,
                    border=True,
                    border_style="rounded",
                    border_color="#1D4ED8",
                    title="Options",
                    padding=1,
                    gap=1,
                    flex_grow=1,
                ),
                detail_panel,
                flex_direction=layout_direction,
                gap=1,
                flex_grow=1,
                align_items="stretch",
            ),
            Box(
                Text(lambda: normalize_menu_text(model.footer), fg="#CBD5E1"),
                Text(
                    lambda: f"Ready → {summarize_menu_value(model.options[selected_index()].value)}",
                    fg="#4ADE80",
                    bold=True,
                ),
                border=True,
                border_style="rounded",
                border_color="#475569",
                background_color="#020617",
                padding=1,
                flex_direction="row",
                justify_content="space-between",
                gap=2,
            ),
            padding=1,
            gap=1,
            background_color="#020617",
        )

    await render(App)
    model.selected_index = selected_index()
    return selection["value"]


def _sanitize_viewer_text(value: Any) -> str:
    text = _ANSI_ESCAPE_RE.sub("", str(value or ""))
    return text.replace("\t", "    ").replace("\r\n", "\n").replace("\r", "\n")


def _wrap_viewer_lines(value: Any, *, width: int) -> list[str]:
    wrapped_lines: list[str] = []
    text = _sanitize_viewer_text(value)
    max_width = max(24, width)
    for raw_line in text.splitlines() or [text]:
        if not raw_line.strip():
            wrapped_lines.append("")
            continue
        wrapped_lines.extend(
            textwrap.wrap(
                raw_line,
                width=max_width,
                replace_whitespace=False,
                drop_whitespace=False,
                break_long_words=True,
                break_on_hyphens=False,
            )
            or [""]
        )
    return wrapped_lines or [""]


def _compute_text_viewer_state(
    *,
    body: str,
    renderer_width: int,
    renderer_height: int,
    requested_offset: int,
) -> TextViewerState:
    safe_width = max(72, int(renderer_width or 120))
    safe_height = max(18, int(renderer_height or 40))
    content_width = max(56, safe_width - 8)
    visible_lines = max(12, safe_height - 10)
    body_lines = tuple(_wrap_viewer_lines(body, width=content_width))
    max_scroll = max(0, len(body_lines) - visible_lines)
    current_offset = max(0, min(int(requested_offset or 0), max_scroll))
    line_start = current_offset + 1 if body_lines else 0
    line_end = min(current_offset + visible_lines, len(body_lines))
    scroll_ratio = 1.0 if max_scroll == 0 else current_offset / max_scroll
    return TextViewerState(
        content_width=content_width,
        visible_lines=visible_lines,
        body_lines=body_lines,
        max_scroll=max_scroll,
        current_offset=current_offset,
        line_start=line_start,
        line_end=line_end,
        scroll_ratio=scroll_ratio,
    )


async def _render_opentui_text_viewer(
    *,
    title: str,
    prompt: str,
    body: str,
    subtitle: str = "",
    footer: str = "↑/↓ or j/k scroll • PgUp/PgDn page • Enter/Esc close",
) -> None:
    from opentui import Box, Keys, Signal, Text, component, render, use_keyboard, use_renderer

    scroll_offset = Signal(0)
    renderer_ref: dict[str, Any] = {"value": None}
    enter_keys = {
        str(getattr(Keys, "RETURN", "")).lower(),
        str(getattr(Keys, "ENTER", "")).lower(),
        str(getattr(Keys, "LINEFEED", "")).lower(),
        "return",
        "enter",
        "linefeed",
    }
    cancel_keys = {str(getattr(Keys, "ESCAPE", "")).lower(), "escape", "esc", "q"}
    up_keys = {str(getattr(Keys, "UP", "")).lower(), "up", "arrowup", "k"}
    down_keys = {str(getattr(Keys, "DOWN", "")).lower(), "down", "arrowdown", "j"}
    page_up_keys = {str(getattr(Keys, "PAGE_UP", "")).lower(), "pageup"}
    page_down_keys = {str(getattr(Keys, "PAGE_DOWN", "")).lower(), "pagedown"}
    home_keys = {str(getattr(Keys, "HOME", "")).lower(), "home", "g"}
    end_keys = {str(getattr(Keys, "END", "")).lower(), "end", "shift+g", "G"}

    def _stop_renderer() -> None:
        renderer = renderer_ref.get("value")
        if renderer is not None:
            renderer.stop()

    def _clamp_scroll(next_offset: int, *, max_scroll: int) -> None:
        scroll_offset.set(max(0, min(next_offset, max_scroll)))

    @component
    def App():
        renderer_ref["value"] = use_renderer()
        renderer = renderer_ref["value"]
        viewer_state = _compute_text_viewer_state(
            body=body,
            renderer_width=getattr(renderer, "width", 120),
            renderer_height=getattr(renderer, "height", 40),
            requested_offset=scroll_offset(),
        )
        current_offset = viewer_state.current_offset
        if current_offset != scroll_offset():
            scroll_offset.set(current_offset)

        def handle_key(event: Any) -> None:
            key = _event_name(event)
            if key in enter_keys or key in cancel_keys:
                _stop_renderer()
                event.stop()
                return
            if key in up_keys:
                _clamp_scroll(current_offset - 1, max_scroll=viewer_state.max_scroll)
                event.stop()
                return
            if key in down_keys:
                _clamp_scroll(current_offset + 1, max_scroll=viewer_state.max_scroll)
                event.stop()
                return
            if key in page_up_keys:
                _clamp_scroll(current_offset - viewer_state.visible_lines, max_scroll=viewer_state.max_scroll)
                event.stop()
                return
            if key in page_down_keys:
                _clamp_scroll(current_offset + viewer_state.visible_lines, max_scroll=viewer_state.max_scroll)
                event.stop()
                return
            if key in home_keys:
                _clamp_scroll(0, max_scroll=viewer_state.max_scroll)
                event.stop()
                return
            if key in end_keys:
                _clamp_scroll(viewer_state.max_scroll, max_scroll=viewer_state.max_scroll)
                event.stop()

        use_keyboard(handle_key)

        visible_slice = viewer_state.body_lines[
            current_offset: current_offset + viewer_state.visible_lines
        ]
        progress_percent = int(round(viewer_state.scroll_ratio * 100))

        content_panel = Box(
            *[Text(line or " ", fg="#E2E8F0") for line in visible_slice],
            border=True,
            border_style="rounded",
            border_color="#1D4ED8",
            title=f"Content • lines {viewer_state.line_start}-{viewer_state.line_end} of {len(viewer_state.body_lines)}",
            padding=1,
            gap=0,
            flex_grow=1,
        )

        return Box(
            Box(
                Text(lambda: f"✦ {normalize_menu_text(title)}", fg="#F472B6", bold=True),
                Text(
                    lambda: normalize_menu_text(subtitle)
                    or "Review helper guidance before continuing.",
                    fg="#C4B5FD",
                ),
                Text(lambda: normalize_menu_text(prompt), fg="#67E8F9"),
                Text(
                    lambda: (
                        f"Scrollable viewer • {len(viewer_state.body_lines)} wrapped lines • "
                        f"width {viewer_state.content_width} cols"
                    ),
                    fg="#E2E8F0",
                    bold=True,
                ),
                border=True,
                border_style="rounded",
                border_color="#7C3AED",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            content_panel,
            Box(
                Text(lambda: normalize_menu_text(footer), fg="#CBD5E1"),
                Text(
                    lambda: (
                        f"Scroll {progress_percent}% • line {viewer_state.line_start}/"
                        f"{max(1, len(viewer_state.body_lines))} • Home/End jump"
                    ),
                    fg="#4ADE80",
                    bold=True,
                ),
                border=True,
                border_style="rounded",
                border_color="#475569",
                background_color="#020617",
                padding=1,
                flex_direction="row",
                justify_content="space-between",
                gap=2,
            ),
            padding=1,
            gap=1,
            background_color="#020617",
        )

    await render(App)


def run_opentui_text_viewer(
    *,
    title: str,
    prompt: str,
    body: str,
    subtitle: str = "",
    footer: str = "↑/↓ or j/k scroll • PgUp/PgDn page • Enter/Esc close",
) -> None:
    _reset_opentui_runtime_state()
    asyncio.run(
        _render_opentui_text_viewer(
            title=title,
            prompt=prompt,
            body=body,
            subtitle=subtitle,
            footer=footer,
        )
    )


async def _render_opentui_text_input(
    *,
    title: str,
    prompt: str,
    subtitle: str = "",
    initial_value: str = "",
    footer: str = "Type to edit • ←/→ move • Enter submit • Esc cancel",
) -> str | None:
    from opentui import (
        Box,
        Keys,
        Signal,
        Text,
        component,
        render,
        use_keyboard,
        use_paste,
        use_renderer,
    )

    value_signal = Signal(str(initial_value or ""))
    cursor_signal = Signal(len(str(initial_value or "")))
    submitted: dict[str, str | None] = {"value": None}
    renderer_ref: dict[str, Any] = {"value": None}
    enter_keys = {
        str(getattr(Keys, "RETURN", "")).lower(),
        str(getattr(Keys, "ENTER", "")).lower(),
        str(getattr(Keys, "LINEFEED", "")).lower(),
        "return",
        "enter",
        "linefeed",
    }
    cancel_keys = {str(getattr(Keys, "ESCAPE", "")).lower(), "escape", "esc"}
    left_keys = {str(getattr(Keys, "LEFT", "")).lower(), "left", "arrowleft"}
    right_keys = {str(getattr(Keys, "RIGHT", "")).lower(), "right", "arrowright"}
    home_keys = {str(getattr(Keys, "HOME", "")).lower(), "home"}
    end_keys = {str(getattr(Keys, "END", "")).lower(), "end"}
    backspace_keys = {str(getattr(Keys, "BACKSPACE", "")).lower(), "backspace"}
    delete_keys = {str(getattr(Keys, "DELETE", "")).lower(), "delete"}

    def _stop_renderer() -> None:
        renderer = renderer_ref.get("value")
        if renderer is not None:
            renderer.stop()

    def _set_state(new_value: str, new_cursor: int | None = None) -> None:
        value_signal.set(new_value)
        if new_cursor is None:
            new_cursor = len(new_value)
        cursor_signal.set(max(0, min(new_cursor, len(new_value))))

    def _insert_text(fragment: str) -> None:
        current = value_signal()
        cursor = cursor_signal()
        next_value = current[:cursor] + fragment + current[cursor:]
        _set_state(next_value, cursor + len(fragment))

    def _confirm() -> None:
        submitted["value"] = value_signal()
        _stop_renderer()

    def _cancel() -> None:
        submitted["value"] = None
        _stop_renderer()

    def _handle_paste(event: Any) -> None:
        text = getattr(event, "text", None)
        if text:
            _insert_text(str(text))
            event.stop()

    def _handle_key(event: Any) -> None:
        key = _event_name(event)
        current = value_signal()
        cursor = cursor_signal()

        if key in enter_keys:
            _confirm()
            event.stop()
            return
        if key in cancel_keys:
            _cancel()
            event.stop()
            return
        if key in left_keys:
            cursor_signal.set(max(0, cursor - 1))
            event.stop()
            return
        if key in right_keys:
            cursor_signal.set(min(len(current), cursor + 1))
            event.stop()
            return
        if key in home_keys:
            cursor_signal.set(0)
            event.stop()
            return
        if key in end_keys:
            cursor_signal.set(len(current))
            event.stop()
            return
        if key in backspace_keys:
            if cursor > 0:
                _set_state(current[: cursor - 1] + current[cursor:], cursor - 1)
            event.stop()
            return
        if key in delete_keys:
            if cursor < len(current):
                _set_state(current[:cursor] + current[cursor + 1 :], cursor)
            event.stop()
            return
        if key == str(getattr(Keys, "SPACE", "space")).lower() or key == "space":
            _insert_text(" ")
            event.stop()
            return
        if len(getattr(event, "key", "")) == 1 and not any(
            getattr(event, modifier, False) for modifier in ("ctrl", "alt", "meta", "hyper")
        ):
            _insert_text(str(event.key))
            event.stop()

    def _render_input_line() -> str:
        return format_input_cursor_line(value_signal(), cursor_signal())

    @component
    def App():
        renderer_ref["value"] = use_renderer()
        use_keyboard(_handle_key)
        use_paste(_handle_paste)

        current = value_signal()
        detail_lines = _wrap_viewer_lines(current or " ", width=56)

        input_panel = Box(
            Text("Input Buffer", fg="#A78BFA", bold=True),
            Text(lambda: _render_input_line(), fg="#E2E8F0", bold=True),
            Text(lambda: f"{len(value_signal())} character(s)", fg="#67E8F9"),
            border=True,
            border_style="rounded",
            border_color="#22D3EE",
            background_color="#082F49",
            padding=1,
            gap=1,
            flex_grow=1,
        )

        detail_panel = Box(
            Text("Input Inspector", fg="#4ADE80", bold=True),
            Text(lambda: normalize_menu_text(prompt), fg="#FCD34D"),
            *[Text(line or " ", fg="#CBD5E1") for line in detail_lines[:8]],
            Box(
                Text("Hotkeys", fg="#F472B6", bold=True),
                Text("Type characters • paste supported", fg="#CBD5E1"),
                Text("←/→ • move • Home/End • jump", fg="#CBD5E1"),
                Text("Backspace/Delete • edit", fg="#CBD5E1"),
                Text("Enter • submit • Esc • cancel", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#4C1D95",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Text("Navigation", fg="#22D3EE", bold=True),
                Text("Look for the > marker in the input buffer.", fg="#CBD5E1"),
                Text("Type directly after > to build the value.", fg="#CBD5E1"),
                Text("Press Esc to return to the previous step.", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#0F766E",
                background_color="#042F2E",
                padding=1,
                gap=1,
            ),
            border=True,
            border_style="rounded",
            border_color="#166534",
            background_color="#052E16",
            padding=1,
            gap=1,
            min_width=36,
        )

        return Box(
            Box(
                Text(lambda: f"✦ {normalize_menu_text(title)}", fg="#F472B6", bold=True),
                Text(
                    lambda: normalize_menu_text(subtitle)
                    or "Capture the next value directly in the TUI.",
                    fg="#C4B5FD",
                ),
                Text(lambda: normalize_menu_text(prompt), fg="#67E8F9"),
                border=True,
                border_style="rounded",
                border_color="#7C3AED",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                input_panel,
                detail_panel,
                flex_direction="row" if len(current) < 160 else "column",
                gap=1,
                flex_grow=1,
                align_items="stretch",
            ),
            Box(
                Text(lambda: normalize_menu_text(footer), fg="#CBD5E1"),
                Text(lambda: f"Ready → {len(value_signal())} chars", fg="#4ADE80", bold=True),
                border=True,
                border_style="rounded",
                border_color="#475569",
                background_color="#020617",
                padding=1,
                flex_direction="row",
                justify_content="space-between",
                gap=2,
            ),
            padding=1,
            gap=1,
            background_color="#020617",
        )

    await render(App)
    return submitted["value"]


def run_opentui_text_input(
    *,
    title: str,
    prompt: str,
    subtitle: str = "",
    initial_value: str = "",
    footer: str = "Type to edit • ←/→ move • Enter submit • Esc cancel",
    cancel_raises: type[Exception] | None = None,
) -> str | None:
    _reset_opentui_runtime_state()
    coro = _render_opentui_text_input(
        title=title,
        prompt=prompt,
        subtitle=subtitle,
        initial_value=initial_value,
        footer=footer,
    )
    try:
        value = asyncio.run(coro)
        if value is None and cancel_raises is not None:
            raise cancel_raises()
        return value
    except Exception as error:
        if cancel_raises is not None and isinstance(error, cancel_raises):
            raise
        coro.close()
        return None


def _render_progress_meter(progress_ratio: float, *, width: int = 28) -> str:
    safe_ratio = max(0.0, min(float(progress_ratio or 0.0), 1.0))
    filled = min(width, max(0, int(round(safe_ratio * width))))
    return f"[{'█' * filled}{'·' * (width - filled)}] {safe_ratio * 100:5.1f}%"


async def _render_opentui_progress_display(
    *,
    title: str,
    prompt: str,
    subtitle: str,
    snapshot_getter: Callable[[], dict[str, Any]],
    worker: Callable[[], Any],
    footer: str,
    cancel: Callable[[], Any] | None = None,
    refresh_interval: float = 0.1,
) -> dict[str, Any]:
    from opentui import Box, Keys, Signal, Text, component, render, use_keyboard, use_renderer

    snapshot_signal = Signal(dict(snapshot_getter() or {}))
    renderer_ref: dict[str, Any] = {"value": None}
    worker_error: dict[str, BaseException | None] = {"value": None}
    worker_done = threading.Event()
    stop_polling = threading.Event()
    cancel_requested = threading.Event()
    cancel_keys = {str(getattr(Keys, "ESCAPE", "")).lower(), "escape", "esc", "q"}

    def _stop_renderer() -> None:
        renderer = renderer_ref.get("value")
        if renderer is not None:
            renderer.stop()

    def _poll_snapshots() -> None:
        try:
            while not stop_polling.is_set():
                snapshot_signal.set(dict(snapshot_getter() or {}))
                if worker_done.is_set():
                    break
                time.sleep(refresh_interval)
            snapshot_signal.set(dict(snapshot_getter() or {}))
        finally:
            _stop_renderer()

    def _run_worker() -> None:
        try:
            worker()
        except BaseException as error:  # pragma: no cover - surfaced after render
            worker_error["value"] = error
        finally:
            worker_done.set()

    def _handle_key(event: Any) -> None:
        key = _event_name(event)
        if key in cancel_keys and cancel is not None and not cancel_requested.is_set():
            cancel_requested.set()
            try:
                cancel()
            finally:
                event.stop()

    worker_thread = threading.Thread(target=_run_worker, daemon=True)
    poller_thread = threading.Thread(target=_poll_snapshots, daemon=True)
    worker_thread.start()
    poller_thread.start()

    @component
    def App():
        renderer_ref["value"] = use_renderer()
        renderer = renderer_ref["value"]
        use_keyboard(_handle_key)

        snapshot = dict(snapshot_signal() or {})
        layout_direction = "row" if getattr(renderer, "width", 120) >= 110 else "column"
        progress_ratio = float(snapshot.get("progress_ratio", 0.0) or 0.0)
        total_scanned = int(snapshot.get("total_scanned", 0) or 0)
        total_hosts = int(snapshot.get("total_hosts", 0) or 0)
        live_count = int(snapshot.get("live_count", 0) or 0)
        unresponsive_count = int(snapshot.get("unresponsive_count", 0) or 0)
        elapsed_seconds = float(snapshot.get("elapsed_seconds", 0.0) or 0.0)
        status_message = normalize_menu_text(snapshot.get("status_message", "Preparing scan..."))
        recent_live = [str(item) for item in snapshot.get("recent_live", [])][:12]
        recent_unresponsive = [str(item) for item in snapshot.get("recent_unresponsive", [])][:12]
        summary_lines = [
            f"Mode: {normalize_menu_text(snapshot.get('mode', 'scan')).upper()}",
            f"Subnet: {snapshot.get('subnet', '') or 'n/a'}",
            f"Interface: {snapshot.get('interface', '') or 'n/a'}",
            f"Elapsed: {elapsed_seconds:0.1f}s",
            f"Last scanned IP: {snapshot.get('last_scanned_ip', '') or 'pending'}",
        ]

        responsive_panel = Box(
            Text("Responsive Hosts", fg="#4ADE80", bold=True),
            *[Text(host, fg="#E2E8F0") for host in (recent_live or ["No responsive hosts yet."])],
            border=True,
            border_style="rounded",
            border_color="#166534",
            background_color="#052E16",
            padding=1,
            gap=1,
            flex_grow=1,
        )
        unresponsive_panel = Box(
            Text("Unresponsive Hosts", fg="#F87171", bold=True),
            *[Text(host, fg="#E2E8F0") for host in (recent_unresponsive or ["No unresponsive hosts yet."])],
            border=True,
            border_style="rounded",
            border_color="#7F1D1D",
            background_color="#450A0A",
            padding=1,
            gap=1,
            flex_grow=1,
        )
        detail_panel = Box(
            Text("Scan Status", fg="#A78BFA", bold=True),
            Text(status_message or "Preparing scan...", fg="#FCD34D"),
            Text(_render_progress_meter(progress_ratio), fg="#67E8F9", bold=True),
            Text(f"Processed: {total_scanned}/{total_hosts or '?'}", fg="#E2E8F0"),
            Text(f"Responsive: {live_count}", fg="#4ADE80"),
            Text(f"Unresponsive: {unresponsive_count}", fg="#F87171"),
            *[Text(line, fg="#94A3B8") for line in summary_lines],
            Box(
                Text("Navigation", fg="#22D3EE", bold=True),
                Text("Watch responsive and unresponsive hosts update live.", fg="#CBD5E1"),
                Text("Press Esc/q to request a graceful stop.", fg="#CBD5E1"),
                Text("The final module summary will open in a TUI viewer.", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#0F766E",
                background_color="#042F2E",
                padding=1,
                gap=1,
            ),
            border=True,
            border_style="rounded",
            border_color="#4C1D95",
            background_color="#1E1B4B",
            padding=1,
            gap=1,
            min_width=38,
        )

        return Box(
            Box(
                Text(lambda: f"✦ {normalize_menu_text(title)}", fg="#F472B6", bold=True),
                Text(lambda: normalize_menu_text(subtitle), fg="#C4B5FD"),
                Text(lambda: normalize_menu_text(prompt), fg="#67E8F9"),
                border=True,
                border_style="rounded",
                border_color="#7C3AED",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Box(
                    responsive_panel,
                    unresponsive_panel,
                    flex_direction="row" if getattr(renderer, "width", 120) >= 135 else "column",
                    gap=1,
                    flex_grow=1,
                ),
                detail_panel,
                flex_direction=layout_direction,
                gap=1,
                flex_grow=1,
                align_items="stretch",
            ),
            Box(
                Text(lambda: normalize_menu_text(footer), fg="#CBD5E1"),
                Text(lambda: f"Progress → {total_scanned}/{total_hosts or '?'}", fg="#4ADE80", bold=True),
                border=True,
                border_style="rounded",
                border_color="#475569",
                background_color="#020617",
                padding=1,
                flex_direction="row",
                justify_content="space-between",
                gap=2,
            ),
            padding=1,
            gap=1,
            background_color="#020617",
        )

    try:
        await render(App)
    finally:
        worker_done.wait()
        stop_polling.set()
        poller_thread.join(timeout=1)
        worker_thread.join(timeout=1)

    if worker_error["value"] is not None:
        raise worker_error["value"]
    return dict(snapshot_getter() or {})


def run_opentui_progress_display(
    *,
    title: str,
    prompt: str,
    subtitle: str,
    snapshot_getter: Callable[[], dict[str, Any]],
    worker: Callable[[], Any],
    footer: str = "Esc/q requests a graceful stop • final results will open after the scan",
    cancel: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    _reset_opentui_runtime_state()
    coro = _render_opentui_progress_display(
        title=title,
        prompt=prompt,
        subtitle=subtitle,
        snapshot_getter=snapshot_getter,
        worker=worker,
        footer=footer,
        cancel=cancel,
    )
    try:
        return asyncio.run(coro)
    finally:
        coro.close()


async def _render_opentui_multi_select(
    *,
    title: str,
    prompt: str,
    options: list[MenuOption],
    selected_values: tuple[Any, ...] = (),
    subtitle: str = "",
    footer: str = "↑/↓ move • Space toggle • a select all • Enter confirm • Esc cancel",
) -> tuple[Any, ...] | None:
    from opentui import Box, Keys, Signal, Text, component, render, use_keyboard, use_renderer

    selected_index = Signal(0)
    active_values = Signal(tuple(selected_values))
    selection: dict[str, tuple[Any, ...] | None] = {"value": None}
    renderer_ref: dict[str, Any] = {"value": None}
    up_keys = {str(getattr(Keys, "UP", "")).lower(), "up", "arrowup", "k"}
    down_keys = {str(getattr(Keys, "DOWN", "")).lower(), "down", "arrowdown", "j"}
    enter_keys = {
        str(getattr(Keys, "RETURN", "")).lower(),
        str(getattr(Keys, "ENTER", "")).lower(),
        str(getattr(Keys, "LINEFEED", "")).lower(),
        "return",
        "enter",
        "linefeed",
    }
    cancel_keys = {str(getattr(Keys, "ESCAPE", "")).lower(), "escape", "esc", "q"}
    toggle_keys = {str(getattr(Keys, "SPACE", "space")).lower(), "space"}

    def _stop_renderer() -> None:
        renderer = renderer_ref.get("value")
        if renderer is not None:
            renderer.stop()

    def _set_index(index: int) -> None:
        selected_index.set(index % len(options))

    def _all_values() -> tuple[Any, ...]:
        return tuple(option.value for option in options)

    def _toggle_current() -> None:
        current_values = list(active_values())
        current_value = options[selected_index()].value
        if current_value in current_values:
            current_values = [value for value in current_values if value != current_value]
        else:
            current_values.append(current_value)
        active_values.set(tuple(current_values))

    def _confirm() -> None:
        chosen = active_values() or _all_values()
        selection["value"] = tuple(chosen)
        _stop_renderer()

    def _cancel() -> None:
        selection["value"] = None
        _stop_renderer()

    def handle_key(event: Any) -> None:
        key = _event_name(event)
        if key in up_keys:
            _set_index(selected_index() - 1)
            event.stop()
            return
        if key in down_keys:
            _set_index(selected_index() + 1)
            event.stop()
            return
        if key in toggle_keys:
            _toggle_current()
            event.stop()
            return
        if key == "a":
            active_values.set(_all_values())
            event.stop()
            return
        if key in enter_keys:
            _confirm()
            event.stop()
            return
        if key in cancel_keys:
            _cancel()
            event.stop()
            return
        if key.isdigit():
            numeric_index = int(key) - 1
            if 0 <= numeric_index < len(options):
                _set_index(numeric_index)
                event.stop()

    @component
    def App():
        renderer_ref["value"] = use_renderer()
        renderer = renderer_ref["value"]
        use_keyboard(handle_key)

        chosen_values = set(active_values())
        layout_direction = "row" if getattr(renderer, "width", 120) >= 110 else "column"

        option_cards = []
        for index, option in enumerate(options):
            is_selected = selected_index() == index
            is_checked = option.value in chosen_values
            option_cards.append(
                Box(
                    Text(
                        f"{'❯' if is_selected else ' '} [{'x' if is_checked else ' '}] {format_menu_option_label(option, index=index)}",
                        fg="#E2E8F0" if is_selected else "#CBD5E1",
                        bold=is_selected,
                    ),
                    Text(
                        option.description or "Toggle this item with Space.",
                        fg="#FDE68A" if is_selected else "#94A3B8",
                    ),
                    Text(
                        option.meta or "Press Space to include/exclude",
                        fg="#67E8F9" if is_selected else "#64748B",
                    ),
                    border=True,
                    border_style="rounded",
                    border_color="#22D3EE" if is_selected else "#334155",
                    background_color="#082F49" if is_selected else "#0F172A",
                    padding=1,
                    gap=1,
                )
            )

        selected_option = options[selected_index()]
        selected_labels = [
            format_menu_option_label(option, index=index)
            for index, option in enumerate(options)
            if option.value in chosen_values
        ]
        detail_panel = Box(
            Text("Selection Inspector", fg="#A78BFA", bold=True),
            Text(
                lambda: f"Current: {format_menu_option_label(selected_option, index=selected_index())}",
                fg="#4ADE80",
                bold=True,
            ),
            Text(
                lambda: f"Selected items: {len(chosen_values) or len(options)}/{len(options)}",
                fg="#FCD34D",
            ),
            *[
                Text(line, fg="#94A3B8")
                for line in _wrap_viewer_lines(
                    ", ".join(selected_labels) if selected_labels else "No items checked — Enter will restore all items.",
                    width=34,
                )[:8]
            ],
            Box(
                Text("Hotkeys", fg="#F472B6", bold=True),
                Text("↑/↓ or j/k • move", fg="#CBD5E1"),
                Text("Space • toggle • a • select all", fg="#CBD5E1"),
                Text("1-9 • jump to an item", fg="#CBD5E1"),
                Text("Enter • confirm • Esc/q • cancel", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#4C1D95",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Text("Navigation", fg="#22D3EE", bold=True),
                Text("Move through phases on the left and toggle them.", fg="#CBD5E1"),
                Text("Use Space to include or exclude the current phase.", fg="#CBD5E1"),
                Text("Press Enter to continue with the selected execution plan.", fg="#CBD5E1"),
                border=True,
                border_style="rounded",
                border_color="#0F766E",
                background_color="#042F2E",
                padding=1,
                gap=1,
            ),
            border=True,
            border_style="rounded",
            border_color="#166534",
            background_color="#052E16",
            padding=1,
            gap=1,
            min_width=36,
        )

        return Box(
            Box(
                Text(lambda: f"✦ {normalize_menu_text(title)}", fg="#F472B6", bold=True),
                Text(
                    lambda: normalize_menu_text(subtitle)
                    or "Toggle the items you want in the execution plan.",
                    fg="#C4B5FD",
                ),
                Text(lambda: normalize_menu_text(prompt), fg="#67E8F9"),
                Text(
                    lambda: f"{len(options)} options available • {len(chosen_values) or len(options)} selected",
                    fg="#E2E8F0",
                    bold=True,
                ),
                border=True,
                border_style="rounded",
                border_color="#7C3AED",
                background_color="#1E1B4B",
                padding=1,
                gap=1,
            ),
            Box(
                Box(
                    *option_cards,
                    border=True,
                    border_style="rounded",
                    border_color="#1D4ED8",
                    title="Selections",
                    padding=1,
                    gap=1,
                    flex_grow=1,
                ),
                detail_panel,
                flex_direction=layout_direction,
                gap=1,
                flex_grow=1,
                align_items="stretch",
            ),
            Box(
                Text(lambda: normalize_menu_text(footer), fg="#CBD5E1"),
                Text(
                    lambda: f"Ready → {len(chosen_values) or len(options)} item(s)",
                    fg="#4ADE80",
                    bold=True,
                ),
                border=True,
                border_style="rounded",
                border_color="#475569",
                background_color="#020617",
                padding=1,
                flex_direction="row",
                justify_content="space-between",
                gap=2,
            ),
            padding=1,
            gap=1,
            background_color="#020617",
        )

    await render(App)
    return selection["value"]


def run_opentui_multi_select(
    *,
    title: str,
    prompt: str,
    options: list[MenuOption],
    selected_values: tuple[Any, ...] = (),
    subtitle: str = "",
    footer: str = "↑/↓ move • Space toggle • a select all • Enter confirm • Esc cancel",
    cancel_raises: type[Exception] | None = None,
) -> tuple[Any, ...] | None:
    _reset_opentui_runtime_state()
    coro = _render_opentui_multi_select(
        title=title,
        prompt=prompt,
        options=options,
        selected_values=selected_values,
        subtitle=subtitle,
        footer=footer,
    )
    try:
        value = asyncio.run(coro)
        if value is None and cancel_raises is not None:
            raise cancel_raises()
        return value
    except Exception as error:
        if cancel_raises is not None and isinstance(error, cancel_raises):
            raise
        coro.close()
        return None


def run_opentui_menu(
    *,
    title: str,
    prompt: str,
    options: list[MenuOption],
    selected_index: int = 0,
    footer: str = "↑/↓ navigate • Enter select • Esc/q cancel",
    subtitle: str = "",
    cancel_raises: type[Exception] | None = None,
) -> MenuOption | None:
    """Render an OpenTUI menu and return the selected option, or None on cancel."""
    _reset_opentui_runtime_state()
    model = MenuModel(
        title=title,
        prompt=prompt,
        options=options,
        selected_index=selected_index,
        footer=footer,
        subtitle=subtitle,
    )
    coro = _render_opentui_menu(model)
    try:
        selected = asyncio.run(coro)
        if selected is None and model.cancelled and cancel_raises is not None:
            raise cancel_raises()
        return selected
    except Exception as error:
        if cancel_raises is not None and isinstance(error, cancel_raises):
            raise
        coro.close()
        return None
