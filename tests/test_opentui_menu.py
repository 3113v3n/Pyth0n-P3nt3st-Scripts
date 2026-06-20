from types import SimpleNamespace

import pytest

from handlers import user_handler as user_handler_module
from handlers.helper_handler import HelpHandler
from handlers.navigation import BackToMainMenu, BackToPreviousMenu
from handlers.opentui_menu import (
    MenuModel,
    MenuOption,
    _compute_text_viewer_state,
    _event_name,
    build_menu_lines,
    build_menu_options,
    ensure_opentui_menu_enabled,
    format_input_cursor_line,
    run_opentui_multi_select,
    run_opentui_progress_display,
    run_opentui_text_input,
)


class _CommandStub:
    def clear_screen(self):
        return None


@pytest.mark.parametrize(
    ("start_index", "direction", "expected_index"),
    [
        (0, "up", 2),
        (2, "down", 0),
        (1, "down", 2),
        (1, "up", 0),
    ],
)
def test_menu_model_wraps_selection(start_index, direction, expected_index):
    model = MenuModel(
        title="Main Menu",
        prompt="Choose one",
        options=[
            MenuOption("Internal", "internal"),
            MenuOption("Mobile", "mobile"),
            MenuOption("Exit", "exit"),
        ],
        selected_index=start_index,
    )

    if direction == "up":
        model.move_up()
    else:
        model.move_down()

    assert model.selected_index == expected_index


def test_build_menu_options_assigns_badges_and_truncates_descriptions():
    options = build_menu_options(
        [
            {
                "label": "Mobile Penetration Testing",
                "value": "mobile",
                "description": "A" * 140,
            }
        ],
        label_getter=lambda item, _index: item["label"],
        value_getter=lambda item, _index: item["value"],
        description_getter=lambda item, _index: item["description"],
        badge_getter=lambda _item, index: str(index + 1),
    )

    assert len(options) == 1
    assert options[0].badge == "1"
    assert options[0].label == "Mobile Penetration Testing"
    assert options[0].description.endswith("...")
    assert len(options[0].description) <= 96


def test_build_menu_lines_highlights_selected_option_and_summary():
    model = MenuModel(
        title="Main Menu",
        prompt="Choose one",
        options=[
            MenuOption("Internal", "internal", description="Run internal tests", badge="1"),
            MenuOption("Mobile", "mobile", description="Run mobile workflow", badge="2"),
        ],
        selected_index=1,
    )

    lines = build_menu_lines(model)

    assert any(line.startswith("✦ Main Menu") for line in lines)
    assert any("❯ [2] Mobile" in line for line in lines)
    assert any("Selected: [2] Mobile" in line for line in lines)


def test_compute_text_viewer_state_allocates_most_space_to_content():
    body = "\n".join(f"line {index}" for index in range(1, 61))

    state = _compute_text_viewer_state(
        body=body,
        renderer_width=120,
        renderer_height=40,
        requested_offset=0,
    )

    assert state.content_width >= 100
    assert state.visible_lines >= 24
    assert len(state.body_lines) == 60
    assert state.max_scroll == len(state.body_lines) - state.visible_lines


def test_compute_text_viewer_state_clamps_requested_offset_to_scroll_range():
    body = "\n".join(f"row {index}" for index in range(1, 31))

    state = _compute_text_viewer_state(
        body=body,
        renderer_width=100,
        renderer_height=20,
        requested_offset=999,
    )

    assert state.current_offset == state.max_scroll
    assert state.line_end == len(state.body_lines)
    assert state.scroll_ratio == 1.0

def test_run_opentui_menu_falls_back_on_runtime_error(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    monkeypatch.setattr(
        opentui_menu.asyncio,
        "run",
        lambda _coro: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    selected = opentui_menu.run_opentui_menu(
        title="Main Menu",
        prompt="Choose one",
        options=[opentui_menu.MenuOption("Internal", "internal")],
    )

    assert selected is None


@pytest.mark.parametrize("raw_key", ["\n", "\r", "linefeed"])
def test_event_name_normalizes_linefeed_variants(raw_key):
    assert _event_name(SimpleNamespace(name=raw_key)) == "linefeed"


def test_format_input_cursor_line_uses_prompt_prefix_and_visible_cursor():
    assert format_input_cursor_line("", 0) == "> ▌"
    assert format_input_cursor_line("example", 0) == "> ▌example"
    assert format_input_cursor_line("example", 3) == "> exa▌mple"
    assert format_input_cursor_line("example", 7) == "> example▌"


def test_ensure_opentui_menu_enabled_raises_when_disabled(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    monkeypatch.setattr(opentui_menu, "opentui_menu_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="OpenTUI is required"):
        ensure_opentui_menu_enabled(context="testing")


def test_run_opentui_menu_raises_navigation_exception_on_cancel(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(model):
        model.cancelled = True
        return None

    monkeypatch.setattr(opentui_menu, "_render_opentui_menu", fake_render)

    with pytest.raises(BackToPreviousMenu):
        opentui_menu.run_opentui_menu(
            title="Main Menu",
            prompt="Choose one",
            options=[opentui_menu.MenuOption("Internal", "internal")],
            cancel_raises=BackToPreviousMenu,
        )


def test_run_opentui_menu_resets_runtime_state_before_each_render(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    calls = []

    async def fake_render(model):
        return model.options[0]

    monkeypatch.setattr(opentui_menu, "_reset_opentui_runtime_state", lambda: calls.append("reset"))
    monkeypatch.setattr(opentui_menu, "_render_opentui_menu", fake_render)

    first = opentui_menu.run_opentui_menu(
        title="First",
        prompt="Choose one",
        options=[opentui_menu.MenuOption("Internal", "internal")],
    )
    second = opentui_menu.run_opentui_menu(
        title="Second",
        prompt="Choose one",
        options=[opentui_menu.MenuOption("Mobile", "mobile")],
    )

    assert first is not None
    assert second is not None
    assert first.value == "internal"
    assert second.value == "mobile"
    assert calls == ["reset", "reset"]


def test_run_opentui_text_input_raises_navigation_exception_on_cancel(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(**kwargs):
        return None

    monkeypatch.setattr(opentui_menu, "_render_opentui_text_input", fake_render)

    with pytest.raises(BackToPreviousMenu):
        run_opentui_text_input(
            title="Input",
            prompt="Enter value",
            cancel_raises=BackToPreviousMenu,
        )


def test_run_opentui_text_input_returns_text(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(**kwargs):
        return "Example"

    monkeypatch.setattr(opentui_menu, "_render_opentui_text_input", fake_render)

    assert run_opentui_text_input(title="Input", prompt="Enter value") == "Example"


def test_run_opentui_progress_display_returns_snapshot(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(**kwargs):
        kwargs["worker"]()
        return kwargs["snapshot_getter"]()

    state = {"count": 0}

    monkeypatch.setattr(opentui_menu, "_render_opentui_progress_display", fake_render)

    snapshot = run_opentui_progress_display(
        title="Progress",
        prompt="Run scan",
        subtitle="Testing progress wrapper",
        snapshot_getter=lambda: {"count": state["count"]},
        worker=lambda: state.update(count=3),
    )

    assert snapshot == {"count": 3}


def test_run_opentui_multi_select_raises_navigation_exception_on_cancel(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(**kwargs):
        return None

    monkeypatch.setattr(opentui_menu, "_render_opentui_multi_select", fake_render)

    with pytest.raises(BackToPreviousMenu):
        run_opentui_multi_select(
            title="External",
            prompt="Select phases",
            options=[MenuOption("Recon", "recon")],
            cancel_raises=BackToPreviousMenu,
        )


def test_run_opentui_multi_select_returns_selected_values(monkeypatch):
    import handlers.opentui_menu as opentui_menu

    async def fake_render(**kwargs):
        return ("recon", "vulns")

    monkeypatch.setattr(opentui_menu, "_render_opentui_multi_select", fake_render)

    assert run_opentui_multi_select(
        title="External",
        prompt="Select phases",
        options=[MenuOption("Recon", "recon")],
    ) == ("recon", "vulns")


def test_user_handler_uses_opentui_menu_when_enabled(monkeypatch):
    helper = HelpHandler()
    handler = user_handler_module.UserHandler(helper, _CommandStub())

    monkeypatch.setattr(
        user_handler_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        user_handler_module,
        "run_opentui_menu",
        lambda **kwargs: MenuOption("Mobile", "mobile"),
    )

    assert handler.get_user_domain() == "mobile"


def test_user_handler_esc_does_not_fall_back_to_legacy_prompt(monkeypatch):
    helper = HelpHandler()
    handler = user_handler_module.UserHandler(helper, _CommandStub())

    monkeypatch.setattr(
        user_handler_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        user_handler_module,
        "run_opentui_menu",
        lambda **kwargs: (_ for _ in ()).throw(BackToMainMenu()),
    )
    monkeypatch.setattr(
        handler,
        "get_user_input",
        lambda prompt: (_ for _ in ()).throw(AssertionError("legacy prompt should not run")),
    )

    with pytest.raises(BackToMainMenu):
        handler.get_user_domain()


def test_user_handler_requires_opentui_and_does_not_use_legacy_prompt(monkeypatch):
    helper = HelpHandler()
    handler = user_handler_module.UserHandler(helper, _CommandStub())

    monkeypatch.setattr(
        user_handler_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("OpenTUI required")),
    )
    monkeypatch.setattr(
        handler,
        "get_user_input",
        lambda prompt: (_ for _ in ()).throw(AssertionError("legacy prompt should not run")),
    )

    with pytest.raises(RuntimeError, match="OpenTUI required"):
        handler.get_user_domain()


def test_user_handler_builds_richer_main_menu_options():
    handler = user_handler_module.UserHandler(HelpHandler(), _CommandStub())

    options = handler._build_main_menu_options()

    assert options[0].badge == "1"
    assert "📱🧪" in options[0].label
    assert "taxonomy-assisted findings" in options[0].description
    assert options[-1].badge == "?"
    assert options[-1].value == "help"


def test_start_domain_helper_shows_helper_viewer_before_confirmation(monkeypatch):
    handler = user_handler_module.UserHandler(HelpHandler(), _CommandStub())
    captured = {}

    monkeypatch.setattr(
        handler,
        "show_text_viewer",
        lambda **kwargs: captured.update(kwargs),
    )
    monkeypatch.setattr(handler, "prompt_for_choice", lambda **kwargs: "yes")

    handler.start_domain_helper(handler.helper_.mobile_helper)

    assert captured["title"] == "Mobile Helper"
    assert "static analysis on a mobile application" in captured["body"]
    assert "workflow guidance" in captured["prompt"].lower()
