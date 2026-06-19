import pytest

from handlers.navigation import BackToPreviousMenu
from handlers.opentui_menu import MenuOption
from handlers.screen import ScreenHandler


def test_create_menu_selection_uses_scanner_alias_as_description(monkeypatch):
    import handlers.screen as screen_module

    captured = {}
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_menu(**kwargs):
        captured["options"] = kwargs["options"]
        return MenuOption("Rapid7 Scanner", 1, "rapid")

    monkeypatch.setattr(screen_module, "run_opentui_menu", fake_menu)

    selected = ScreenHandler.create_menu_selection(
        menu_selection="Select scanner",
        options=[
            {"name": "Nessus Scanner", "alias": "nessus"},
            {"name": "Rapid7 Scanner", "alias": "rapid"},
        ],
        check_range_string="Scanner: ",
        check_range_function=lambda prompt, options: 0,
        start_color="",
        end_color="",
        scanner=True,
    )

    assert selected == 1
    assert [(opt.label, opt.description, opt.badge) for opt in captured["options"]] == [
        ("Nessus Scanner", "nessus", "1"),
        ("Rapid7 Scanner", "rapid", "2"),
    ]


def test_create_menu_selection_uses_uppercase_labels_for_plain_options(monkeypatch):
    import handlers.screen as screen_module

    captured = {}
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_menu(**kwargs):
        captured["options"] = kwargs["options"]
        return MenuOption("BOTH", 2)

    monkeypatch.setattr(screen_module, "run_opentui_menu", fake_menu)

    selected = ScreenHandler.create_menu_selection(
        menu_selection="Select format",
        options=["csv", "xlsx", "both"],
        check_range_string="File Format: ",
        check_range_function=lambda prompt, options: 0,
        start_color="",
        end_color="",
    )

    assert selected == 2
    assert [(opt.label, opt.description, opt.badge) for opt in captured["options"]] == [
        ("CSV", "", "1"),
        ("XLSX", "", "2"),
        ("BOTH", "", "3"),
    ]


def test_create_menu_selection_esc_raises_back_to_previous_menu(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        screen_module,
        "run_opentui_menu",
        lambda **kwargs: (_ for _ in ()).throw(BackToPreviousMenu()),
    )

    with pytest.raises(BackToPreviousMenu):
        ScreenHandler.create_menu_selection(
            menu_selection="Select format",
            options=["csv", "xlsx", "both"],
            check_range_string="File Format: ",
            check_range_function=lambda prompt, options: 0,
            start_color="",
            end_color="",
        )


def test_create_menu_selection_requires_opentui(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(
        screen_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("OpenTUI required")),
    )

    with pytest.raises(RuntimeError, match="OpenTUI required"):
        ScreenHandler.create_menu_selection(
            menu_selection="Select format",
            options=["csv", "xlsx", "both"],
            check_range_string="File Format: ",
            check_range_function=lambda prompt, options: 0,
            start_color="",
            end_color="",
        )


def test_prompt_for_choice_uses_opentui_metadata_and_returns_canonical_value(monkeypatch):
    import handlers.screen as screen_module

    captured = {}
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_menu(**kwargs):
        captured["title"] = kwargs["title"]
        captured["options"] = kwargs["options"]
        return kwargs["options"][1]

    monkeypatch.setattr(screen_module, "run_opentui_menu", fake_menu)

    handler = ScreenHandler()
    selected = handler.prompt_for_choice(
        title="Mobile",
        prompt="Select taxonomy profile",
        choices=[
            {
                "value": "balanced",
                "label": "Balanced",
                "description": "Recommended defaults for most app triage runs",
                "aliases": ("b",),
            },
            {
                "value": "strict",
                "label": "Strict",
                "description": "Fewer false positives with conservative matching",
                "aliases": ("s",),
            },
        ],
        default="balanced",
    )

    assert selected == "strict"
    assert captured["title"] == "Mobile"
    assert [(opt.label, opt.description, opt.badge) for opt in captured["options"]] == [
        ("Balanced", "Recommended defaults for most app triage runs", "1"),
        ("Strict", "Fewer false positives with conservative matching", "2"),
    ]


def test_prompt_for_choice_esc_raises_back_to_previous_menu(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        screen_module,
        "run_opentui_menu",
        lambda **kwargs: (_ for _ in ()).throw(BackToPreviousMenu()),
    )

    handler = ScreenHandler()
    with pytest.raises(BackToPreviousMenu):
        handler.prompt_for_choice(
            title="Mobile",
            prompt="Select scan mode",
            choices=[
                {"value": "single", "label": "Single", "aliases": ("s",)},
                {"value": "all", "label": "All", "aliases": ("a",)},
            ],
            default="single",
        )


def test_prompt_for_choice_requires_opentui(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(
        screen_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("OpenTUI required")),
    )

    handler = ScreenHandler()
    with pytest.raises(RuntimeError, match="OpenTUI required"):
        handler.prompt_for_choice(
            title="Mobile",
            prompt="Select scan mode",
            choices=[
                {"value": "single", "label": "Single", "aliases": ("s",)},
                {"value": "all", "label": "All", "aliases": ("a",)},
            ],
            default="single",
        )


def test_prompt_format_uses_text_input_and_normalizes_non_path_values(monkeypatch):
    import handlers.screen as screen_module

    captured = {}
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        screen_module,
        "run_opentui_text_input",
        lambda **kwargs: captured.update(kwargs) or " Example.COM ",
    )

    handler = ScreenHandler()
    result = handler.prompt_format("Enter domain")

    assert result == "example.com"
    assert captured["title"] == "Input"
    assert "freeform text" in captured["subtitle"].lower()


def test_prompt_format_preserves_case_for_paths_and_filenames(monkeypatch):
    import handlers.screen as screen_module

    calls = []
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_input(**kwargs):
        calls.append(kwargs)
        return " /Tmp/Reports/CaseFile.TXT " if kwargs["title"] == "Path Input" else " Findings.Report "

    monkeypatch.setattr(screen_module, "run_opentui_text_input", fake_input)

    handler = ScreenHandler()
    path_value = handler.prompt_format("Enter path", path=True)
    filename_value = handler.prompt_format("Enter filename", filename=True)

    assert path_value == "/Tmp/Reports/CaseFile.TXT"
    assert filename_value == "Findings.Report"
    assert [call["title"] for call in calls] == ["Path Input", "Filename Input"]


def test_prompt_format_esc_raises_back_to_previous_menu(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        screen_module,
        "run_opentui_text_input",
        lambda **kwargs: (_ for _ in ()).throw(BackToPreviousMenu()),
    )

    handler = ScreenHandler()
    with pytest.raises(BackToPreviousMenu):
        handler.prompt_format("Enter domain")


def test_prompt_for_multi_choice_returns_selected_values(monkeypatch):
    import handlers.screen as screen_module

    captured = {}
    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_multi(**kwargs):
        captured.update(kwargs)
        return ("recon", "vulns")

    monkeypatch.setattr(screen_module, "run_opentui_multi_select", fake_multi)

    handler = ScreenHandler()
    result = handler.prompt_for_multi_choice(
        title="External",
        prompt="Select phases",
        choices=[
            {"value": "recon", "label": "Recon", "description": "Discovery", "meta": "Default phase order"},
            {"value": "vulns", "label": "Vulns", "description": "Nuclei and checks", "meta": "Default phase order"},
        ],
        default_values=("recon", "vulns"),
    )

    assert result == ("recon", "vulns")
    assert captured["selected_values"] == ("recon", "vulns")
    assert [opt.label for opt in captured["options"]] == ["Recon", "Vulns"]


def test_prompt_for_multi_choice_esc_raises_back_to_previous_menu(monkeypatch):
    import handlers.screen as screen_module

    monkeypatch.setattr(screen_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        screen_module,
        "run_opentui_multi_select",
        lambda **kwargs: (_ for _ in ()).throw(BackToPreviousMenu()),
    )

    handler = ScreenHandler()
    with pytest.raises(BackToPreviousMenu):
        handler.prompt_for_multi_choice(
            title="External",
            prompt="Select phases",
            choices=[{"value": "recon", "label": "Recon"}],
        )
