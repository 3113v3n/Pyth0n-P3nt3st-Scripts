import pytest

from handlers.file_selection_mixin import FileSelectionMixin
from handlers.navigation import BackToPreviousMenu
from handlers.opentui_menu import MenuOption


class _FileSelectionHarness(FileSelectionMixin):
    INFO = ""
    ENDC = ""

    def __init__(self):
        self.files = []
        self.display_options_called = False

    def print_error_message(self, *args, **kwargs):
        return None

    def print_info_message(self, *args, **kwargs):
        return None

    def get_last_unresponsive_ip(self, filepath):
        return None

    def _display_file_options(self):
        self.display_options_called = True
        return super()._display_file_options()


def test_index_out_of_range_display_uses_filename_and_full_path_in_opentui(monkeypatch):
    import handlers.file_selection_mixin as file_selection_module

    harness = _FileSelectionHarness()
    captured = {}

    monkeypatch.setattr(file_selection_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)

    def fake_menu(**kwargs):
        captured["options"] = kwargs["options"]
        return MenuOption("report.csv", 1)

    monkeypatch.setattr(file_selection_module, "run_opentui_menu", fake_menu)

    index = harness.index_out_of_range_display(
        "Choose file",
        [
            {"filename": "report.csv", "full_path": "/tmp/output/report.csv"},
            {"filename": "hosts.csv", "full_path": "/tmp/output/hosts.csv"},
        ],
    )

    assert index == 1
    assert [(opt.label, opt.description, opt.badge) for opt in captured["options"]] == [
        ("report.csv", "/tmp/output/report.csv", "1"),
        ("hosts.csv", "/tmp/output/hosts.csv", "2"),
    ]


def test_index_out_of_range_display_esc_raises_back_to_previous_menu(monkeypatch):
    import handlers.file_selection_mixin as file_selection_module

    harness = _FileSelectionHarness()
    monkeypatch.setattr(file_selection_module, "ensure_opentui_menu_enabled", lambda **kwargs: None)
    monkeypatch.setattr(
        file_selection_module,
        "run_opentui_menu",
        lambda **kwargs: (_ for _ in ()).throw(BackToPreviousMenu()),
    )

    with pytest.raises(BackToPreviousMenu):
        harness.index_out_of_range_display(
            "Choose file",
            [
                {"filename": "report.csv", "full_path": "/tmp/output/report.csv"},
                {"filename": "hosts.csv", "full_path": "/tmp/output/hosts.csv"},
            ],
        )


def test_index_out_of_range_display_requires_opentui(monkeypatch):
    import handlers.file_selection_mixin as file_selection_module

    harness = _FileSelectionHarness()
    monkeypatch.setattr(
        file_selection_module,
        "ensure_opentui_menu_enabled",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("OpenTUI required")),
    )

    with pytest.raises(RuntimeError, match="OpenTUI required"):
        harness.index_out_of_range_display(
            "Choose file",
            [
                {"filename": "report.csv", "full_path": "/tmp/output/report.csv"},
                {"filename": "hosts.csv", "full_path": "/tmp/output/hosts.csv"},
            ],
        )


def test_display_saved_files_relies_on_opentui_selection_without_preprinting(monkeypatch):
    harness = _FileSelectionHarness()

    monkeypatch.setattr(
        harness,
        "find_files",
        lambda path: harness.files.extend(
            [
                {"filename": "one.csv", "full_path": "/tmp/output/one.csv"},
                {"filename": "two.csv", "full_path": "/tmp/output/two.csv"},
            ]
        ),
    )
    monkeypatch.setattr(
        harness,
        "_get_filtered_files",
        lambda **kwargs: list(harness.files),
    )
    monkeypatch.setattr(
        harness,
        "_handle_analysis",
        lambda **kwargs: (harness.files, 1),
    )

    selected = harness.display_saved_files("/tmp/output", scan_extension="csv")

    assert selected == (harness.files, 1)
    assert harness.display_options_called is False
