try:
    import readline  # noqa: F401  # Enables history/arrow navigation in input()
except Exception:  # pragma: no cover - platform dependent
    readline = None
else:  # pragma: no cover - runtime capability
    try:
        readline.parse_and_bind("set editing-mode emacs")
        readline.parse_and_bind(r'"\e[A": previous-history')
        readline.parse_and_bind(r'"\e[B": next-history')
    except Exception:
        pass

import os
import re
import shutil
import textwrap
from collections.abc import Callable

from utils.shared.loader import Loader

from .messages import DisplayHandler
from .navigation import BackToPreviousMenu, check_navigation_command, sanitize_dialog_input
from .opentui_menu import (
    build_menu_options,
    ensure_opentui_menu_enabled,
    run_opentui_menu,
    run_opentui_multi_select,
    run_opentui_progress_display,
    run_opentui_text_input,
    run_opentui_text_viewer,
)


class ScreenHandler(DisplayHandler):
    NAVIGATION_HINT = (
        "Navigation: back=previous menu | main=Menu 1 | Up/Down=history | Ctrl+C=exit"
    )
    _nav_hint_visible = False
    _lines_since_nav_hint = 10**9
    _ansi_escape_re = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    _output_transcript: list[str] = []

    def __init__(self):
        super().__init__()

    @classmethod
    def _terminal_size(cls) -> os.terminal_size:
        return shutil.get_terminal_size((120, 40))

    @classmethod
    def _estimate_rendered_lines(cls, text: str) -> int:
        sample = cls._ansi_escape_re.sub("", str(text or ""))
        if not sample:
            return 1
        columns = max(20, cls._terminal_size().columns)
        lines = 0
        for raw_line in sample.splitlines() or [sample]:
            wrapped = textwrap.wrap(
                raw_line if raw_line else " ",
                width=columns,
                break_long_words=True,
                break_on_hyphens=False,
            )
            lines += max(1, len(wrapped))
        return max(1, lines)

    @classmethod
    def note_output_rendered(cls, text_or_line_count: str | int) -> None:
        """Track approximate output line usage to infer hint visibility."""
        state_cls = ScreenHandler
        if isinstance(text_or_line_count, str):
            sanitized = state_cls._ansi_escape_re.sub("", str(text_or_line_count or "")).strip()
            if sanitized:
                state_cls._output_transcript.append(sanitized)
        if not state_cls._nav_hint_visible:
            return
        if isinstance(text_or_line_count, int):
            consumed = max(0, text_or_line_count)
        else:
            consumed = state_cls._estimate_rendered_lines(text_or_line_count)
        state_cls._lines_since_nav_hint += consumed

        # If output likely exceeded the viewport, consider hint no longer visible.
        viewport_rows = max(6, state_cls._terminal_size().lines)
        if state_cls._lines_since_nav_hint >= max(2, viewport_rows - 2):
            state_cls._nav_hint_visible = False

    @classmethod
    def clear_output_transcript(cls) -> None:
        ScreenHandler._output_transcript = []

    @classmethod
    def consume_output_transcript(cls) -> str:
        transcript = "\n\n".join(ScreenHandler._output_transcript).strip()
        ScreenHandler._output_transcript = []
        return transcript

    @classmethod
    def note_screen_cleared(cls) -> None:
        """Reset hint visibility when terminal is explicitly cleared."""
        state_cls = ScreenHandler
        state_cls._nav_hint_visible = False
        state_cls._lines_since_nav_hint = 10**9

    @classmethod
    def show_navigation_hint(cls, *, force: bool = False) -> None:
        state_cls = ScreenHandler
        if not force and state_cls._nav_hint_visible:
            return
        hint_line = f"[Navigation] {state_cls.NAVIGATION_HINT}"
        state_cls._emit_message(f"\n{state_cls.MUTED}{hint_line}{state_cls.ENDC}")
        state_cls._nav_hint_visible = True
        state_cls._lines_since_nav_hint = state_cls._estimate_rendered_lines(hint_line) + 1

    @staticmethod
    def create_menu_selection(
            menu_selection: str,
            options: list | tuple,
            check_range_string: str,
            check_range_function: callable,
            start_color: str,
            end_color: str,
            **kwargs):
        if not options:
            raise ValueError("create_menu_selection requires at least one option")
        ensure_opentui_menu_enabled(context="interactive menu selection")
        tui_options = build_menu_options(
            list(options),
            label_getter=lambda option, _index: (
                option["name"] if "scanner" in kwargs else str(option).upper()
            ),
            value_getter=lambda _option, index: index,
            description_getter=lambda option, _index: (
                option.get("alias", "") if "scanner" in kwargs else ""
            ),
            badge_getter=lambda _option, index: str(index + 1),
            meta_getter=lambda option, _index: (
                f"Scanner alias: {option.get('alias', '')}" if "scanner" in kwargs else ""
            ),
        )
        selected = run_opentui_menu(
            title="Selection",
            prompt=sanitize_dialog_input(menu_selection) or check_range_string,
            options=tui_options,
            footer="↑/↓ or j/k navigate • number keys jump • Enter selects • Esc goes back",
            subtitle="Choose an item from the active workflow with a richer OpenTUI selector",
            cancel_raises=BackToPreviousMenu,
        )
        if selected is None:
            raise RuntimeError("OpenTUI selection ended without a choice")
        return int(selected.value)

    @staticmethod
    def show_loader(
            message: str,
            end_message: str,
            spinner_type: str = "dots",
            timer=10
    ):
        """Display Loading functionality to a user

        :param message: Message to display
        :param end_message: Message to display after loading complete
        :param spinner_type: Type of spinner to use
        :param timer: period for loader to display
        """
        loader = Loader(
            desc=message,
            end=end_message,
            spinner_type=spinner_type,
            timer=timer
        )
        loader.start()
        # if continuous:
        #     return loader  # return loader only for continuous loading

        return None

    @staticmethod
    def show_text_viewer(
        *,
        title: str,
        prompt: str,
        body: str,
        subtitle: str = "",
        footer: str = "↑/↓ or j/k scroll • PgUp/PgDn page • Enter/Esc close",
    ) -> None:
        ensure_opentui_menu_enabled(context=f"the '{title}' helper viewer")
        run_opentui_text_viewer(
            title=title,
            prompt=prompt,
            body=body,
            subtitle=subtitle,
            footer=footer,
        )

    @staticmethod
    def show_progress_viewer(
        *,
        title: str,
        prompt: str,
        subtitle: str,
        snapshot_getter: Callable[[], dict],
        worker: Callable[[], object],
        footer: str = "Esc/q requests a graceful stop • final results open after completion",
        cancel: Callable[[], object] | None = None,
    ) -> dict:
        ensure_opentui_menu_enabled(context=f"the '{title}' progress viewer")
        return run_opentui_progress_display(
            title=title,
            prompt=prompt,
            subtitle=subtitle,
            snapshot_getter=snapshot_getter,
            worker=worker,
            footer=footer,
            cancel=cancel,
        )

    def get_file_path(
        self,
        prompt: str,
        check_exists: callable,
        *,
        require_file: bool = False,
    ):
        """Get and validate a filesystem path from user."""

        while True:
            file_path = self.prompt_format(prompt, path=True)
            if not file_path:
                self.print_warning_message("Path cannot be empty")
                continue
            if not check_exists(file_path):
                self.print_error_message("No such file/folder exists")
                continue
            if require_file and not self.isfile_and_exists(file_path):
                self.print_error_message(
                    f"Expected a file path, but got a directory: {file_path}"
                )
                continue
            return file_path

    def get_output_filename(self, prompt: str = "\n[+] Please enter the output filename: "):
        """Get output filename from user"""

        while True:
            filename = self.prompt_format(prompt, filename=True)
            if not filename:
                self.print_warning_message("Filename cannot be empty")
                continue
            return filename

    def get_user_input(self, prompt: str, default: str | None = None):
        """Get user input
        :param prompt: Text to display to user
        : return user input
        """

        while True:
            user_input = self.prompt_format(prompt)
            if not user_input and default is not None:
                return default
            if not user_input:
                self.print_warning_message("Input cannot be empty")
                continue
            return user_input

    def prompt_for_choice(
            self,
            *,
            title: str,
            prompt: str,
            choices: list[dict],
            default: str | None = None,
            footer: str = "↑/↓ or j/k navigate • number keys jump • Enter selects • Esc goes back",
    ) -> str:
        """Return a canonical value for a small fixed set of keyword choices."""
        if not choices:
            raise ValueError("prompt_for_choice requires at least one choice")

        aliases_to_value: dict[str, str] = {}
        option_records: list[dict[str, str]] = []

        for index, choice in enumerate(choices, start=1):
            value = str(choice["value"]).strip().lower()
            label = str(choice.get("label", value)).strip()
            description = str(choice.get("description", "")).strip()
            aliases = {value}
            aliases.update(
                str(alias).strip().lower() for alias in choice.get("aliases", ()) if str(alias).strip()
            )
            for alias in aliases:
                aliases_to_value[alias] = value
            option_records.append(
                {
                    "value": value,
                    "label": label,
                    "description": description,
                    "badge": str(choice.get("badge", index)),
                }
            )

        ensure_opentui_menu_enabled(context=f"the '{title}' choice prompt")
        tui_options = build_menu_options(
            option_records,
            label_getter=lambda option, _index: option["label"],
            value_getter=lambda option, _index: option["value"],
            description_getter=lambda option, _index: option["description"],
            badge_getter=lambda option, _index: option["badge"],
            meta_getter=lambda option, _index: f"Keyword: {option['value']}",
        )
        selected = run_opentui_menu(
            title=title,
            prompt=sanitize_dialog_input(prompt) or prompt,
            options=tui_options,
            footer=footer,
            subtitle="Use the selector to review descriptions before committing to a branch in the workflow",
            cancel_raises=BackToPreviousMenu,
        )
        if selected is None:
            raise RuntimeError(f"OpenTUI prompt '{title}' ended without a selection")
        return aliases_to_value[str(selected.value).strip().lower()]

    def prompt_for_multi_choice(
            self,
            *,
            title: str,
            prompt: str,
            choices: list[dict],
            default_values: tuple[str, ...] = (),
            footer: str = "↑/↓ move • Space toggle • a select all • Enter confirm • Esc goes back",
    ) -> tuple[str, ...]:
        """Return canonical values for a multi-select choice set."""
        if not choices:
            raise ValueError("prompt_for_multi_choice requires at least one choice")

        option_records: list[dict[str, str]] = []
        for index, choice in enumerate(choices, start=1):
            option_records.append(
                {
                    "value": str(choice["value"]).strip().lower(),
                    "label": str(choice.get("label", choice["value"])).strip(),
                    "description": str(choice.get("description", "")).strip(),
                    "badge": str(choice.get("badge", index)),
                    "meta": str(choice.get("meta", "")).strip(),
                }
            )

        ensure_opentui_menu_enabled(context=f"the '{title}' multi-select prompt")
        tui_options = build_menu_options(
            option_records,
            label_getter=lambda option, _index: option["label"],
            value_getter=lambda option, _index: option["value"],
            description_getter=lambda option, _index: option["description"],
            badge_getter=lambda option, _index: option["badge"],
            meta_getter=lambda option, _index: option["meta"],
        )
        selected = run_opentui_multi_select(
            title=title,
            prompt=sanitize_dialog_input(prompt) or prompt,
            options=tui_options,
            selected_values=tuple(str(value).strip().lower() for value in default_values if str(value).strip()),
            footer=footer,
            subtitle="Toggle multiple workflow phases before continuing with the execution plan",
            cancel_raises=BackToPreviousMenu,
        )
        if selected is None:
            raise RuntimeError(f"OpenTUI multi-select '{title}' ended without a selection")
        return tuple(str(value).strip().lower() for value in selected)

    def prompt_format(self, prompt, **kwargs):
        prompt_text = sanitize_dialog_input(prompt) or str(prompt or "")
        ensure_opentui_menu_enabled(context=f"the prompt '{prompt_text[:32] or 'input'}'")

        title = "Input"
        subtitle = "Capture freeform text for the active workflow step."
        preserve_case = False
        footer = "Type to edit • ←/→ move • Enter submit • Esc go back"

        if kwargs.get('path'):
            title = "Path Input"
            subtitle = "Enter a filesystem path for the current workflow step."
            preserve_case = True
        elif kwargs.get('filename'):
            title = "Filename Input"
            subtitle = "Enter an output filename for the current workflow step."
            preserve_case = True

        user_input = run_opentui_text_input(
            title=title,
            prompt=prompt_text,
            subtitle=subtitle,
            footer=footer,
            cancel_raises=BackToPreviousMenu,
        )
        if user_input is None:
            raise RuntimeError(f"OpenTUI prompt '{title}' ended without input")

        sanitized = sanitize_dialog_input(user_input)
        check_navigation_command(sanitized)
        return sanitized if preserve_case else sanitized.lower()

    def validate_user_choice(
            self,
            options: set,
            get_user_input: callable,
            text: str,
            *,
            default: str | None = None,
    ):
        valid_options = options
        while True:
            try:
                response = get_user_input(text, default=default)
            except TypeError:
                response = get_user_input(text)
                if not response and default is not None:
                    response = default

            if response in valid_options:
                break  # Exit loop if response is valid
            else:
                self.print_warning_message(
                    f"Invalid choice: {response}.\n Please "
                    f"choose from: {self.BOLD}{valid_options}{self.ENDC}")
        return response

    @staticmethod
    def display_files_onscreen(
            directory: str,
            display_saved_files: callable,
            **kwargs) -> tuple:
        """Display files in directory with extension filter"""
        files = display_saved_files(
            directory,
            scan_extension=kwargs.get("scan_extension"),
            resume_scan=kwargs.get("resume_scan", False),
            display_applications=kwargs.get("display_applications", False)
        )
        if not files:
            raise FileNotFoundError(f"\n[!] No files found in {directory}")
        return files
