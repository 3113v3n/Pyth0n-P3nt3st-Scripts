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

import shutil
import textwrap
import os
import re

from .messages import DisplayHandler
from .navigation import check_navigation_command, sanitize_dialog_input
from utils.shared.loader import Loader


class ScreenHandler(DisplayHandler):
    NAVIGATION_HINT = (
        "Navigation: back=previous menu | main=Menu 1 | Up/Down=history | Ctrl+C=exit"
    )
    _nav_hint_visible = False
    _lines_since_nav_hint = 10**9
    _ansi_escape_re = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

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
        print(f"\n{state_cls.MUTED}{hint_line}{state_cls.ENDC}")
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
        print(menu_selection)
        ScreenHandler.note_output_rendered(menu_selection)
        for option in options:
            # Ensure both scanner menu and file extension are sorted for
            display_option = option["name"] if "scanner" in kwargs else option.upper(
            )
            option_line = (
                f" {start_color}[{options.index(option) + 1}]{end_color}"
                f" {display_option}"
            )
            print(option_line)
            ScreenHandler.note_output_rendered(option_line)
        return check_range_function(f"\n {check_range_string}", options)

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

    def prompt_format(self, prompt, **kwargs):
        decorator = "..." * 30
        dotted_lines = f"{self.MUTED}{decorator}{self.ENDC}"

        def not_lower():
            while True:
                self.show_navigation_hint()
                raw_input = input(prompt)
                self.note_output_rendered(prompt)
                self.note_output_rendered(raw_input)
                user_input = sanitize_dialog_input(raw_input)
                # Ignore raw arrow-key escape sequences when readline is unavailable.
                if not user_input and str(raw_input).startswith("\x1b"):
                    print(dotted_lines)
                    self.note_output_rendered(dotted_lines)
                    continue
                check_navigation_command(user_input)
                print(dotted_lines)
                self.note_output_rendered(dotted_lines)
                return user_input

        if kwargs.get('path'):
            return not_lower()

        if kwargs.get('filename'):
            return not_lower()

        while True:
            self.show_navigation_hint()
            raw_input = input(prompt)
            self.note_output_rendered(prompt)
            self.note_output_rendered(raw_input)
            sanitized = sanitize_dialog_input(raw_input)
            if not sanitized and str(raw_input).startswith("\x1b"):
                print(dotted_lines)
                self.note_output_rendered(dotted_lines)
                continue
            check_navigation_command(sanitized)
            user_input = sanitized.lower()
            print(dotted_lines)
            self.note_output_rendered(dotted_lines)
            return user_input

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
