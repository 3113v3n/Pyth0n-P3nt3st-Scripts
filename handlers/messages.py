"""
messages.py — Colored terminal output helpers for the pentest framework.

All public print_*_message() methods delegate to the private _format_message()
base method, eliminating the previous duplication of color-wrapping logic.
"""

from utils.shared.colors import Bcolors


class DisplayHandler(Bcolors):
    """Mixin that provides colored console output for all framework classes."""

    _stdout_suppressed = False

    def __init__(self):
        super().__init__()

    # ------------------------------------------------------------------
    # Private base formatter
    # ------------------------------------------------------------------

    @staticmethod
    def _note_screen_output(output: str | int) -> None:
        """Best-effort bridge to ScreenHandler visibility tracking."""
        try:
            from handlers.screen import ScreenHandler
            ScreenHandler.note_output_rendered(output)
        except Exception:
            pass

    @classmethod
    def set_stdout_suppressed(cls, suppressed: bool) -> None:
        DisplayHandler._stdout_suppressed = bool(suppressed)

    @classmethod
    def stdout_suppressed(cls) -> bool:
        return bool(DisplayHandler._stdout_suppressed)

    @classmethod
    def _emit_message(cls, message: str, *, flush: bool = False) -> None:
        if not cls.stdout_suppressed():
            if flush:
                print(message, flush=True)
            else:
                print(message)
        cls._note_screen_output(message)

    @staticmethod
    def _format_message(
        prefix: str,
        color_start: str,
        message: str,
        suffix: str = "",
    ) -> str:
        """Build a color-wrapped message string.

        Args:
            prefix:      Label shown before the message, e.g. "[+]".
            color_start: ANSI color escape sequence to open.
            message:     The text body.
            suffix:      Optional trailing text appended after the color reset.

        Returns:
            Formatted string ready for printing.
        """
        # [Redundancy] Single source of truth for color-wrapping logic that was
        # previously repeated across all 7 print methods.
        return f"\n{color_start}{prefix} {message}{Bcolors.ENDC}{suffix}"

    # ------------------------------------------------------------------
    # Public print methods
    # ------------------------------------------------------------------

    @staticmethod
    def print_debug_message(message: str) -> None:
        """Print a debug message (muted for low visual noise).

        Args:
            message: Debug text to display.
        """
        debug_msg = (
            f" {Bcolors.DEBUG}[#] DEBUG:{Bcolors.ENDC} "
            f"\n{Bcolors.MUTED}{message}{Bcolors.ENDC}"
        )
        DisplayHandler._emit_message(debug_msg)

    @staticmethod
    def print_success_message(message: str, **kwargs) -> None:
        """Print a success message (green).

        Args:
            message: Success text to display.
            kwargs:
                mobile_success (str): Directory path shown underlined below the message.
                extras (str):         Additional text appended inline.
                flush (bool):         If True, flush stdout immediately.
        """
        msg = f"\n{Bcolors.SUCCESS}[+] {message}{Bcolors.ENDC}"

        if kwargs.get("mobile_success"):
            msg = (
                f"\n{Bcolors.SUCCESS}[+]{Bcolors.ENDC} {message}\n"
                f"{Bcolors.SUCCESS}{Bcolors.UNDERLINE}{kwargs['mobile_success']}{Bcolors.ENDC}\n"
            )
        elif kwargs.get("extras"):
            extra_data = kwargs["extras"]
            msg = f"{msg}{extra_data}\n\n"
        elif kwargs.get("flush"):
            extra_data = kwargs.get("extras", "")
            msg = f"{msg}{extra_data}"
            DisplayHandler._emit_message(msg, flush=kwargs["flush"])
            return

        DisplayHandler._emit_message(msg)

    @staticmethod
    def print_error_message(message: str = "Error", **kwargs) -> None:
        """Print an error message (red).

        Args:
            message: Error description.
            kwargs:
                exception_error: Exception instance or string to display.
        """
        if kwargs.get("exception_error"):
            error = kwargs["exception_error"]
            msg = f"\n{Bcolors.FAIL}[!] {message}: {error}{Bcolors.ENDC}"
        else:
            msg = f"\n{Bcolors.FAIL}[!] Error: {message} {Bcolors.ENDC}"
        DisplayHandler._emit_message(msg)

    @staticmethod
    def print_warning_message(message: str, **kwargs) -> None:
        """Print a warning message (yellow).

        Args:
            message: Warning text.
            kwargs:
                flush (bool): Flush stdout; also requires a *data* list.
                data (list):  IP list printed alongside the summary header.
                file_path (str): File path appended after the message.
        """
        msg = f"\n{Bcolors.WARNING}[-] Warning: {message} {Bcolors.ENDC}\n"

        if kwargs.get("flush"):
            msg = f"\n{Bcolors.HIGHLIGHT}[#] Summary: {message} {Bcolors.ENDC}\n"
            ip_list = kwargs["data"]
            DisplayHandler._emit_message(f"{msg} {ip_list}", flush=kwargs["flush"])
            return

        if kwargs.get("file_path"):
            msg = f"{msg}{kwargs['file_path']}"

        DisplayHandler._emit_message(msg)

    @staticmethod
    def print_trace_message(message: str) -> None:
        """Print a trace message (header color, no label prefix).

        Args:
            message: Trace text to display.
        """
        trace_msg = f"\n {Bcolors.TRACE}[TRACE]{Bcolors.ENDC} {message}"
        DisplayHandler._emit_message(trace_msg)

    @staticmethod
    def print_info_message(message: str, **kwargs) -> None:
        """Print an informational message (cyan).

        Args:
            message: Info text.
            kwargs:
                flush (bool):          Flush stdout; also requires *encoded_string*.
                encoded_string (str):  Appended after the message when flush is set.
                file_path (str):       File path shown on a separate line.
                file (str):            File being currently scanned (mobile module).
        """
        msg = f"\n{Bcolors.INFO}[*] Info: {message} {Bcolors.ENDC}\n"

        if kwargs.get("flush"):
            encoded_string = kwargs.get("encoded_string", "")
            msg = f"{msg}{encoded_string}"
            DisplayHandler._emit_message(msg, flush=kwargs["flush"])
            return

        if kwargs.get("file_path"):
            path = kwargs["file_path"]
            msg = f"\n{Bcolors.INFO}[-] Info: {message} {Bcolors.ENDC}\n{path}"
        elif kwargs.get("file"):
            msg = f"{msg}{kwargs['file']}"

        DisplayHandler._emit_message(msg)

    @staticmethod
    def print_selection_items(file: dict, index: int) -> None:
        """Print a numbered file selection item for the interactive menu.

        Args:
            file:  Dictionary with "filename" key.
            index: Display number shown to the user (1-based).
        """
        filename = f" {Bcolors.BOLD}{Bcolors.WARNING}{file['filename']}{Bcolors.ENDC}"
        display_str = (
            f"Enter [{Bcolors.INFO}{Bcolors.BOLD}{index}{Bcolors.ENDC}] to select"
            f"{filename}"
        )
        DisplayHandler._emit_message(display_str)
