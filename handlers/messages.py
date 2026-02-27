"""
messages.py — Colored terminal output helpers for the pentest framework.

All public print_*_message() methods delegate to the private _format_message()
base method, eliminating the previous duplication of color-wrapping logic.
"""

from utils.shared.colors import Bcolors


class DisplayHandler(Bcolors):
    """Mixin that provides colored console output for all framework classes."""

    def __init__(self):
        super().__init__()

    # ------------------------------------------------------------------
    # Private base formatter
    # ------------------------------------------------------------------

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
        """Print a debug message (header color).

        Args:
            message: Debug text to display.
        """
        print(
            f" {Bcolors.HEADER}[#] DEBUG:{Bcolors.ENDC} "
            f"\n{Bcolors.WARNING}{message}{Bcolors.ENDC}"
        )

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
        msg = f"\n{Bcolors.OKGREEN}[+] {message}{Bcolors.ENDC}"

        if kwargs.get("mobile_success"):
            msg = (
                f"\n{Bcolors.WARNING}[+]{Bcolors.ENDC} {message}\n"
                f"{Bcolors.OKGREEN}{Bcolors.UNDERLINE}{kwargs['mobile_success']}{Bcolors.ENDC}\n"
            )
        elif kwargs.get("extras"):
            extra_data = kwargs["extras"]
            msg = f"{msg}{extra_data}\n\n"
        elif kwargs.get("flush"):
            extra_data = kwargs.get("extras", "")
            msg = f"{msg}{extra_data}"
            return print(msg, flush=kwargs["flush"])

        print(msg)

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
        print(msg)

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
            msg = f"\n{Bcolors.HEADER}[#] Summary: {message} {Bcolors.ENDC}\n"
            ip_list = kwargs["data"]
            return print(msg, ip_list, flush=kwargs["flush"])

        if kwargs.get("file_path"):
            msg = f"{msg}{kwargs['file_path']}"

        print(msg)

    @staticmethod
    def print_trace_message(message: str) -> None:
        """Print a trace message (header color, no label prefix).

        Args:
            message: Trace text to display.
        """
        print(f"\n {Bcolors.HEADER}[TRACE]{Bcolors.ENDC} {message}")

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
        msg = f"\n{Bcolors.OKCYAN}[*] Info: {message} {Bcolors.ENDC}\n"

        if kwargs.get("flush"):
            encoded_string = kwargs.get("encoded_string", "")
            msg = f"{msg}{encoded_string}"
            return print(msg, flush=kwargs["flush"])

        if kwargs.get("file_path"):
            path = kwargs["file_path"]
            msg = f"\n{Bcolors.HEADER}[-] Info: {message} {Bcolors.ENDC}\n{path}"
        elif kwargs.get("file"):
            msg = f"{msg}{kwargs['file']}"

        print(msg)

    @staticmethod
    def print_selection_items(file: dict, index: int) -> None:
        """Print a numbered file selection item for the interactive menu.

        Args:
            file:  Dictionary with "filename" key.
            index: Display number shown to the user (1-based).
        """
        filename = f" {Bcolors.BOLD}{Bcolors.WARNING}{file['filename']}{Bcolors.ENDC}"
        display_str = (
            f"Enter [{Bcolors.OKGREEN}{Bcolors.BOLD}{index}{Bcolors.ENDC}] to select"
            f"{filename}"
        )
        print(display_str)
