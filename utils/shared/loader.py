from itertools import cycle
from shutil import get_terminal_size
from threading import Event, Thread
from time import sleep
from typing import Optional

from .colors import Bcolors


def _display_handler_suppressed() -> bool:
    """Return True when interactive output should be captured instead of printed."""
    try:
        from handlers.messages import DisplayHandler

        return DisplayHandler.stdout_suppressed()
    except Exception:
        return False


def _note_screen_output(message: str) -> None:
    """Best-effort bridge to the shared transcript used by TUI viewers."""
    try:
        from handlers.screen import ScreenHandler

        ScreenHandler.note_output_rendered(message)
    except Exception:
        pass


class Loader:
    """
        A loader-like context manager

        Args:
            desc (str, optional): The loader's description. Default to "Loading...".
            end (str, optional): Final print. Default to "Done!"
            timeout (float, optional): Sleep time between prints. Default to 0.1.
    """

    DEFAULT_SPINNER = {
        "dots": ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"],
        "line": ["⣷", "⣯", "⣟", "⡿"],
        "pipe": ["┤", "┘", "┴", "└", "├", "┌", "┬", "┐"],
        "simple": ["-", "\\", "|", "/"],
        "arc": ["◐", "◓", "◑", "◒"],
        "circle": ["◡", "⊙", "◠", "⊕"],
        'bounce': ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈'],

    }

    def __init__(self,
                 desc: str = "Loading...",
                 end: str = "Done!",
                 timeout: float = 0.1,
                 timer: int = 10,
                 spinner_type: str = "dots",
                 continuous=True
                 ):

        self.desc = desc
        self.end = end
        self.timeout = max(0.1, timeout)
        self.spinner = self.DEFAULT_SPINNER.get(
            spinner_type, self.DEFAULT_SPINNER["dots"])

        self._done = Event()
        self._thread: Optional[Thread] = None
        self._cols = get_terminal_size((80, 20)).columns
        self.timer = timer
        self.continuous = continuous
        self._suppressed_capture = False
        self._suppressed_end_recorded = False

    def start(self):
        """Start Animation"""
        if _display_handler_suppressed():
            self._suppressed_capture = True
            self._suppressed_end_recorded = False
            if self.desc:
                _note_screen_output(self.desc)
            return

        if self._thread is None or not self._thread.is_alive():
            self._done.clear()
            self._thread = Thread(target=self._animate, daemon=True)
            self._thread.start()

    def _animate(self) -> None:
        try:
            spinner_cycle = cycle(self.spinner)
            # Continuous loading until explicitly stopped
            if self.continuous:
                while not self._done.is_set():
                    frame = next(spinner_cycle)
                    output = f"\033[F\033[G{Bcolors.INFO}{self.desc}{Bcolors.ENDC} {frame} "
                    print(output, flush=True, end="")
                    sleep(self.timeout)

            else:
                # Timed loading
                for _ in range(self.timer):
                    if self._done.is_set():
                        break

                    frame = next(spinner_cycle)
                    # print(f"\033[F\033[G{self.desc} {frame} ",
                    #       flush=True, end="")
                    print(
                        f"\r{Bcolors.INFO}{self.desc}{Bcolors.ENDC} {frame} ", flush=True, end="")
                    sleep(self.timeout)
                self._done.set()

        finally:
            # Clear the line and print end message
            print("\r" + " " * self._cols, end="", flush=True)
            if self.end:
                print(f"\r{Bcolors.SUCCESS}{self.end}{Bcolors.ENDC}", flush=True)

    def stop(self):
        """Stop Animation"""
        if self._suppressed_capture:
            self._done.set()
            if self.end and not self._suppressed_end_recorded:
                _note_screen_output(self.end)
                self._suppressed_end_recorded = True
            self._suppressed_capture = False
            return

        self._done.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.timeout * 2)
