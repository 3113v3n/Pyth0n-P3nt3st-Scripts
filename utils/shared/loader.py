from itertools import cycle
from shutil import get_terminal_size
from threading import Thread, Event
from time import sleep
from typing import Optional


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
                 spinner_type: str = "dots"

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

    def start(self):
        """Start Animation"""
        if self._thread is None or not self._thread.is_alive():
            self._done.clear()
            self._thread = Thread(target=self._animate, daemon=True)
            self._thread.start()

    def _animate(self) -> None:
        spinner_cycle = cycle(self.spinner)
        while not self._done.is_set():
            frame = next(spinner_cycle)
            # Use \r to return to start of the line
            output = f"\r{self.desc} {frame} "
            print(output, flush=True, end="")
            sleep(self.timeout)
        print(f"\r{self.end}", flush=True)

    def stop(self):
        """Stop Animation"""
        self._done.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.timeout * 2)
