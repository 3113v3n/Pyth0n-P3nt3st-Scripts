from itertools import cycle
from shutil import get_terminal_size
from threading import Thread, Event
from time import sleep
from typing import Optional
from .colors import Bcolors


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

    def start(self):
        """Start Animation"""
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
                    output = f"\033[F\033[G{Bcolors.OKCYAN}{self.desc}{Bcolors.ENDC} {frame} "
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
                        f"\r{Bcolors.OKCYAN}{self.desc}{Bcolors.ENDC} {frame} ", flush=True, end="")
                    sleep(self.timeout)
                self._done.set()

        finally:
            # Clear the line and print end message
            print("\r" + " " * self._cols, end="", flush=True)
            if self.end:
                print(f"\r{Bcolors.OKGREEN}{self.end}{Bcolors.ENDC}", flush=True)

    def stop(self):
        """Stop Animation"""
        self._done.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.timeout * 2)
