import os
import sys


_TERM = os.environ.get("TERM", "")
_FORCE_COLOR = os.environ.get("FORCE_COLOR", "").strip() not in {"", "0", "false", "False"}
_COLOR_ENABLED = (
    _FORCE_COLOR
    or (
        os.environ.get("NO_COLOR") is None
        and _TERM not in {"", "dumb"}
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )
)


def _ansi(code: str) -> str:
    return f"\033[{code}m" if _COLOR_ENABLED else ""


class Bcolors:
    """Terminal palette optimized for readability with semantic aliases."""

    # Text styles
    ENDC = _ansi("0")
    BOLD = _ansi("1")
    UNDERLINE = _ansi("4")
    ITALICS = _ansi("3")

    # Semantic colors (ANSI-256 tuned for dark terminals)
    INFO = _ansi("38;5;39")         # Blue-cyan
    SUCCESS = _ansi("38;5;46")      # Green
    WARNING = _ansi("38;5;220")     # Amber
    FAIL = _ansi("38;5;196")        # Red
    CRITICAL = _ansi("1;38;5;15;48;5;160")  # White on deep red
    DEBUG = _ansi("38;5;244")       # Muted gray
    TRACE = _ansi("38;5;117")       # Soft azure
    HIGHLIGHT = _ansi("1;38;5;51")  # Bright cyan
    MUTED = _ansi("38;5;244")

    # Backward-compatible aliases used across the codebase
    HEADER = HIGHLIGHT
    OKBLUE = _ansi("38;5;33")
    OKCYAN = INFO
    OKGREEN = SUCCESS
