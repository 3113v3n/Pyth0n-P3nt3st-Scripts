"""Tool lookup helpers for external assessment binaries."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOOLS_BIN = PROJECT_ROOT / "tools" / "bin"
MACPORTS_BIN_DIRS = ("/opt/local/bin", "/opt/local/sbin")


def ensure_tools_path() -> None:
    """Prepend repo-local and MacPorts tool dirs so binaries are discoverable."""
    current = os.environ.get("PATH", "")
    entries = current.split(os.pathsep) if current else []
    for path in reversed((str(TOOLS_BIN), *MACPORTS_BIN_DIRS)):
        if path not in entries:
            entries.insert(0, path)
    os.environ["PATH"] = os.pathsep.join(entries)


def which_tool(*names: str) -> str | None:
    """Return the first available executable path for one or more tool names."""
    ensure_tools_path()
    for name in names:
        if not name:
            continue
        local = TOOLS_BIN / name
        if local.exists() and os.access(local, os.X_OK):
            return str(local)
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def available_name(*names: str) -> str | None:
    """Return the command name/path that should be executed for aliases."""
    return which_tool(*names)
