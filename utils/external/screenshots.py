"""
screenshots.py — Capture screenshots of alive web hosts using gowitness.

Falls back silently when gowitness is missing; the rest of the pipeline keeps
running without the screenshots artifact.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from utils.shared.commands import Commands


GOWITNESS_BIN = "gowitness"


class Screenshotter:
    """Capture website screenshots into a per-run directory."""

    def __init__(self) -> None:
        self.command = Commands()

    def capture(self, alive_urls_file: Path, output_dir: Path) -> dict:
        """Run gowitness against the URLs in *alive_urls_file*.

        Args:
            alive_urls_file: File containing one URL per line.
            output_dir:      Run directory; screenshots land in <output>/screenshots.

        Returns:
            Dict with the screenshot directory path, the count of images, and
            a "missing" key when gowitness is not installed.
        """
        if not alive_urls_file or not alive_urls_file.exists():
            return {"directory": None, "count": 0}

        if shutil.which(GOWITNESS_BIN) is None:
            return {"directory": None, "count": 0, "missing": GOWITNESS_BIN}

        screenshots_dir = output_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            GOWITNESS_BIN,
            "file",
            "-f", str(alive_urls_file),
            "-P", str(screenshots_dir),
            "--disable-db",
        ]
        self.command.execute_command(cmd)

        images = list(screenshots_dir.glob("*.png"))
        return {
            "directory": screenshots_dir if images else None,
            "count": len(images),
        }
