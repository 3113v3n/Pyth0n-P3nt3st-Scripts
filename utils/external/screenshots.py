"""
screenshots.py — Capture screenshots of alive web hosts using gowitness.

Falls back silently when gowitness is missing; the rest of the pipeline keeps
running without the screenshots artifact.
"""

from __future__ import annotations

from pathlib import Path

from utils.shared.commands import Commands
from .tooling import available_name


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

        gowitness = available_name(GOWITNESS_BIN)
        if gowitness is None:
            return {"directory": None, "count": 0, "missing": GOWITNESS_BIN, "skipped": True}

        screenshots_dir = output_dir / "screenshots"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        command_candidates = self._build_command_candidates(
            gowitness,
            alive_urls_file,
            screenshots_dir,
        )
        for cmd in command_candidates:
            result = self.command.stream_command(cmd, prefix="[gowitness] ")
            if result.returncode == 0:
                break

        images = self._count_images(screenshots_dir)
        return {
            "directory": screenshots_dir if images else None,
            "count": len(images),
        }

    def _build_command_candidates(
        self,
        gowitness: str,
        alive_urls_file: Path,
        screenshots_dir: Path,
    ) -> list[list[str]]:
        """Return gowitness command variants ordered by likely local version."""
        modern = [
            gowitness,
            "scan",
            "file",
            "-f", str(alive_urls_file),
            "-s", str(screenshots_dir),
            "--screenshot-format", "png",
        ]
        legacy = [
            gowitness,
            "file",
            "-f", str(alive_urls_file),
            "-P", str(screenshots_dir),
            "--disable-db",
        ]
        help_text = self.command.get_process_output([gowitness, "--help"]).lower()
        if "scan" in help_text:
            return [modern, legacy]
        return [legacy, modern]

    @staticmethod
    def _count_images(screenshots_dir: Path) -> list[Path]:
        images: list[Path] = []
        for ext in ("*.png", "*.jpg", "*.jpeg"):
            images.extend(screenshots_dir.glob(ext))
        return images
