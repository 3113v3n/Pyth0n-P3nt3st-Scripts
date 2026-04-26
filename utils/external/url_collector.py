"""
url_collector.py — Collect historical URLs (gauplus / waybackurls) and pull
out URLs that point at sensitive file extensions for follow-up review.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from utils.shared.commands import Commands
from .external_constants import GAUPLUS_THREADS, SENSITIVE_EXTENSION_RE


# Tool order: gauplus first (more sources), waybackurls as fallback.
URL_TOOL_PRIORITY = ("gauplus", "waybackurls")


class UrlCollector:
    """Aggregate historical URLs and surface sensitive file paths."""

    def __init__(self) -> None:
        self.command = Commands()

    def collect(self, hosts_file: Path, output_dir: Path) -> dict:
        """Run the first available URL collector against *hosts_file*.

        Args:
            hosts_file: Resolved hostnames or alive URLs (one per line).
            output_dir: Destination directory for the URL artifacts.

        Returns:
            Dict with keys: urls (path), sensitive (path), counts, tool, missing.
        """
        if not hosts_file or not hosts_file.exists():
            return {"urls": None, "sensitive": None, "url_count": 0, "sensitive_count": 0}

        tool = next((bin_ for bin_ in URL_TOOL_PRIORITY if shutil.which(bin_)), None)
        if tool is None:
            return {
                "urls": None,
                "sensitive": None,
                "url_count": 0,
                "sensitive_count": 0,
                "missing": "gauplus/waybackurls",
            }

        urls_path = output_dir / "historical_urls.txt"
        sensitive_path = output_dir / "sensitive_urls.txt"

        cmd = self._build_command(tool, hosts_file)
        with urls_path.open("w", encoding="utf-8") as out:
            self.command.run_os_commands(cmd, stdout=out)

        sensitive = self._filter_sensitive(urls_path)
        if sensitive:
            sensitive_path.write_text("\n".join(sensitive) + "\n", encoding="utf-8")

        url_count = self._line_count(urls_path)
        return {
            "urls": urls_path if urls_path.exists() else None,
            "sensitive": sensitive_path if sensitive else None,
            "url_count": url_count,
            "sensitive_count": len(sensitive),
            "tool": tool,
        }

    @staticmethod
    def _build_command(tool: str, hosts_file: Path) -> list[str]:
        if tool == "gauplus":
            return ["gauplus", "-t", str(GAUPLUS_THREADS), "-subs", "-random-agent", str(hosts_file)]
        return ["waybackurls", str(hosts_file)]

    @staticmethod
    def _filter_sensitive(urls_path: Path) -> list[str]:
        if not urls_path.exists():
            return []
        seen: set[str] = set()
        for line in urls_path.read_text(encoding="utf-8", errors="replace").splitlines():
            url = line.strip()
            if url and SENSITIVE_EXTENSION_RE.search(url):
                seen.add(url)
        return sorted(seen)

    @staticmethod
    def _line_count(path: Path) -> int:
        try:
            return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        except OSError:
            return 0
