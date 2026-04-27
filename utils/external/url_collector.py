"""
url_collector.py — Collect historical URLs (gauplus / waybackurls) and pull
out URLs that point at sensitive file extensions for follow-up review.
"""

from __future__ import annotations

from pathlib import Path

from utils.shared.commands import Commands
from .external_constants import (
    GAUPLUS_THREADS,
    SAFE_GAUPLUS_THREADS,
    SENSITIVE_EXTENSION_RE,
)
from .tooling import available_name


# Tool order: gauplus first (more sources), waybackurls as fallback.
URL_TOOL_PRIORITY = (("gauplus", "gau"), ("waybackurls",))


class UrlCollector:
    """Aggregate historical URLs and surface sensitive file paths."""

    def __init__(self) -> None:
        self.command = Commands()

    def collect(self, hosts_file: Path, output_dir: Path, safe_mode: bool = False) -> dict:
        """Run the first available URL collector against *hosts_file*.

        Args:
            hosts_file: Resolved hostnames or alive URLs (one per line).
            output_dir: Destination directory for the URL artifacts.
            safe_mode:  Enable lower-impact collection profile.

        Returns:
            Dict with keys: urls (path), sensitive (path), counts, tool, missing.
        """
        if not hosts_file or not hosts_file.exists():
            return {"urls": None, "sensitive": None, "url_count": 0, "sensitive_count": 0}

        tool = None
        executable = None
        for aliases in URL_TOOL_PRIORITY:
            resolved = available_name(*aliases)
            if resolved:
                tool = Path(resolved).name
                if tool not in {"gauplus", "gau", "waybackurls"}:
                    tool = aliases[0]
                executable = resolved
                break

        if tool is None or executable is None:
            return {
                "urls": None,
                "sensitive": None,
                "url_count": 0,
                "sensitive_count": 0,
                "missing": "gauplus/waybackurls",
                "skipped": True,
            }

        urls_path = output_dir / "historical_urls.txt"
        sensitive_path = output_dir / "sensitive_urls.txt"

        cmd = self._build_command(tool, executable, hosts_file, safe_mode=safe_mode)
        self.command.stream_command(cmd, output_file=urls_path, prefix=f"[{tool}] ")

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
    def _build_command(
        tool: str,
        executable: str,
        hosts_file: Path,
        safe_mode: bool = False,
    ) -> list[str]:
        threads = SAFE_GAUPLUS_THREADS if safe_mode else GAUPLUS_THREADS
        if tool == "gauplus":
            cmd = [executable, "-t", str(threads), "-subs"]
            if not safe_mode:
                cmd.append("-random-agent")
            cmd.append(str(hosts_file))
            return cmd
        if tool == "gau":
            return [executable, "--threads", str(threads), "--subs", str(hosts_file)]
        return [executable, str(hosts_file)]

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
