"""
port_scanner.py — Service-detection scan of alive hosts using nmap.

Designed as a thin wrapper that produces both human (-oN) and grepable (-oG)
output for downstream tooling. The host list is sourced from the HTTP probe
phase to keep the surface area small and avoid rescanning dead targets.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from utils.shared.commands import Commands
from .tooling import available_name


NMAP_BIN = "nmap"


class PortScanner:
    """Run service/version detection against alive HTTP hosts."""

    def __init__(self) -> None:
        self.command = Commands()

    def scan(
        self,
        alive_urls_file: Path,
        output_dir: Path,
    ) -> dict:
        """Run nmap against unique hosts from *alive_urls_file*.

        Args:
            alive_urls_file: Text file containing one URL per line.
            output_dir:      Destination directory for scan output.

        Returns:
            Dict with normal/grepable output paths and host count, plus a
            "missing" key when nmap is not installed.
        """
        if not alive_urls_file or not alive_urls_file.exists():
            return {"normal": None, "grepable": None, "count": 0}

        nmap = available_name(NMAP_BIN)
        if nmap is None:
            return {"normal": None, "grepable": None, "count": 0, "missing": NMAP_BIN, "skipped": True}

        hosts = self._unique_hosts(alive_urls_file)
        if not hosts:
            return {"normal": None, "grepable": None, "count": 0}

        targets_file = output_dir / "nmap_targets.txt"
        targets_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        normal = output_dir / "nmap_results.txt"
        grepable = output_dir / "nmap_results.gnmap"

        cmd = [
            nmap,
            "-v",
            "-sV",
            "-Pn",
            "-p-",
            "--open",
            "--script", "vuln",
            "-iL", str(targets_file),
            "-oN", str(normal),
            "-oG", str(grepable),
        ]
        try:
            self.command.stream_command(cmd, prefix="[nmap] ")
        finally:
            # Runtime helper input file; reports are written to nmap_results.* outputs.
            targets_file.unlink(missing_ok=True)

        return {
            "normal": normal if normal.exists() else None,
            "grepable": grepable if grepable.exists() else None,
            "count": len(hosts),
        }

    @staticmethod
    def _unique_hosts(alive_urls_file: Path) -> list[str]:
        """Return de-duplicated hostnames extracted from a list of URLs."""
        host_pattern = re.compile(r"^[A-Za-z0-9.\-]+$")
        seen: set[str] = set()
        for line in alive_urls_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            host = urlparse(line).hostname or line
            if host and host_pattern.match(host):
                seen.add(host)
        return sorted(seen)
