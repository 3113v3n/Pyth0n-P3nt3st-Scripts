"""
http_probe.py — HTTP probing for resolved subdomains using httpx-toolkit.

Reads a file of hostnames produced by domain_recon.py and writes a JSON-lines
file describing alive hosts (status code, title, technology, web server).
Falls back to a plain text list of alive URLs when httpx is unavailable.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from utils.shared.commands import Commands
from .external_constants import HTTP_PROBE_PORTS, HTTPX_THREADS


HTTPX_BIN = "httpx-toolkit"


class HttpProbe:
    """Probe resolved hosts and capture HTTP metadata."""

    def __init__(self) -> None:
        self.command = Commands()

    def probe(self, hosts_file: Path, output_dir: Path) -> dict:
        """Probe each host in *hosts_file* and write alive_hosts.json + alive_hosts.txt.

        Args:
            hosts_file: Path to file containing one hostname per line.
            output_dir: Directory where probe results are stored.

        Returns:
            Dictionary with keys:
                json_path: Path to the JSONL output (or None on failure).
                txt_path:  Path to the text URL list (or None on failure).
                count:     Number of alive hosts discovered.
        """
        json_path = output_dir / "alive_hosts.json"
        txt_path = output_dir / "alive_hosts.txt"

        if not hosts_file.exists() or hosts_file.stat().st_size == 0:
            return {"json_path": None, "txt_path": None, "count": 0}

        if shutil.which(HTTPX_BIN) is None:
            return {"json_path": None, "txt_path": None, "count": 0, "missing": HTTPX_BIN}

        cmd = [
            HTTPX_BIN,
            "-l", str(hosts_file),
            "-ports", HTTP_PROBE_PORTS,
            "-threads", str(HTTPX_THREADS),
            "-title",
            "-tech-detect",
            "-web-server",
            "-status-code",
            "-random-agent",
            "-json",
            "-silent",
            "-o", str(json_path),
        ]
        self.command.execute_command(cmd)

        urls = self._extract_urls(json_path)
        if urls:
            txt_path.write_text("\n".join(urls) + "\n", encoding="utf-8")

        return {
            "json_path": json_path if json_path.exists() else None,
            "txt_path": txt_path if txt_path.exists() else None,
            "count": len(urls),
        }

    @staticmethod
    def _extract_urls(json_path: Path) -> list[str]:
        """Extract URLs from an httpx JSONL file. Returns empty list on any error."""
        if not json_path.exists():
            return []
        urls: list[str] = []
        with json_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = record.get("url") or record.get("input")
                if url:
                    urls.append(url)
        return urls
