"""
vuln_scanner.py — Run nuclei templates against alive URLs.

Templates are managed by nuclei itself (`nuclei -update-templates`); this
wrapper only runs the scan and counts findings by severity.
"""

from __future__ import annotations

import re
from pathlib import Path

from utils.shared.commands import Commands
from .external_constants import NUCLEI_CONCURRENCY, SAFE_NUCLEI_CONCURRENCY
from .tooling import available_name


NUCLEI_BIN = "nuclei"
SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")
SEVERITY_RE = re.compile(r"\[(info|low|medium|high|critical)\]", re.IGNORECASE)


class VulnerabilityScanner:
    """Wrap nuclei for vulnerability scanning of alive HTTP services."""

    def __init__(self) -> None:
        self.command = Commands()

    def scan(self, alive_urls_file: Path, output_dir: Path, safe_mode: bool = False) -> dict:
        """Run nuclei against the alive URLs.

        Args:
            alive_urls_file: File containing one URL per line.
            output_dir:      Destination directory for nuclei output.
            safe_mode:       Enable lower-impact scanner concurrency profile.

        Returns:
            Dict with output path, total findings, severity counts, and a
            "missing" key when nuclei is not installed.
        """
        if not alive_urls_file or not alive_urls_file.exists():
            return {"output": None, "total": 0, "severities": {}}

        nuclei = available_name(NUCLEI_BIN)
        if nuclei is None:
            return {"output": None, "total": 0, "severities": {}, "missing": NUCLEI_BIN, "skipped": True}

        concurrency = SAFE_NUCLEI_CONCURRENCY if safe_mode else NUCLEI_CONCURRENCY
        report = output_dir / "nuclei_results.txt"
        cmd = [
            nuclei,
            "-l", str(alive_urls_file),
            "-c", str(concurrency),
            "-severity", ",".join(SEVERITY_LEVELS),
            "-silent",
        ]
        self.command.stream_command(cmd, output_file=report, prefix="[nuclei] ")

        severities = self._severity_counts(report) if report.exists() else {}
        total = sum(severities.values())
        return {
            "output": report if report.exists() else None,
            "total": total,
            "severities": severities,
        }

    @staticmethod
    def _severity_counts(report: Path) -> dict[str, int]:
        counts: dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
        try:
            for line in report.read_text(encoding="utf-8", errors="replace").splitlines():
                match = SEVERITY_RE.search(line)
                if match:
                    counts[match.group(1).lower()] += 1
        except OSError:
            return {}
        return {level: count for level, count in counts.items() if count}
