"""
takeover.py — Detect possible subdomain takeovers using subzy (preferred)
or subjack as a fallback.

Both tools accept a hostname list and produce findings on stdout; we capture
stdout and persist it untouched so manual verification stays easy.
"""

from __future__ import annotations

from pathlib import Path

from utils.shared.commands import Commands
from .external_constants import TAKEOVER_TOOL_PRIORITY
from .tooling import available_name


class TakeoverChecker:
    """Run subdomain-takeover detection against resolved subdomains."""

    def __init__(self) -> None:
        self.command = Commands()

    def check(self, hosts_file: Path, output_dir: Path) -> dict:
        """Run the first available takeover tool against *hosts_file*.

        Args:
            hosts_file: Text file with one hostname per line.
            output_dir: Destination directory for the report.

        Returns:
            Dict with output path, tool used, and a "missing" key when no
            supported tool is installed.
        """
        if not hosts_file or not hosts_file.exists():
            return {"output": None, "tool": None, "count": 0}

        selected_name = None
        selected_path = None
        for candidate in TAKEOVER_TOOL_PRIORITY:
            resolved = available_name(candidate)
            if resolved:
                selected_name = candidate
                selected_path = resolved
                break

        if selected_name is None or selected_path is None:
            return {"output": None, "tool": None, "count": 0, "missing": "subzy/subjack", "skipped": True}

        report = output_dir / f"takeover_{selected_name}.txt"
        cmd = self._build_command(selected_name, selected_path, hosts_file, report)
        result = self.command.stream_command(cmd, prefix=f"[{selected_name}] ")

        # subzy prints results to stdout; persist the run output as-is.
        if result.stdout and not report.exists():
            report.write_text(result.stdout, encoding="utf-8")

        findings = self._count_findings(report) if report.exists() else 0
        return {
            "output": report if report.exists() else None,
            "tool": selected_name,
            "count": findings,
        }

    @staticmethod
    def _build_command(tool: str, executable: str, hosts_file: Path, report: Path) -> list[str]:
        if tool == "subzy":
            return [
                executable, "run",
                "--targets", str(hosts_file),
                "--hide_fails",
                "--output", str(report),
            ]
        # subjack
        return [
            executable,
            "-w", str(hosts_file),
            "-t", "50",
            "-timeout", "30",
            "-o", str(report),
            "-ssl",
        ]

    @staticmethod
    def _count_findings(report: Path) -> int:
        try:
            return sum(
                1
                for line in report.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and "VULNERABLE" in line.upper()
            )
        except OSError:
            return 0
