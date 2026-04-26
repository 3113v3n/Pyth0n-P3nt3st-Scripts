"""
takeover.py — Detect possible subdomain takeovers using subzy (preferred)
or subjack as a fallback.

Tool output is sanitized before persistence; subzy reports are normalized to
vulnerable hosts only.
"""

from __future__ import annotations

import json
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

        self._persist_report(report, selected_name, result.stdout)

        findings = self._count_findings(report) if report.exists() else 0
        return {
            "output": report if report.exists() else None,
            "tool": selected_name,
            "count": findings,
        }

    @classmethod
    def _persist_report(cls, report: Path, tool: str, stdout: str) -> None:
        """Persist takeover output with ANSI stripped and tool-specific filtering."""
        if report.exists():
            raw_text = report.read_text(encoding="utf-8", errors="replace")
        else:
            raw_text = stdout or ""

        cleaned = Commands.strip_ansi(raw_text)
        if tool == "subzy":
            normalized = cls._subzy_vulnerable_only(cleaned)
            if normalized:
                report.write_text(normalized.rstrip() + "\n", encoding="utf-8")
            else:
                report.unlink(missing_ok=True)
            return

        if cleaned.strip():
            report.write_text(cleaned.rstrip() + "\n", encoding="utf-8")
        else:
            report.unlink(missing_ok=True)

    @staticmethod
    def _subzy_vulnerable_only(content: str) -> str:
        """Normalize subzy output to vulnerable-only entries (JSON or text)."""
        text = content.strip()
        if not text:
            return ""

        # JSON payload (array/object)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, list):
            vulnerable = [entry for entry in parsed if isinstance(entry, dict) and entry.get("vulnerable") is True]
            return json.dumps(vulnerable, indent=2) if vulnerable else ""
        if isinstance(parsed, dict):
            return json.dumps(parsed, indent=2) if parsed.get("vulnerable") is True else ""

        # Fallback: line-oriented outputs (text or NDJSON)
        filtered_lines: list[str] = []
        seen: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue

            # NDJSON line
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, dict):
                if obj.get("vulnerable") is True:
                    rendered = json.dumps(obj, ensure_ascii=False)
                    if rendered not in seen:
                        seen.add(rendered)
                        filtered_lines.append(rendered)
                continue

            upper = line.upper()
            if "NOT VULNERABLE" in upper:
                continue
            if '"VULNERABLE"' in upper and "FALSE" in upper:
                continue
            if "VULNERABLE" not in upper:
                continue
            if line in seen:
                continue
            seen.add(line)
            filtered_lines.append(line)

        return "\n".join(filtered_lines)

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
